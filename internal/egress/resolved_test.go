package egress

import (
	"net/netip"
	"syscall"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time                          { return c.t }
func (c *clock) advance(d time.Duration)                 { c.t = c.t.Add(d) }
func newClock() *clock                                   { return &clock{time.Unix(1_000_000, 0)} }
func addr(s string) netip.Addr                           { return netip.MustParseAddr(s) }
func lookup(r *Resolved, s string) bool                  { _, ok := r.Lookup(addr(s)); return ok }
func record(r *Resolved, n, s string, ttl time.Duration) { r.Record(n, addr(s), ttl, 1) }

// A ZERO TTL STILL ALLOWS THE CONNECTION THAT FOLLOWS IT, and a week-long one
// does not keep the address open for a week.
func TestResolvedClampsTheTTL(t *testing.T) {
	c := newClock()
	r := NewResolved(ResolvedConfig{MinTTL: time.Minute, MaxTTL: time.Hour, Now: c.now})
	record(r, "zero.example", "1.1.1.1", 0)
	record(r, "week.example", "2.2.2.2", 7*24*time.Hour)

	c.advance(59 * time.Second)
	if !lookup(r, "1.1.1.1") {
		t.Error("a zero-TTL answer expired before the floor")
	}
	c.advance(2 * time.Second)
	if lookup(r, "1.1.1.1") {
		t.Error("a zero-TTL answer outlived the floor")
	}
	c.advance(time.Hour)
	if lookup(r, "2.2.2.2") {
		t.Error("a week-long TTL outlived the ceiling")
	}
}

func TestResolvedIsCapped(t *testing.T) {
	r := NewResolved(ResolvedConfig{Cap: 3})
	for _, a := range []string{"1.0.0.1", "1.0.0.2", "1.0.0.3"} {
		record(r, "x.example", a, time.Minute)
	}
	// Re-recording the oldest makes it the newest, so the next eviction takes
	// 1.0.0.2 instead.
	record(r, "x.example", "1.0.0.1", time.Minute)
	record(r, "x.example", "1.0.0.4", time.Minute)
	if r.Len() != 3 {
		t.Fatalf("Len = %d, want the cap of 3", r.Len())
	}
	if lookup(r, "1.0.0.2") {
		t.Error("the least recently recorded address survived eviction")
	}
	for _, a := range []string{"1.0.0.1", "1.0.0.3", "1.0.0.4"} {
		if !lookup(r, a) {
			t.Errorf("%s was evicted", a)
		}
	}
}

// ONE ADDRESS, ONE KEY. The answer says 1.2.3.4; the kernel may say
// ::ffff:1.2.3.4. If those were two keys the allowlist would refuse its own
// answers.
func TestResolvedCanonicalisesSpellings(t *testing.T) {
	r := NewResolved(ResolvedConfig{})
	record(r, "a.example", "1.2.3.4", time.Minute)
	if !lookup(r, "::ffff:1.2.3.4") {
		t.Error("the v4-mapped spelling of a resolved address was not found")
	}
	record(r, "b.example", "fe80::1%eth0", time.Minute)
	if !lookup(r, "fe80::1") {
		t.Error("the zone was part of the key")
	}
}

// The newest answer names the address; an earlier, longer promise stands.
func TestResolvedKeepsTheLongerPromise(t *testing.T) {
	c := newClock()
	r := NewResolved(ResolvedConfig{MinTTL: time.Second, MaxTTL: time.Hour, Now: c.now})
	r.Record("first.example", addr("1.1.1.1"), 30*time.Minute, 1)
	r.Record("second.example", addr("1.1.1.1"), time.Minute, 2)
	e, ok := r.Lookup(addr("1.1.1.1"))
	if !ok || e.Name != "second.example" || e.Query != 2 {
		t.Fatalf("Lookup = %+v, %v; want the newest name and query", e, ok)
	}
	c.advance(10 * time.Minute)
	if !lookup(r, "1.1.1.1") {
		t.Error("a shorter re-answer cut short the earlier TTL the client may still hold")
	}
}

// The netlink parse, on messages built the way the kernel lays them out:
// local and anycast routes in the local table count, a unicast route does not,
// and a local route in a policy table (TPROXY's `local 0.0.0.0/0 table 100`)
// does not make the whole internet host-owned.
func TestParseLocalRoutes(t *testing.T) {
	msg := func(family, dstLen, table, typ byte, attrs ...[]byte) syscall.NetlinkMessage {
		data := make([]byte, syscall.SizeofRtMsg)
		data[0], data[1], data[4], data[7] = family, dstLen, table, typ
		for _, a := range attrs {
			data = append(data, a...)
		}
		return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.RTM_NEWROUTE}, Data: data}
	}
	rta := func(typ uint16, v []byte) []byte {
		l := 4 + len(v)
		b := []byte{byte(l), byte(l >> 8), byte(typ), byte(typ >> 8)}
		b = append(b, v...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	dst := func(s string) []byte { return rta(syscall.RTA_DST, addr(s).AsSlice()) }
	msgs := []syscall.NetlinkMessage{
		msg(syscall.AF_INET, 24, syscall.RT_TABLE_LOCAL, syscall.RTN_LOCAL, dst("203.0.113.0")),      // AnyIP
		msg(syscall.AF_INET6, 128, syscall.RT_TABLE_LOCAL, syscall.RTN_ANYCAST, dst("2001:db8:1::")), // subnet-router anycast
		msg(syscall.AF_INET, 0, 100, syscall.RTN_LOCAL),                                              // TPROXY's local default
		msg(syscall.AF_INET, 32, syscall.RT_TABLE_LOCAL, syscall.RTN_UNICAST, dst("198.51.100.1")),
		// A table id too big for the header byte, carried in RTA_TABLE.
		msg(syscall.AF_INET, 32, 252, syscall.RTN_LOCAL, dst("198.51.100.2"), rta(syscall.RTA_TABLE, []byte{0x00, 0x01, 0, 0})),
	}
	got, err := parseLocalRoutes(msgs)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8:1::/128")}
	if len(got) != len(want) {
		t.Fatalf("parseLocalRoutes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("route %d = %v, want %v", i, got[i], want[i])
		}
	}
}
