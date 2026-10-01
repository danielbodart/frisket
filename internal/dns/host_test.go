package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// testHost answers shop.example.internal alone, as a stand-in for
// docker.Project and docker.Address, which this package cannot import.
func testHost(t *testing.T) (*Host, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return &Host{
		Lookup: func(name string) (netip.Addr, bool) {
			if name == "shop.example.internal" {
				return netip.MustParseAddr("127.101.170.171"), true
			}
			return netip.Addr{}, false
		},
		Log: slog.New(slog.NewJSONHandler(&buf, nil)),
	}, &buf
}

func hostAsk(t *testing.T, h *Host, req []byte) *dnsmessage.Message {
	t.Helper()
	resp := h.Answer(req, true, "127.0.0.1:5353")
	if resp == nil {
		return nil
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		t.Fatalf("our own reply does not parse: %v", err)
	}
	return &m
}

// A project's name answers A with its address and nothing else with
// records; the rest of .internal is NXDOMAIN, and everything outside it
// REFUSED, with nothing forwarded anywhere.
func TestTheHostAnswersAProjectsNameAndNothingElse(t *testing.T) {
	h, log := testHost(t)
	m := hostAsk(t, h, query(t, 1, "Shop.Example.Internal.", dnsmessage.TypeA, false))
	if m.Header.RCode != dnsmessage.RCodeSuccess || !m.Header.Authoritative || len(m.Answers) != 1 {
		t.Fatalf("A: %+v", m)
	}
	if a := m.Answers[0].Body.(*dnsmessage.AResource).A; netip.AddrFrom4(a) != netip.MustParseAddr("127.101.170.171") {
		t.Errorf("A is %v", a)
	}
	if m.Answers[0].Header.TTL != uint32(HostTTL/time.Second) || m.Header.ID != 1 {
		t.Errorf("TTL %d, id %d", m.Answers[0].Header.TTL, m.Header.ID)
	}
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.TypeHTTPS, dnsmessage.TypeTXT} {
		if m := hostAsk(t, h, query(t, 2, "shop.example.internal.", typ, true)); m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
			t.Errorf("%v: %+v", typ, m)
		}
	}
	for name, rcode := range map[string]dnsmessage.RCode{
		"other.example.internal.":    dnsmessage.RCodeNameError,
		"internal.":                  dnsmessage.RCodeNameError,
		"metadata.google.internal.":  dnsmessage.RCodeNameError,
		"example.com.":               dnsmessage.RCodeRefused,
		"shop.example.internal.com.": dnsmessage.RCodeRefused,
	} {
		if m := hostAsk(t, h, query(t, 3, name, dnsmessage.TypeA, false)); m.Header.RCode != rcode || len(m.Answers) != 0 {
			t.Errorf("%s: %v %v, want %v", name, m.Header.RCode, m.Answers, rcode)
		}
	}
	lines := strings.Split(strings.TrimSpace(log.String()), "\n")
	if len(lines) != 9 {
		t.Fatalf("%d lines for 9 queries:\n%s", len(lines), log)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first["name"] != "shop.example.internal" || first["decision"] != DecisionLocal || first["rcode"] != "Success" {
		t.Errorf("line: %v", first)
	}
}

// A response is never answered, and garbage gets no reply, so the host's
// server cannot be made to talk to itself or to anyone it did not hear from.
func TestTheHostAnswersNoResponseAndNoGarbage(t *testing.T) {
	h, _ := testHost(t)
	resp := query(t, 4, "shop.example.internal.", dnsmessage.TypeA, false)
	resp[2] |= 0x80
	if m := hostAsk(t, h, resp); m != nil {
		t.Errorf("a response was answered: %+v", m)
	}
	if m := hostAsk(t, h, []byte{1, 2, 3}); m != nil {
		t.Errorf("garbage was answered: %+v", m)
	}
}

// Over real sockets, UDP and TCP both, as systemd passes them.
func TestTheHostServesUDPAndTCP(t *testing.T) {
	h, _ := testHost(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	go func() { done <- h.ServeUDP(ctx, pc) }()
	go func() { done <- h.ServeTCP(ctx, ln) }()

	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(query(t, 5, "shop.example.internal.", dnsmessage.TypeA, false)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil || len(m.Answers) != 1 {
		t.Fatalf("UDP: %v %+v", err, m)
	}

	tc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	for id := uint16(6); id < 8; id++ {
		if err := writeFrame(tc, query(t, id, "shop.example.internal.", dnsmessage.TypeA, false)); err != nil {
			t.Fatal(err)
		}
		b, err := readFrame(tc)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Unpack(b); err != nil || len(m.Answers) != 1 || m.Header.ID != id {
			t.Fatalf("TCP %d: %v %+v", id, err, m)
		}
	}

	cancel()
	for range 2 {
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	}
}
