package dns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// seen is one query as the fake upstream received it.
type seen struct {
	msg  dnsmessage.Message
	from netip.AddrPort
}

// udpUpstream is a fake resolver on loopback. respond decides what, and how
// many, datagrams go back for each query.
type udpUpstream struct {
	pc   *net.UDPConn
	addr netip.AddrPort
	mu   sync.Mutex
	seen []seen
}

func startUDPUpstream(t *testing.T, respond func(q dnsmessage.Message, reply func([]byte))) *udpUpstream {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	u := &udpUpstream{pc: pc, addr: netip.MustParseAddrPort(pc.LocalAddr().String())}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if err := q.Unpack(buf[:n]); err != nil {
				continue
			}
			u.mu.Lock()
			u.seen = append(u.seen, seen{q, from})
			u.mu.Unlock()
			respond(q, func(b []byte) { _, _ = pc.WriteToUDPAddrPort(b, from) })
		}
	}()
	return u
}

func (u *udpUpstream) queries() []seen {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]seen(nil), u.seen...)
}

// answer builds a response to q, as a well-behaved resolver would -- echoing
// the question exactly as sent -- then lets mutate spoil it.
func answer(q dnsmessage.Message, a string, mutate func(*dnsmessage.Message)) []byte {
	m := dnsmessage.Message{
		Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true, RecursionDesired: true},
		// A copy: a mutation that spoils this answer must not spoil the next.
		Questions: append([]dnsmessage.Question(nil), q.Questions...),
		Answers:   []dnsmessage.Resource{rrA(q.Questions[0].Name, a, 60)},
	}
	if mutate != nil {
		mutate(&m)
	}
	b, err := m.Pack()
	if err != nil {
		panic(err)
	}
	return b
}

func question(name string, typ dnsmessage.Type) dnsmessage.Question {
	return dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}
}

func onlyA(t *testing.T, m *dnsmessage.Message) string {
	t.Helper()
	if len(m.Answers) != 1 {
		t.Fatalf("answers = %+v", m.Answers)
	}
	return netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A).String()
}

// 0x20, A FRESH ID AND A FRESH SOCKET, every time. What the upstream saw is
// the evidence: the name in a random case that is still the name, ids that
// vary, and source ports that vary. The answer comes back in the client's own
// spelling, owner names included.
func TestUpstreamAsksWithRandomCaseAFreshIDAndAFreshSocket(t *testing.T) {
	up := startUDPUpstream(t, func(q dnsmessage.Message, reply func([]byte)) { reply(answer(q, "93.184.216.34", nil)) })
	u := &Upstream{Servers: []netip.AddrPort{up.addr}}
	const name = "abcdefghijklmnopqrstuvwxyz.example."
	q := question(name, dnsmessage.TypeA)
	for range 8 {
		m, tr, err := u.Exchange(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		if tr.Mismatched != 0 || tr.Transport != "udp" || tr.Server != up.addr {
			t.Errorf("trace = %+v", tr)
		}
		if got := m.Questions[0].Name.String(); got != name {
			t.Errorf("question came back as %q", got)
		}
		if got := m.Answers[0].Header.Name.String(); got != name {
			t.Errorf("answer owner came back as %q, not the client's spelling", got)
		}
	}
	ids, ports, spellings := map[uint16]bool{}, map[uint16]bool{}, map[string]bool{}
	for _, s := range up.queries() {
		sent := s.msg.Questions[0].Name.String()
		if !strings.EqualFold(sent, name) {
			t.Fatalf("0x20 changed the name itself: %q", sent)
		}
		// 32 letters: the chance of an all-lowercase draw is 2^-32.
		if sent == name {
			t.Errorf("a query went out with no case randomisation: %q", sent)
		}
		if s.msg.RecursionDesired != true {
			t.Error("a query went out without RD")
		}
		ids[s.msg.ID], ports[s.from.Port()], spellings[sent] = true, true, true
	}
	if len(ids) < 2 || len(ports) < 2 || len(spellings) < 2 {
		t.Fatalf("8 queries used %d ids, %d source ports and %d spellings", len(ids), len(ports), len(spellings))
	}
}

// A RESPONSE WHOSE QUESTION DOES NOT MATCH BYTE FOR BYTE IS DROPPED -- and so
// is one with the wrong id, one that is not a response, and one with a second
// question -- and the real answer that follows is still taken. Each forgery
// carries a different address so the test can tell which one won.
func TestUpstreamDropsEveryResponseThatIsNotTheAnswer(t *testing.T) {
	up := startUDPUpstream(t, func(q dnsmessage.Message, reply func([]byte)) {
		reply(answer(q, "6.6.6.1", func(m *dnsmessage.Message) {
			// Case-insensitively the same name: exactly what 0x20 exists to catch.
			n := dnsmessage.MustNewName(strings.ToLower(q.Questions[0].Name.String()))
			m.Questions = []dnsmessage.Question{{Name: n, Type: q.Questions[0].Type, Class: q.Questions[0].Class}}
		}))
		reply(answer(q, "6.6.6.2", func(m *dnsmessage.Message) { m.ID++ }))
		reply(answer(q, "6.6.6.3", func(m *dnsmessage.Message) { m.Response = false }))
		reply(answer(q, "6.6.6.4", func(m *dnsmessage.Message) { m.Questions = append(m.Questions, m.Questions[0]) }))
		reply(answer(q, "6.6.6.5", func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeAAAA }))
		reply(answer(q, "93.184.216.34", nil))
	})
	u := &Upstream{Servers: []netip.AddrPort{up.addr}}
	m, tr, err := u.Exchange(context.Background(), question("www.example.com.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if got := onlyA(t, m); got != "93.184.216.34" {
		t.Fatalf("took the forgery answering %s", got)
	}
	if tr.Mismatched != 5 {
		t.Fatalf("Mismatched = %d, want 5", tr.Mismatched)
	}
}

func TestUpstreamWithOnlyForgeriesFails(t *testing.T) {
	up := startUDPUpstream(t, func(q dnsmessage.Message, reply func([]byte)) {
		reply(answer(q, "6.6.6.6", func(m *dnsmessage.Message) { m.ID++ }))
	})
	u := &Upstream{Servers: []netip.AddrPort{up.addr}, Timeout: 200 * time.Millisecond}
	if m, _, err := u.Exchange(context.Background(), question("www.example.com.", dnsmessage.TypeA)); err == nil {
		t.Fatalf("accepted %+v", m)
	}
}

// A CONNECTED SOCKET. A datagram with the right id and the right question, but
// from anywhere but the server, never reaches us: the kernel drops it. The
// forgery is sent first and would win the race if the socket were not
// connected.
func TestUpstreamIgnoresAnAnswerFromAnotherAddress(t *testing.T) {
	forger, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Skipf("cannot bind 127.0.0.2: %v", err)
	}
	defer forger.Close()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	// Forge from 127.0.0.2 at once; answer genuinely from the server later.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			_, _ = forger.WriteToUDPAddrPort(answer(q, "6.6.6.6", nil), from)
			time.Sleep(100 * time.Millisecond)
			_, _ = pc.WriteToUDPAddrPort(answer(q, "93.184.216.34", nil), from)
		}
	}()
	u := &Upstream{Servers: []netip.AddrPort{netip.MustParseAddrPort(pc.LocalAddr().String())}}
	m, tr, err := u.Exchange(context.Background(), question("www.example.com.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if got := onlyA(t, m); got != "93.184.216.34" {
		t.Fatalf("took the forgery from 127.0.0.2, answering %s", got)
	}
	if tr.Mismatched != 0 {
		t.Fatalf("the forgery reached userspace (%d mismatched); the socket is not connected", tr.Mismatched)
	}
}

// A truncated UDP answer is asked again over TCP, with its own id and case.
func TestUpstreamRetriesATruncatedAnswerOverTCP(t *testing.T) {
	up := startUDPUpstream(t, func(q dnsmessage.Message, reply func([]byte)) {
		reply(answer(q, "6.6.6.6", func(m *dnsmessage.Message) { m.Truncated, m.Answers = true, nil }))
	})
	ln, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(up.addr))
	if err != nil {
		t.Skipf("the UDP port is taken for TCP: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, err := readFrame(c)
		if err != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(b) != nil {
			return
		}
		_ = writeFrame(c, answer(q, "93.184.216.34", nil))
	}()
	u := &Upstream{Servers: []netip.AddrPort{up.addr}}
	m, tr, err := u.Exchange(context.Background(), question("big.example.com.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if got := onlyA(t, m); got != "93.184.216.34" || !tr.Truncated || tr.Transport != "tcp" {
		t.Fatalf("answer %s, trace %+v", got, tr)
	}
}

func TestUpstreamFallsBackToTheNextServer(t *testing.T) {
	dead, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip(err)
	}
	deadAddr := netip.MustParseAddrPort(dead.LocalAddr().String())
	_ = dead.Close()
	up := startUDPUpstream(t, func(q dnsmessage.Message, reply func([]byte)) { reply(answer(q, "93.184.216.34", nil)) })
	u := &Upstream{Servers: []netip.AddrPort{deadAddr, up.addr}, Timeout: time.Second}
	m, tr, err := u.Exchange(context.Background(), question("www.example.com.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if onlyA(t, m) != "93.184.216.34" || tr.Server != up.addr {
		t.Fatalf("trace %+v", tr)
	}
}

// Upstream answers are not the sandbox's bytes, but an allowed name's
// authoritative server shapes them, so they are fuzzed too: never a panic, and
// anything accepted really does answer the question that was sent.
func FuzzAcceptResponse(f *testing.F) {
	sent := question("wWw.ExAmPlE.cOm.", dnsmessage.TypeA)
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x1234}, Questions: []dnsmessage.Question{sent}}
	f.Add(answer(q, "93.184.216.34", nil))
	f.Add(answer(q, "93.184.216.34", func(m *dnsmessage.Message) {
		m.Answers = append(m.Answers, rrCNAME(sent.Name, "a.example.net."))
	}))
	f.Add([]byte{0x12, 0x34, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, ok, err := acceptResponse(b, 0x1234, sent)
		if !ok || err != nil {
			return
		}
		if m.ID != 0x1234 || !m.Response || len(m.Questions) != 1 || !sameQuestion(m.Questions[0], sent) {
			t.Fatalf("accepted %+v for %+v", m.Header, sent)
		}
		restoreCase(m, sent.Name, dnsmessage.MustNewName("www.example.com."))
		_ = chainAddrs(m.Questions[0].Name, m.Answers)
	})
}
