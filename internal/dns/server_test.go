package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/danielbodart/frisket/internal/steer"
)

// journal is the injected log writer; see the egress package's for why.
type journal struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (j *journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.Write(p)
}

func (j *journal) reset() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.buf.Reset()
}

func (j *journal) lines(t testing.TB) []map[string]any {
	t.Helper()
	j.mu.Lock()
	raw := j.buf.String()
	j.mu.Unlock()
	var out []map[string]any
	for _, l := range bytes.Split([]byte(raw), []byte("\n")) {
		if len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(l, &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", l, err)
		}
		if m["msg"] == "dns" {
			out = append(out, m)
		}
	}
	return out
}

// fakeUpstream answers from a table and counts every question it is asked.
// "A refused name triggers no upstream lookup" is asserted on this counter.
type fakeUpstream struct {
	mu      sync.Mutex
	asked   []dnsmessage.Question
	answers map[string]func(q dnsmessage.Question) []dnsmessage.Resource
	fail    error
	block   chan struct{}
}

func (f *fakeUpstream) Exchange(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, Trace, error) {
	f.mu.Lock()
	f.asked = append(f.asked, q)
	ans := f.answers[Normalize(q.Name.String())]
	fail, block := f.fail, f.block
	f.mu.Unlock()
	tr := Trace{Server: netip.MustParseAddrPort("192.0.2.53:53"), Transport: "udp"}
	if block != nil {
		<-block
	}
	if fail != nil {
		return nil, tr, fail
	}
	m := &dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{q},
	}
	if ans == nil {
		m.RCode = dnsmessage.RCodeNameError
	} else {
		m.Answers = ans(q)
	}
	return m, tr, nil
}

func (f *fakeUpstream) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

type recorded struct {
	name  string
	addr  netip.Addr
	ttl   time.Duration
	query uint64
}

type fakeRecorder struct {
	mu   sync.Mutex
	recs []recorded
}

func (r *fakeRecorder) Record(name string, a netip.Addr, ttl time.Duration, q uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, recorded{name, a, ttl, q})
}

func (r *fakeRecorder) all() []recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recorded(nil), r.recs...)
}

func rrA(name dnsmessage.Name, a string, ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
		Body:   &dnsmessage.AResource{A: netip.MustParseAddr(a).As4()},
	}
}

func rrCNAME(name dnsmessage.Name, target string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 300},
		Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)},
	}
}

type fixture struct {
	s   *Server
	j   *journal
	up  *fakeUpstream
	rec *fakeRecorder
}

var service = []netip.Addr{netip.MustParseAddr("100.100.0.1"), netip.MustParseAddr("fd00:f::1")}

func newFixture(t testing.TB, tweak func(*Config)) *fixture {
	t.Helper()
	f := &fixture{j: &journal{}, rec: &fakeRecorder{}, up: &fakeUpstream{answers: map[string]func(dnsmessage.Question) []dnsmessage.Resource{
		"pkg.example": func(q dnsmessage.Question) []dnsmessage.Resource {
			return []dnsmessage.Resource{rrA(q.Name, "93.184.216.34", 120)}
		},
	}}}
	cfg := Config{
		Session:   "sess-d",
		Policy:    "strict",
		Allow:     MustMatcher("pkg.example", "*.cdn.example", "api.github.com", "denied-intercept.example"),
		Intercept: MustMatcher("api.github.com", "not-allowed-but-intercepted.example"),
		Service:   service,
		Upstream:  f.up,
		Resolved:  f.rec,
		Log:       slog.New(slog.NewJSONHandler(f.j, nil)),
	}
	if tweak != nil {
		tweak(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.s = s
	return f
}

var (
	testPeer = netip.MustParseAddrPort("10.0.0.2:40000")
	testDst  = netip.MustParseAddrPort("10.0.0.1:53")
)

// ask runs one query through the same path a datagram takes after admission,
// and returns the reply (nil for none) and the query's line.
func (f *fixture) ask(t testing.TB, req []byte) (*dnsmessage.Message, map[string]any) {
	t.Helper()
	before := len(f.j.lines(t))
	l := f.s.newLine("udp", testPeer, testDst)
	resp := f.s.handle(context.Background(), req, &l, true)
	f.s.log(&l)
	lines := f.j.lines(t)
	if len(lines) != before+1 {
		t.Fatalf("one query produced %d lines", len(lines)-before)
	}
	if resp == nil {
		return nil, lines[len(lines)-1]
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		t.Fatalf("our own reply does not parse: %v", err)
	}
	return &m, lines[len(lines)-1]
}

func query(t testing.TB, id uint16, name string, typ dnsmessage.Type, edns bool) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if edns {
		if err := b.StartAdditionals(); err != nil {
			t.Fatal(err)
		}
		var h dnsmessage.ResourceHeader
		if err := h.SetEDNS0(4096, dnsmessage.RCodeSuccess, false); err != nil {
			t.Fatal(err)
		}
		if err := b.OPTResource(h, dnsmessage.OPTResource{}); err != nil {
			t.Fatal(err)
		}
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func expect(t testing.TB, line map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if line[k] != v {
			t.Errorf("line[%q] = %v, want %v; line: %v", k, line[k], v, line)
		}
	}
}

// A NAME NOT ALLOWED IS REFUSED WITHOUT AN UPSTREAM LOOKUP -- so it cannot
// leak through DNS -- and says so in the log.
func TestANameNotAllowedIsRefusedWithoutAskingUpstream(t *testing.T) {
	f := newFixture(t, nil)
	for _, name := range []string{"exfil-c2VjcmV0.attacker.example.", "evil-cdn.example.", "cdn.example."} {
		m, line := f.ask(t, query(t, 0x1234, name, dnsmessage.TypeA, false))
		if m == nil || m.RCode != dnsmessage.RCodeRefused || m.ID != 0x1234 || !m.Response {
			t.Fatalf("%s: reply %+v, want REFUSED to id 0x1234", name, m)
		}
		if len(m.Questions) != 1 || m.Questions[0].Name.String() != name {
			t.Errorf("%s: the reply does not echo the question: %+v", name, m.Questions)
		}
		expect(t, line, map[string]any{"decision": DecisionRefused, "reason": "not allowed", "rcode": "Refused", "name": Normalize(name)})
	}
	if n := f.up.count(); n != 0 {
		t.Fatalf("refused names caused %d upstream lookups", n)
	}
}

func TestAnAllowedNameIsResolvedAndRecorded(t *testing.T) {
	f := newFixture(t, nil)
	m, line := f.ask(t, query(t, 7, "PKG.Example.", dnsmessage.TypeA, false))
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatalf("reply = %+v", m)
	}
	// The client's own spelling, case and all, comes back.
	if m.Questions[0].Name.String() != "PKG.Example." {
		t.Errorf("question came back as %q", m.Questions[0].Name.String())
	}
	recs := f.rec.all()
	if len(recs) != 1 || recs[0].name != "pkg.example" || recs[0].addr != netip.MustParseAddr("93.184.216.34") || recs[0].ttl != 120*time.Second {
		t.Fatalf("recorded %+v", recs)
	}
	if recs[0].query != uint64(line["query"].(float64)) {
		t.Errorf("recorded under query %d, logged as %v: the connection could not be joined to its query", recs[0].query, line["query"])
	}
	expect(t, line, map[string]any{
		"session": "sess-d", "policy": "strict", "transport": "udp",
		"name": "pkg.example", "type": "A", "decision": DecisionResolved, "rcode": "Success",
		"upstream": "192.0.2.53:53", "peer": testPeer.String(), "dst": testDst.String(),
	})
	if a, _ := line["answers"].([]any); len(a) != 1 || a[0] != "93.184.216.34" {
		t.Errorf("answers = %v", line["answers"])
	}
}

// An intercepted name resolves to the session's service address, in the right
// family, without an upstream lookup and without entering the resolved set --
// connections to the service address are frisket's own, not egress.
func TestAnInterceptedNameResolvesToTheServiceAddress(t *testing.T) {
	f := newFixture(t, nil)
	m, line := f.ask(t, query(t, 1, "api.github.com.", dnsmessage.TypeA, false))
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != service[0].As4() {
		t.Fatalf("A reply = %+v", m.Answers)
	}
	expect(t, line, map[string]any{"decision": DecisionIntercepted})
	m, _ = f.ask(t, query(t, 2, "api.github.com.", dnsmessage.TypeAAAA, false))
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AAAAResource).AAAA != service[1].As16() {
		t.Fatalf("AAAA reply = %+v", m.Answers)
	}
	m, _ = f.ask(t, query(t, 3, "api.github.com.", dnsmessage.TypeHTTPS, false))
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("HTTPS reply = %+v, want NOERROR with nothing", m)
	}
	if f.up.count() != 0 || len(f.rec.all()) != 0 {
		t.Fatalf("interception asked upstream %d times and recorded %v", f.up.count(), f.rec.all())
	}
}

// Intercepting is how an allowed host gets its credential. It is not a way
// round the allowlist.
func TestAnInterceptedNameMustAlsoBeAllowed(t *testing.T) {
	f := newFixture(t, nil)
	m, line := f.ask(t, query(t, 1, "not-allowed-but-intercepted.example.", dnsmessage.TypeA, false))
	if m.RCode != dnsmessage.RCodeRefused || len(m.Answers) != 0 {
		t.Fatalf("reply = %+v", m)
	}
	expect(t, line, map[string]any{"decision": DecisionRefused})
}

// OTTERGATE'S AUDIT-LOG BUG. One 14-byte wire label "api.github.com" -- not
// three labels -- is what ottergate's hand-rolled parser turned into the name
// api.github.com, which matched an exact allowlist entry and was logged as that
// host. dnsmessage refuses it; the reply is FORMERR, nothing is looked up, and
// the log does not claim the name.
func TestALabelContainingADotIsNeverTheName(t *testing.T) {
	f := newFixture(t, nil)
	label := "api.github.com"
	req := []byte{0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, byte(len(label))}
	req = append(req, label...)
	req = append(req, 0, 0, 1, 0, 1)
	m, line := f.ask(t, req)
	if m == nil || m.RCode != dnsmessage.RCodeFormatError || m.ID != 0xbeef {
		t.Fatalf("reply = %+v, want FORMERR", m)
	}
	if name, ok := line["name"]; ok {
		t.Fatalf("the log names the query %q", name)
	}
	expect(t, line, map[string]any{"decision": DecisionRefused, "reason": "malformed question"})
	if f.up.count() != 0 {
		t.Fatal("a malformed name was looked up")
	}
}

// A name made of bytes a name cannot contain is refused, and logged escaped so
// the line cannot be made to say something else.
func TestAnInvalidNameIsRefusedAndLoggedEscaped(t *testing.T) {
	f := newFixture(t, nil)
	label := "pkg\"x\\"
	req := []byte{0, 9, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, byte(len(label))}
	req = append(req, label...)
	req = append(req, 7)
	req = append(req, "example"...)
	req = append(req, 0, 0, 1, 0, 1)
	m, line := f.ask(t, req)
	if m == nil || m.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("reply = %+v", m)
	}
	expect(t, line, map[string]any{"decision": DecisionRefused, "reason": "invalid name", "name": `pkg\x22x\x5c.example.`})
}

func TestMalformedAndOddQueriesAreAnsweredOrDroppedAndAlwaysLogged(t *testing.T) {
	f := newFixture(t, nil)
	two := func() []byte {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 5})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("pkg.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("pkg.example."), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET})
		out, _ := b.Finish()
		return out
	}()
	response := query(t, 6, "pkg.example.", dnsmessage.TypeA, false)
	response[2] |= 0x80 // QR: this is a response, not a query
	notify := query(t, 8, "pkg.example.", dnsmessage.TypeA, false)
	notify[2] |= 4 << 3 // opcode NOTIFY
	chaos := query(t, 9, "version.bind.", dnsmessage.TypeTXT, false)
	chaos[len(chaos)-1] = 3 // class CH
	for _, tc := range []struct {
		name     string
		req      []byte
		reply    bool
		rcode    dnsmessage.RCode
		decision string
		reason   string
	}{
		{"empty", nil, false, 0, DecisionDropped, "malformed header"},
		{"short", []byte{1, 2, 3}, false, 0, DecisionDropped, "malformed header"},
		{"a response", response, false, 0, DecisionDropped, "not a query"},
		{"two questions", two, true, dnsmessage.RCodeFormatError, DecisionRefused, "more than one question"},
		{"notify", notify, true, dnsmessage.RCodeNotImplemented, DecisionRefused, "opcode 4"},
		{"chaos", chaos, true, dnsmessage.RCodeRefused, DecisionRefused, "class CHAOS"},
		{"zone transfer", query(t, 10, "pkg.example.", dnsmessage.TypeAXFR, false), true, dnsmessage.RCodeNotImplemented, DecisionRefused, "zone transfer"},
	} {
		m, line := f.ask(t, tc.req)
		if (m != nil) != tc.reply {
			t.Errorf("%s: reply = %+v, want a reply %v", tc.name, m, tc.reply)
		}
		if m != nil && m.RCode != tc.rcode {
			t.Errorf("%s: rcode %v, want %v", tc.name, m.RCode, tc.rcode)
		}
		if line["decision"] != tc.decision || line["reason"] != tc.reason {
			t.Errorf("%s: line = %v, want %s/%s", tc.name, line, tc.decision, tc.reason)
		}
	}
	if f.up.count() != 0 {
		t.Fatalf("%d upstream lookups for queries that should never get that far", f.up.count())
	}
}

func TestAnUpstreamFailureIsServfail(t *testing.T) {
	f := newFixture(t, nil)
	f.up.fail = errors.New("i/o timeout")
	m, line := f.ask(t, query(t, 1, "pkg.example.", dnsmessage.TypeA, false))
	if m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("reply = %+v", m)
	}
	expect(t, line, map[string]any{"decision": DecisionFailed, "rcode": "ServerFailure", "error": "i/o timeout"})
}

// Only the chain from the question counts. An A record for some other name,
// slipped into the answer, is not an answer to this question and must not
// become an address the session may reach.
func TestOnlyTheCNAMEChainIsRecorded(t *testing.T) {
	f := newFixture(t, nil)
	f.up.answers["www.cdn.example"] = func(q dnsmessage.Question) []dnsmessage.Resource {
		return []dnsmessage.Resource{
			rrCNAME(q.Name, "edge.cdnprovider.net."),
			rrCNAME(dnsmessage.MustNewName("edge.cdnprovider.net."), "e1.cdnprovider.net."),
			rrA(dnsmessage.MustNewName("E1.CDNPROVIDER.NET."), "151.101.1.1", 30),
			rrA(dnsmessage.MustNewName("bank.example."), "203.0.113.66", 30),
		}
	}
	_, line := f.ask(t, query(t, 1, "www.cdn.example.", dnsmessage.TypeA, false))
	recs := f.rec.all()
	if len(recs) != 1 || recs[0].addr != netip.MustParseAddr("151.101.1.1") || recs[0].name != "www.cdn.example" {
		t.Fatalf("recorded %+v, want only the chain's address under the asked name", recs)
	}
	if a, _ := line["answers"].([]any); len(a) != 1 {
		t.Errorf("answers = %v", line["answers"])
	}
}

// A browser may connect to an HTTPS record's ipv4hint before its A query
// returns. The hints are part of the same answer for the same allowed name.
func TestHTTPSHintsAreRecorded(t *testing.T) {
	f := newFixture(t, nil)
	f.up.answers["pkg.example"] = func(q dnsmessage.Question) []dnsmessage.Resource {
		r := dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{Priority: 1, Target: dnsmessage.MustNewName(".")}}
		r.SetParam(dnsmessage.SVCParamIPv4Hint, []byte{93, 184, 216, 34, 93, 184, 216, 35})
		r.SetParam(dnsmessage.SVCParamIPv6Hint, netip.MustParseAddr("2606:2800:220:1::1").AsSlice())
		return []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET, TTL: 60}, Body: &r}}
	}
	f.ask(t, query(t, 1, "pkg.example.", dnsmessage.TypeHTTPS, false))
	var got []string
	for _, r := range f.rec.all() {
		got = append(got, r.addr.String())
	}
	if len(got) != 3 || got[0] != "93.184.216.34" || got[1] != "93.184.216.35" || got[2] != "2606:2800:220:1::1" {
		t.Fatalf("recorded %v", got)
	}
}

// Too big for the client's UDP limit: TC and nothing else, so it asks again
// over TCP. With EDNS0 advertising room, the whole answer.
func TestALargeAnswerIsTruncatedToTheClientsLimit(t *testing.T) {
	f := newFixture(t, nil)
	f.up.answers["pkg.example"] = func(q dnsmessage.Question) []dnsmessage.Resource {
		var rr []dnsmessage.Resource
		for i := range 60 {
			rr = append(rr, rrA(q.Name, netip.AddrFrom4([4]byte{93, 184, 1, byte(i)}).String(), 60))
		}
		return rr
	}
	m, line := f.ask(t, query(t, 1, "pkg.example.", dnsmessage.TypeA, false))
	if !m.Truncated || len(m.Answers) != 0 {
		t.Fatalf("no EDNS0: truncated %v with %d answers", m.Truncated, len(m.Answers))
	}
	expect(t, line, map[string]any{"truncated": true})
	m, _ = f.ask(t, query(t, 2, "pkg.example.", dnsmessage.TypeA, true))
	if m.Truncated || len(m.Answers) != 60 {
		t.Fatalf("EDNS0 4096: truncated %v with %d answers", m.Truncated, len(m.Answers))
	}
}

// A RATE-LIMITED DROP IS LOGGED. ottergate drops with `continue` and writes
// nothing, which is the silent drop PLAN.md calls a bug.
func TestARateLimitedQueryIsDroppedAndLogged(t *testing.T) {
	now := time.Unix(0, 0)
	f := newFixture(t, func(c *Config) {
		c.Rate, c.Burst = 1, 2
		c.Now = func() time.Time { return now }
	})
	uc, client := udpPair(t)
	for i := range 3 {
		f.s.ServePacket(context.Background(), datagram(uc, testPeer, query(t, uint16(i), "pkg.example.", dnsmessage.TypeA, false)))
	}
	f.s.Wait()
	lines := f.j.lines(t)
	if len(lines) != 3 {
		t.Fatalf("%d lines for 3 queries", len(lines))
	}
	var dropped []map[string]any
	for _, l := range lines {
		if l["decision"] == DecisionDropped {
			dropped = append(dropped, l)
		}
	}
	if len(dropped) != 1 {
		t.Fatalf("dropped %d, want 1: %v", len(dropped), lines)
	}
	expect(t, dropped[0], map[string]any{"reason": "rate limited", "name": "pkg.example", "type": "A"})
	if _, ok := dropped[0]["rcode"]; ok {
		t.Error("a dropped query claims an rcode it never sent")
	}
	_ = client
}

func TestTheInFlightCapDropsAndLogs(t *testing.T) {
	block := make(chan struct{})
	f := newFixture(t, func(c *Config) { c.MaxInFlight = 1 })
	f.up.block = block
	uc, _ := udpPair(t)
	f.s.ServePacket(context.Background(), datagram(uc, testPeer, query(t, 1, "pkg.example.", dnsmessage.TypeA, false)))
	f.s.ServePacket(context.Background(), datagram(uc, testPeer, query(t, 2, "pkg.example.", dnsmessage.TypeA, false)))
	close(block)
	f.s.Wait()
	lines := f.j.lines(t)
	if len(lines) != 2 {
		t.Fatalf("%d lines for 2 queries", len(lines))
	}
	if lines[0]["reason"] != "in-flight cap" || lines[0]["decision"] != DecisionDropped {
		t.Fatalf("the second query was not dropped at the cap: %v", lines)
	}
}

// datagram is a steered datagram whose reply goes out of an ordinary socket:
// the transparent socket and PKTINFO are steer's, and tested there.
func datagram(uc *net.UDPConn, peer netip.AddrPort, payload []byte) *steer.Datagram {
	return steer.NewDatagram("sess-d", peer, testDst, payload, func(b []byte) error {
		_, err := uc.WriteToUDPAddrPort(b, peer)
		return err
	})
}

func udpPair(t *testing.T) (server, client *net.UDPConn) {
	t.Helper()
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	c, err := net.DialUDP("udp4", nil, s.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(); _ = c.Close() })
	return s, c
}

// Over real UDP, through ServePacket: the reply reaches the client, and the
// payload buffer steer reuses can be overwritten the moment ServePacket
// returns without corrupting the query being answered.
func TestServePacketAnswersOverUDP(t *testing.T) {
	f := newFixture(t, nil)
	uc, client := udpPair(t)
	peer := netip.MustParseAddrPort(client.LocalAddr().String())
	buf := query(t, 0x4242, "pkg.example.", dnsmessage.TypeA, false)
	f.s.ServePacket(context.Background(), datagram(uc, peer, buf))
	for i := range buf {
		buf[i] = 0xff // steer's next datagram
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 1500)
	n, err := client.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(b[:n]); err != nil {
		t.Fatal(err)
	}
	if m.ID != 0x4242 || len(m.Answers) != 1 {
		t.Fatalf("reply = %+v", m)
	}
	f.s.Wait()
	if n := len(f.j.lines(t)); n != 1 {
		t.Fatalf("%d lines for one datagram", n)
	}
}

// DNS over TCP, RFC 7766: two queries pipelined in one write are both
// answered, in order, one line each; then a frame that stops halfway is a
// query that will never be answered, and gets a line of its own.
func TestServeConnAnswersPipelinedTCP(t *testing.T) {
	f := newFixture(t, nil)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		tc := c.(*net.TCPConn)
		f.s.ServeConn(context.Background(), &steer.Conn{TCPConn: tc, Session: "sess-d", ID: 42, Peer: testPeer, Orig: testDst})
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	var out bytes.Buffer
	for _, q := range [][]byte{query(t, 1, "pkg.example.", dnsmessage.TypeA, false), query(t, 2, "nope.example.", dnsmessage.TypeA, false)} {
		_ = writeFrame(&out, q)
	}
	if _, err := c.Write(out.Bytes()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		id    uint16
		rcode dnsmessage.RCode
	}{{1, dnsmessage.RCodeSuccess}, {2, dnsmessage.RCodeRefused}} {
		b, err := readFrame(c)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(b); err != nil {
			t.Fatal(err)
		}
		if m.ID != want.id || m.RCode != want.rcode {
			t.Fatalf("reply id %d rcode %v, want %d %v", m.ID, m.RCode, want.id, want.rcode)
		}
	}
	if _, err := c.Write([]byte{0, 40, 1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	<-done

	lines := f.j.lines(t)
	if len(lines) != 3 {
		t.Fatalf("%d lines, want 3: %v", len(lines), lines)
	}
	for _, l := range lines {
		expect(t, l, map[string]any{"transport": "tcp", "conn": float64(42)})
	}
	expect(t, lines[2], map[string]any{"decision": DecisionDropped, "reason": "truncated frame"})
}

// FuzzHandle drives the query path with bytes the sandbox chose. It must never
// panic; every call is exactly one line; any reply parses, carries the query's
// id and is a response; and nothing that is not an allowed name ever reaches
// the upstream.
func FuzzHandle(f *testing.F) {
	for _, s := range [][]byte{
		query(f, 1, "pkg.example.", dnsmessage.TypeA, false),
		query(f, 2, "pkg.example.", dnsmessage.TypeAAAA, true),
		query(f, 3, "api.github.com.", dnsmessage.TypeA, false),
		query(f, 4, "evil.example.", dnsmessage.TypeA, false),
		query(f, 5, "x.cdn.example.", dnsmessage.TypeHTTPS, true),
		{0xbe, 0xef, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'a', '.', 'b', 0, 0, 1, 0, 1},
		{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1}, // a pointer to itself
		{},
	} {
		f.Add(s)
	}
	fx := newFixture(f, nil)
	f.Fuzz(func(t *testing.T, req []byte) {
		fx.j.reset()
		before := fx.up.count()
		m, _ := fx.ask(t, req)
		if m != nil {
			if !m.Response || len(req) < 2 || m.ID != uint16(req[0])<<8|uint16(req[1]) {
				t.Fatalf("reply %+v to a query with id bytes %v", m.Header, req[:min(2, len(req))])
			}
		}
		if fx.up.count() > before {
			q := fx.up.asked[len(fx.up.asked)-1]
			if !fx.s.cfg.Allow.Match(q.Name.String()) || fx.s.cfg.Intercept.Match(q.Name.String()) {
				t.Fatalf("%q reached the upstream", q.Name.String())
			}
		}
	})
}

// FuzzStream is the same for the TCP framing: any byte stream, answered frame
// by frame, never panics, and every reply frame parses.
func FuzzStream(f *testing.F) {
	var two bytes.Buffer
	_ = writeFrame(&two, query(f, 1, "pkg.example.", dnsmessage.TypeA, false))
	_ = writeFrame(&two, query(f, 2, "nope.example.", dnsmessage.TypeA, false))
	f.Add(two.Bytes())
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 40, 1})
	f.Add([]byte{0xff, 0xff})
	fx := newFixture(f, nil)
	f.Fuzz(func(t *testing.T, in []byte) {
		var out bytes.Buffer
		fx.s.serveStream(context.Background(), &streamRW{r: bytes.NewReader(in), w: &out}, 1, testPeer, testDst)
		for out.Len() > 0 {
			b, err := readFrame(&out)
			if err != nil {
				t.Fatalf("a reply frame does not frame: %v", err)
			}
			var m dnsmessage.Message
			if err := m.Unpack(b); err != nil {
				t.Fatalf("a reply does not parse: %v", err)
			}
		}
	})
}

type streamRW struct {
	r *bytes.Reader
	w *bytes.Buffer
}

func (s *streamRW) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *streamRW) Write(p []byte) (int, error) { return s.w.Write(p) }
