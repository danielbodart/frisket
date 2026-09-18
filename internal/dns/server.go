package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/danielbodart/frisket/internal/steer"
)

// Defaults for the knobs on Config.
const (
	// DefaultRate and DefaultBurst bound queries per second for one session.
	// The whole sandbox is one source, so this is a limit on the sandbox and
	// not a per-client fairness scheme -- ottergate's per-source-IP buckets
	// would be a self-limit here, and its eviction scans the whole map.
	DefaultRate  = 100
	DefaultBurst = 200
	// DefaultMaxInFlight bounds concurrent upstream lookups per session. Each
	// one is a goroutine and a host socket.
	DefaultMaxInFlight = 64
	// DefaultServiceTTL is the TTL on an intercepted name's answer. Short, so
	// a policy change reaches clients soon; the address never changes anyway.
	DefaultServiceTTL = time.Minute
	// DefaultTCPIdle is how long a DNS-over-TCP connection may sit between
	// queries. RFC 7766 leaves it to the server and suggests seconds.
	DefaultTCPIdle = 10 * time.Second
)

// Decisions on a query's line.
const (
	DecisionResolved    = "resolved"
	DecisionIntercepted = "intercepted"
	DecisionRefused     = "refused"
	DecisionDropped     = "dropped"
	DecisionFailed      = "failed"
)

// Recorder is where upstream answers for allowed names go: the session's
// resolved set, which egress consults at connect. egress.Resolved implements
// it; this package does not import egress.
type Recorder interface {
	Record(name string, addr netip.Addr, ttl time.Duration, query uint64)
}

// Config is one session's DNS policy and plumbing.
type Config struct {
	// Session and Policy label every line.
	Session string
	Policy  string

	// Allow is the name allowlist. Nil allows nothing.
	Allow *Matcher
	// Intercept names are answered with Service instead of being resolved.
	// Only names Allow also matches are intercepted: interception is how an
	// allowed host gets its credential, not a way round the allowlist.
	Intercept *Matcher
	// Service is the session's service address(es): v4 answers A queries, v6
	// answers AAAA.
	Service    []netip.Addr
	ServiceTTL time.Duration

	Upstream Exchanger
	Resolved Recorder

	// Log is injected and required. A logger that silences itself under test
	// -- ottergate's does, by sniffing os.Args -- makes "one line per query"
	// untestable.
	Log *slog.Logger

	Rate        float64
	Burst       int
	MaxInFlight int
	TCPIdle     time.Duration

	// Now is the clock for the rate limiter; nil means time.Now.
	Now func() time.Time
}

// Server is one session's DNS server, over UDP (as a steer.PacketHandler) and
// TCP (as a steer.Handler).
type Server struct {
	cfg      Config
	seq      atomic.Uint64
	limit    *bucket
	inflight chan struct{}
	wg       sync.WaitGroup
}

var (
	_ steer.Handler       = (*Server)(nil)
	_ steer.PacketHandler = (*Server)(nil)
)

// New validates cfg and fills in defaults.
func New(cfg Config) (*Server, error) {
	if cfg.Log == nil {
		return nil, errors.New("dns: a server needs a logger")
	}
	if cfg.Resolved == nil {
		return nil, errors.New("dns: a server needs a resolved set to record answers in")
	}
	if cfg.Upstream == nil {
		return nil, errors.New("dns: a server needs an upstream")
	}
	for _, a := range cfg.Service {
		if !a.IsValid() || a.Zone() != "" {
			return nil, fmt.Errorf("dns: service address %v is not a plain address", a)
		}
	}
	if cfg.ServiceTTL <= 0 {
		cfg.ServiceTTL = DefaultServiceTTL
	}
	if cfg.Rate <= 0 {
		cfg.Rate = DefaultRate
	}
	if cfg.Burst <= 0 {
		cfg.Burst = DefaultBurst
	}
	if cfg.MaxInFlight <= 0 {
		cfg.MaxInFlight = DefaultMaxInFlight
	}
	if cfg.TCPIdle <= 0 {
		cfg.TCPIdle = DefaultTCPIdle
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Server{
		cfg:      cfg,
		limit:    newBucket(cfg.Rate, cfg.Burst, cfg.Now),
		inflight: make(chan struct{}, cfg.MaxInFlight),
	}, nil
}

// Wait blocks until every query already accepted has been answered and
// logged. For shutdown, and for tests.
func (s *Server) Wait() { s.wg.Wait() }

// ServePacket answers one datagram.
//
// steer reuses the payload's buffer for the next datagram as soon as this
// returns, and an upstream lookup can take seconds, so the query is copied and
// answered on its own goroutine -- bounded by the in-flight cap, because
// unbounded is one goroutine per packet a sandbox cares to send (ottergate's
// shape).
//
// The reply goes out through the datagram's own Reply, which sends it FROM the
// address the client asked -- 8.8.8.8:53, or 127.0.0.1:53 -- so a client that
// only accepts an answer from where it sent the question gets one.
func (s *Server) ServePacket(ctx context.Context, d *steer.Datagram) {
	l := s.newLine("udp", d.Peer, d.Orig)
	if !s.admit(&l, d.Payload) {
		return
	}
	req := bytes.Clone(d.Payload)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { <-s.inflight }()
		resp := s.handle(ctx, req, &l, true)
		if resp != nil {
			if err := d.Reply(resp); err != nil && l.err == nil {
				l.err = fmt.Errorf("reply: %w", err)
			}
		}
		s.log(&l)
	}()
}

// ServeConn answers DNS over TCP (RFC 7766): two-byte length-prefixed
// messages, several per connection, answered in order.
func (s *Server) ServeConn(ctx context.Context, c *steer.Conn) {
	defer c.Close()
	s.serveStream(ctx, c.TCPConn, c.ID, c.Peer, c.Orig)
}

type deadliner interface {
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// serveStream is ServeConn without the socket, so the framing can be fuzzed
// with a byte stream.
func (s *Server) serveStream(ctx context.Context, rw io.ReadWriter, conn uint64, peer, orig netip.AddrPort) {
	dl, _ := rw.(deadliner)
	if dl != nil {
		stop := context.AfterFunc(ctx, func() { _ = dl.SetReadDeadline(time.Unix(1, 0)) })
		defer stop()
	}
	for queries := 0; ; queries++ {
		if dl != nil {
			_ = dl.SetReadDeadline(s.cfg.Now().Add(s.cfg.TCPIdle))
		}
		msg, partial, err := readQueryFrame(rw)
		if err != nil {
			switch {
			case partial:
				// A frame that started and did not finish is a query we will
				// never answer, and that is worth a line.
				l := s.newLine("tcp", peer, orig)
				l.conn = conn
				l.drop("truncated frame")
				l.err = err
				s.log(&l)
			case queries == 0:
				// And a connection that asked nothing still gets its one
				// line: every connection frisket accepts is in the log.
				l := s.newLine("tcp", peer, orig)
				l.conn = conn
				l.drop("no query")
				s.log(&l)
			}
			return
		}
		l := s.newLine("tcp", peer, orig)
		l.conn = conn
		if !s.admit(&l, msg) {
			continue
		}
		resp := s.handle(ctx, msg, &l, false)
		<-s.inflight
		if resp != nil {
			if dl != nil {
				_ = dl.SetWriteDeadline(s.cfg.Now().Add(s.cfg.TCPIdle))
			}
			if err := writeFrame(rw, resp); err != nil {
				l.err = fmt.Errorf("reply: %w", err)
				s.log(&l)
				return
			}
		}
		s.log(&l)
	}
}

// readQueryFrame reads one RFC 7766 frame and says whether it had started when
// it failed: EOF on a frame boundary is the client hanging up, EOF inside one
// is a truncated query.
func readQueryFrame(r io.Reader) (msg []byte, partial bool, err error) {
	var l [2]byte
	n, err := io.ReadFull(r, l[:])
	if err != nil {
		return nil, n > 0, err
	}
	b := make([]byte, int(l[0])<<8|int(l[1]))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, true, err
	}
	return b, false, nil
}

// admit applies the rate limit and the in-flight cap, and on refusal logs the
// drop -- with the name, if the query has one, because "rate limited" with no
// name says nothing about what was being asked. On success the caller holds an
// in-flight slot and must release it.
//
// Dropped, not answered: an answer costs what the flood costs, and a client
// retries a query that went unanswered, where REFUSED would be final for the
// name and, to musl, for the rest of its search list.
func (s *Server) admit(l *line, req []byte) bool {
	reason := ""
	if !s.limit.allow() {
		reason = "rate limited"
	} else {
		select {
		case s.inflight <- struct{}{}:
			return true
		default:
			reason = "in-flight cap"
		}
	}
	peekQuestion(req, l)
	l.drop(reason)
	s.log(l)
	return false
}

// typeIXFR is RFC 1995's incremental transfer, which dnsmessage does not name.
const typeIXFR dnsmessage.Type = 251

// Reply size limits. 512 is UDP's without EDNS0; a client that advertises more
// gets up to what it advertised. TCP is bounded only by the frame.
const (
	udpLimit = 512
	tcpLimit = 0xffff
)

// handle answers one query and fills in its line. A nil reply means none is
// sent: to a response (answering those is how reflection loops start) and to
// anything too broken to have an id to reply to.
func (s *Server) handle(ctx context.Context, req []byte, l *line, udp bool) []byte {
	limit := tcpLimit
	if udp {
		limit = udpLimit
	}
	var p dnsmessage.Parser
	h, err := p.Start(req)
	if err != nil {
		l.drop("malformed header")
		l.err = err
		return nil
	}
	if h.Response {
		l.drop("not a query")
		return nil
	}
	// THE ANSWER CODE IS CHOSEN CASE BY CASE, because stub resolvers act on
	// it. NXDOMAIN says the name does not exist, and a resolver carries on
	// down its search list; every other failure can stop it there.
	q, err := p.Question()
	if err != nil {
		// FORMERR: the query itself is broken, and the id is known, so say so
		// rather than leave the client to time out. dnsmessage refuses a label
		// containing a dot here -- the name ottergate would have logged as
		// api.github.com never exists.
		l.refuse("malformed question", dnsmessage.RCodeFormatError)
		l.err = err
		return s.reply(h, nil, l, nil, nil, ednsInfo{}, limit)
	}
	l.question(q)
	if _, err := p.Question(); !errors.Is(err, dnsmessage.ErrSectionDone) {
		l.refuse("more than one question", dnsmessage.RCodeFormatError)
		return s.reply(h, &q, l, nil, nil, ednsInfo{}, limit)
	}
	edns, err := readEDNS(&p)
	if err != nil {
		l.refuse("malformed records", dnsmessage.RCodeFormatError)
		l.err = err
		return s.reply(h, &q, l, nil, nil, ednsInfo{}, limit)
	}
	if edns.present && udp {
		limit = max(udpLimit, int(edns.size))
	}
	// NOTIMP: an opcode other than QUERY -- NOTIFY, UPDATE -- is an operation
	// frisket does not implement, which is exactly what the code says. Stub
	// resolvers never send one.
	if h.OpCode != 0 {
		l.refuse(fmt.Sprintf("opcode %d", h.OpCode), dnsmessage.RCodeNotImplemented)
		return s.reply(h, &q, l, nil, nil, edns, limit)
	}
	// REFUSED: frisket serves class IN and declines the rest -- CHAOS's
	// version.bind and the like -- by policy, which is what REFUSED means. The
	// name may well exist in that class, so NXDOMAIN would be a lie, and a
	// search list is only ever walked in class IN.
	if q.Class != dnsmessage.ClassINET {
		l.refuse("class "+strings.TrimPrefix(q.Class.String(), "Class"), dnsmessage.RCodeRefused)
		return s.reply(h, &q, l, nil, nil, edns, limit)
	}
	// NXDOMAIN: a string no name could be is not allowed by any policy -- even
	// "*" is every name, not every string -- so it gets a name not allowed's
	// answer, below.
	name := Normalize(q.Name.String())
	if !ValidQueryName(name) {
		l.refuse("invalid name", dnsmessage.RCodeNameError)
		return s.reply(h, &q, l, nil, nil, edns, limit)
	}
	// NOT ALLOWED MEANS NO UPSTREAM LOOKUP. A refused name must not leave the
	// host at all, or DNS is an exfiltration channel with a refusal on top.
	//
	// NXDOMAIN, NOT REFUSED. musl -- Alpine, and every static binary built
	// on it -- treats REFUSED as a hard failure and stops walking the
	// resolv.conf search list, so with `search lan` a refused `foo.lan` means
	// `foo` alone is never tried, and a name the policy does allow fails
	// because of one it does not. Cilium documents the same and makes its
	// reject code configurable for it. To the sandbox, a name it may not
	// resolve is a name that does not exist.
	if !s.cfg.Allow.Match(name) {
		l.refuse("not allowed", dnsmessage.RCodeNameError)
		return s.reply(h, &q, l, nil, nil, edns, limit)
	}
	// NOTIMP: frisket is not a zone's server and has no transfer to give.
	if q.Type == dnsmessage.TypeAXFR || q.Type == typeIXFR {
		l.refuse("zone transfer", dnsmessage.RCodeNotImplemented)
		return s.reply(h, &q, l, nil, nil, edns, limit)
	}
	if s.cfg.Intercept.Match(name) {
		return s.reply(h, &q, l, s.intercept(q, l), nil, edns, limit)
	}

	l.upstream = true
	m, tr, err := s.cfg.Upstream.Exchange(ctx, q)
	l.trace = tr
	if err != nil {
		// SERVFAIL: the name may exist and frisket could not find out. That
		// is temporary, a client retries it, and NXDOMAIN would be a lie a
		// negative cache would keep.
		l.fail("upstream", err)
		return s.reply(h, &q, l, nil, nil, edns, limit)
	}
	l.decision, l.rcode = DecisionResolved, m.RCode
	for _, a := range chainAddrs(q.Name, m.Answers) {
		s.cfg.Resolved.Record(name, a.addr, time.Duration(a.ttl)*time.Second, l.id)
		l.answers = append(l.answers, a.addr.String())
	}
	return s.reply(h, &q, l, m.Answers, m.Authorities, edns, limit)
}

// intercept answers an intercepted name with the service address.
func (s *Server) intercept(q dnsmessage.Question, l *line) []dnsmessage.Resource {
	l.decision, l.rcode = DecisionIntercepted, dnsmessage.RCodeSuccess
	ttl := uint32(s.cfg.ServiceTTL / time.Second)
	var out []dnsmessage.Resource
	for _, a := range s.cfg.Service {
		hdr := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: ttl}
		switch {
		case q.Type == dnsmessage.TypeA && a.Unmap().Is4():
			hdr.Type = dnsmessage.TypeA
			out = append(out, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: a.Unmap().As4()}})
		case q.Type == dnsmessage.TypeAAAA && a.Is6() && !a.Is4In6():
			hdr.Type = dnsmessage.TypeAAAA
			out = append(out, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AAAAResource{AAAA: a.As16()}})
		default:
			continue
		}
		l.answers = append(l.answers, a.String())
	}
	// Any other type -- HTTPS, TXT, MX -- is NOERROR with no records: the name
	// exists, there is just nothing of that type. A client falls back to A.
	return out
}

// reply builds the answer. Everything sent goes through dnsmessage's builder;
// nothing is assembled by hand. If it does not fit the client's limit it goes
// out truncated, with no records, and the client asks again over TCP.
func (s *Server) reply(h dnsmessage.Header, q *dnsmessage.Question, l *line, answers, authorities []dnsmessage.Resource, edns ednsInfo, limit int) []byte {
	m := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 h.ID,
			Response:           true,
			OpCode:             h.OpCode,
			RecursionDesired:   h.RecursionDesired,
			RecursionAvailable: true,
			RCode:              l.rcode,
		},
		Answers:     answers,
		Authorities: authorities,
	}
	if q != nil {
		m.Questions = []dnsmessage.Question{*q}
	}
	if edns.present {
		var opt dnsmessage.ResourceHeader
		if err := opt.SetEDNS0(upstreamUDPSize, dnsmessage.RCodeSuccess, false); err == nil {
			m.Additionals = []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}}
		}
	}
	b, err := m.Pack()
	if err == nil && len(b) <= limit {
		return b
	}
	if err != nil {
		// The upstream sent something dnsmessage could read and cannot write
		// back. Say so rather than send it on.
		l.fail("packing the reply", err)
		m.Header.RCode = dnsmessage.RCodeServerFailure
	} else {
		l.truncated = true
		m.Header.Truncated = true
	}
	m.Answers, m.Authorities = nil, nil
	b, err = m.Pack()
	if err != nil {
		l.fail("packing the reply", err)
		return nil
	}
	return b
}

type ednsInfo struct {
	present bool
	size    uint16
}

// readEDNS skips to the additional section and reads the OPT record's
// advertised payload size, which is what a UDP reply is allowed to fill.
func readEDNS(p *dnsmessage.Parser) (ednsInfo, error) {
	if err := p.SkipAllAnswers(); err != nil {
		return ednsInfo{}, err
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return ednsInfo{}, err
	}
	var e ednsInfo
	for {
		h, err := p.AdditionalHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return e, nil
		}
		if err != nil {
			return ednsInfo{}, err
		}
		if h.Type == dnsmessage.TypeOPT {
			e = ednsInfo{present: true, size: uint16(h.Class)}
		}
		if err := p.SkipAdditional(); err != nil {
			return ednsInfo{}, err
		}
	}
}

type answered struct {
	addr netip.Addr
	ttl  uint32
}

// maxChain bounds how many names a CNAME chain may add. Real chains are two or
// three long; the bound is only there so a hostile answer is linear.
const maxChain = 16

// chainAddrs returns the addresses the answer gives for qname: records whose
// owner is qname or a name it is CNAMEd to, followed from qname. An A record
// for some other name, included in the answer by a hostile upstream, is not an
// answer to this question -- no client would use it, and it must not become an
// address the session is allowed to reach.
//
// HTTPS and SVCB hints count: a browser can connect to an ipv4hint before its
// A query returns, and refusing that would be a failure with nothing in it for
// security -- the hints came from the same answer for the same allowed name.
func chainAddrs(qname dnsmessage.Name, rrs []dnsmessage.Resource) []answered {
	chain := []dnsmessage.Name{qname}
	inChain := func(n dnsmessage.Name) bool {
		for _, c := range chain {
			if equalFold(c, n) {
				return true
			}
		}
		return false
	}
	for grew := true; grew && len(chain) < maxChain; {
		grew = false
		for _, rr := range rrs {
			c, ok := rr.Body.(*dnsmessage.CNAMEResource)
			if ok && inChain(rr.Header.Name) && !inChain(c.CNAME) && len(chain) < maxChain {
				chain = append(chain, c.CNAME)
				grew = true
			}
		}
	}
	var out []answered
	for _, rr := range rrs {
		if !inChain(rr.Header.Name) {
			continue
		}
		ttl := rr.Header.TTL
		switch b := rr.Body.(type) {
		case *dnsmessage.AResource:
			out = append(out, answered{netip.AddrFrom4(b.A), ttl})
		case *dnsmessage.AAAAResource:
			out = append(out, answered{netip.AddrFrom16(b.AAAA).Unmap(), ttl})
		case *dnsmessage.HTTPSResource:
			out = appendHints(out, &b.SVCBResource, ttl)
		case *dnsmessage.SVCBResource:
			out = appendHints(out, b, ttl)
		}
	}
	return out
}

func appendHints(out []answered, r *dnsmessage.SVCBResource, ttl uint32) []answered {
	if v, ok := r.GetParam(dnsmessage.SVCParamIPv4Hint); ok && len(v)%4 == 0 {
		for i := 0; i < len(v); i += 4 {
			out = append(out, answered{netip.AddrFrom4([4]byte(v[i : i+4])), ttl})
		}
	}
	if v, ok := r.GetParam(dnsmessage.SVCParamIPv6Hint); ok && len(v)%16 == 0 {
		for i := 0; i < len(v); i += 16 {
			out = append(out, answered{netip.AddrFrom16([16]byte(v[i : i+16])).Unmap(), ttl})
		}
	}
	return out
}

// peekQuestion reads the question out of a query that is about to be dropped,
// for its log line only. Nothing is decided from it.
func peekQuestion(req []byte, l *line) {
	var p dnsmessage.Parser
	if _, err := p.Start(req); err != nil {
		return
	}
	if q, err := p.Question(); err == nil {
		l.question(q)
	}
}

// line is one query's log line, filled in as the query is handled and written
// exactly once.
type line struct {
	start     time.Time
	id        uint64
	transport string
	conn      uint64
	peer, dst netip.AddrPort

	name      string
	qtype     string
	decision  string
	reason    string
	rcode     dnsmessage.RCode
	answers   []string
	upstream  bool
	trace     Trace
	truncated bool
	err       error
}

func (s *Server) newLine(transport string, peer, dst netip.AddrPort) line {
	return line{start: time.Now(), id: s.seq.Add(1), transport: transport, peer: peer, dst: dst}
}

func (l *line) question(q dnsmessage.Question) {
	l.name = logName(q.Name.String())
	l.qtype = strings.TrimPrefix(q.Type.String(), "Type")
}

func (l *line) drop(reason string) { l.decision, l.reason = DecisionDropped, reason }

func (l *line) refuse(reason string, rcode dnsmessage.RCode) {
	l.decision, l.reason, l.rcode = DecisionRefused, reason, rcode
}

func (l *line) fail(reason string, err error) {
	l.decision, l.reason, l.rcode, l.err = DecisionFailed, reason, dnsmessage.RCodeServerFailure, err
}

// logName is the name as the log shows it: normalised when it is a valid name,
// and otherwise with every byte outside [a-z0-9-_.] written as \xNN. The
// backslash is itself outside that set, so the escaping cannot be imitated:
// two different wire names never produce the same log field. That, and
// dnsmessage refusing a dot inside a label, is what keeps the audit trail from
// being made to say a name that was not asked.
func logName(raw string) string {
	n := Normalize(raw)
	if ValidQueryName(n) {
		return n
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '.' || nameByte(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	return b.String()
}

func (s *Server) log(l *line) {
	attrs := []any{
		"session", s.cfg.Session,
		"policy", s.cfg.Policy,
		"query", l.id,
		"transport", l.transport,
	}
	if l.conn != 0 {
		attrs = append(attrs, "conn", l.conn)
	}
	attrs = append(attrs, "peer", l.peer.String(), "dst", l.dst.String())
	if l.name != "" {
		attrs = append(attrs, "name", l.name, "type", l.qtype)
	}
	attrs = append(attrs, "decision", l.decision)
	if l.reason != "" {
		attrs = append(attrs, "reason", l.reason)
	}
	if l.decision != DecisionDropped {
		attrs = append(attrs, "rcode", strings.TrimPrefix(l.rcode.String(), "RCode"))
	}
	if l.answers != nil {
		attrs = append(attrs, "answers", l.answers)
	}
	if l.upstream {
		attrs = append(attrs, "upstream", l.trace.Server.String(), "upstream_transport", l.trace.Transport)
		if l.trace.Mismatched > 0 {
			attrs = append(attrs, "mismatched", l.trace.Mismatched)
		}
	}
	if l.truncated {
		attrs = append(attrs, "truncated", true)
	}
	attrs = append(attrs, "duration_ms", float64(time.Since(l.start).Microseconds())/1000)
	if l.err != nil {
		attrs = append(attrs, "error", l.err.Error())
	}
	s.cfg.Log.Info("dns", attrs...)
}

// bucket is a token bucket: rate per second, up to burst.
type bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newBucket(rate float64, burst int, now func() time.Time) *bucket {
	return &bucket{rate: rate, burst: float64(burst), tokens: float64(burst), last: now(), now: now}
}

func (b *bucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = min(b.burst, b.tokens+el*b.rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
