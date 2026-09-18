package dns

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DefaultUpstreamTimeout bounds one attempt at one upstream server.
const DefaultUpstreamTimeout = 3 * time.Second

// upstreamUDPSize is the EDNS0 payload size frisket advertises upstream: the
// 2020 DNS flag day's value, which avoids IP fragmentation on any real path.
// A bigger answer comes back truncated and is re-asked over TCP.
const upstreamUDPSize = 1232

// Exchanger resolves one question upstream. The server depends on this, not on
// Upstream, so a test can count lookups -- "a refused name triggers no
// upstream lookup" is a property, and a property needs a counter.
type Exchanger interface {
	Exchange(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, Trace, error)
}

// Trace is what happened upstream, for the query's log line.
type Trace struct {
	Server    netip.AddrPort
	Transport string
	// Mismatched counts responses dropped because their id or question did
	// not match what was sent. Non-zero on a healthy network is worth a look.
	Mismatched int
	// Truncated: the UDP answer had TC set and the question was re-asked
	// over TCP.
	Truncated bool
}

// Upstream is frisket's stub resolver towards the host's real one.
//
// Every query gets three things, which together make an off-path spoofer guess
// roughly 16 bits of id, 16 bits of source port, and one bit per letter of the
// name:
//
//   - 0x20 encoding: each letter of the name sent upstream is randomly upper
//     or lower case, and a response is only accepted if its question matches
//     BYTE FOR BYTE -- a resolver echoes the question it was sent, a spoofer
//     does not know it;
//   - a fresh random transaction id from crypto/rand;
//   - a connected socket of its own, so the kernel drops datagrams from any
//     other address, and the source port is new every time.
//
// This is ottergate's one unambiguously good idea. What it does not do is
// validate DNSSEC: ottergate's validation takes the key out of the response it
// is validating, so it proves nothing, and it SERVFAILs unsigned zones on its
// own allowlist. If upstream integrity matters, the answer is DoT or DoH to a
// validating resolver, not a validator in here.
type Upstream struct {
	// Servers are tried in order until one answers.
	Servers []netip.AddrPort
	// Timeout bounds each attempt; zero means DefaultUpstreamTimeout.
	Timeout time.Duration
	// Dial is injectable; nil means a plain net.Dialer. These connections are
	// frisket's own, to its configured resolver, and do not go through the
	// egress classifier: the resolver is very often on the host's loopback.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// Rand is the entropy for ids and case; nil means crypto/rand.
	Rand io.Reader
}

var errNoServers = errors.New("no upstream DNS servers configured")

// Exchange asks q of each server in turn and returns the first valid answer.
// The answer's question is restored to q's own spelling, and so is the owner
// name of every record the upstream wrote in our randomised case, so the
// client sees exactly the case it asked in.
func (u *Upstream) Exchange(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, Trace, error) {
	var tr Trace
	if len(u.Servers) == 0 {
		return nil, tr, errNoServers
	}
	lastErr := errNoServers
	for _, srv := range u.Servers {
		tr.Server = srv
		m, err := u.attempt(ctx, "udp", srv, q, &tr)
		if err == nil && m.Truncated {
			tr.Truncated = true
			m, err = u.attempt(ctx, "tcp", srv, q, &tr)
		}
		if err == nil {
			return m, tr, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, tr, lastErr
}

func (u *Upstream) attempt(ctx context.Context, network string, srv netip.AddrPort, q dnsmessage.Question, tr *Trace) (*dnsmessage.Message, error) {
	tr.Transport = network
	rnd := u.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	sent, err := randomCase(q, rnd)
	if err != nil {
		return nil, err
	}
	var idb [2]byte
	if _, err := io.ReadFull(rnd, idb[:]); err != nil {
		return nil, fmt.Errorf("transaction id: %w", err)
	}
	id := binary.BigEndian.Uint16(idb[:])
	query, err := buildUpstreamQuery(id, sent)
	if err != nil {
		return nil, err
	}

	timeout := u.Timeout
	if timeout <= 0 {
		timeout = DefaultUpstreamTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dial := u.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, network, srv.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	next, err := exchangeTransport(conn, network, query)
	if err != nil {
		return nil, err
	}
	for {
		b, err := next()
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", network, srv, err)
		}
		m, ok, err := acceptResponse(b, id, sent)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", network, srv, err)
		}
		if !ok {
			// Not ours: keep listening until the deadline. Returning here would
			// let one spoofed datagram cost the real answer.
			tr.Mismatched++
			continue
		}
		restoreCase(m, sent.Name, q.Name)
		return m, nil
	}
}

// exchangeTransport writes the query and returns a function that reads each
// response in turn, framed as the transport frames them.
func exchangeTransport(conn net.Conn, network string, query []byte) (func() ([]byte, error), error) {
	if network == "udp" {
		if _, err := conn.Write(query); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		return func() ([]byte, error) {
			n, err := conn.Read(buf)
			if err != nil {
				return nil, err
			}
			return buf[:n], nil
		}, nil
	}
	if err := writeFrame(conn, query); err != nil {
		return nil, err
	}
	return func() ([]byte, error) { return readFrame(conn) }, nil
}

func buildUpstreamQuery(id uint16, q dnsmessage.Question) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var opt dnsmessage.ResourceHeader
	// DO bit clear: frisket does not validate, so it does not ask for
	// signatures it would only carry.
	if err := opt.SetEDNS0(upstreamUDPSize, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, err
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// acceptResponse decides whether b is the answer to the query (id, sent).
// ok=false means "not ours, keep waiting"; an error means it was ours and is
// unusable.
func acceptResponse(b []byte, id uint16, sent dnsmessage.Question) (*dnsmessage.Message, bool, error) {
	var p dnsmessage.Parser
	h, err := p.Start(b)
	if err != nil || !h.Response || h.ID != id {
		return nil, false, nil
	}
	got, err := p.Question()
	if err != nil || !sameQuestion(got, sent) {
		return nil, false, nil
	}
	if _, err := p.Question(); !errors.Is(err, dnsmessage.ErrSectionDone) {
		return nil, false, nil
	}
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		return nil, true, fmt.Errorf("malformed answer: %w", err)
	}
	return &m, true, nil
}

// sameQuestion is byte-for-byte on the name, case included. That is the whole
// of 0x20: a case-insensitive compare here would accept exactly the forgery it
// exists to catch.
func sameQuestion(a, b dnsmessage.Question) bool {
	return a.Type == b.Type && a.Class == b.Class &&
		bytes.Equal(a.Name.Data[:a.Name.Length], b.Name.Data[:b.Name.Length])
}

// randomCase gives every ASCII letter of the name a random case, one bit of
// entropy each.
func randomCase(q dnsmessage.Question, rnd io.Reader) (dnsmessage.Question, error) {
	n := int(q.Name.Length)
	bits := make([]byte, (n+7)/8)
	if _, err := io.ReadFull(rnd, bits); err != nil {
		return q, fmt.Errorf("0x20 entropy: %w", err)
	}
	out := q
	for i := 0; i < n; i++ {
		c := out.Name.Data[i] | 0x20
		if c < 'a' || c > 'z' {
			continue
		}
		if bits[i/8]&(1<<(i%8)) != 0 {
			c -= 'a' - 'A'
		}
		out.Name.Data[i] = c
	}
	return out, nil
}

// restoreCase puts the client's own spelling back wherever the upstream
// echoed ours: in the question, and on every record whose owner is the name
// that was asked. Clients that do their own 0x20 check compare the question to
// what they sent, and would drop an answer in our randomised case.
func restoreCase(m *dnsmessage.Message, sent, orig dnsmessage.Name) {
	for i := range m.Questions {
		if equalFold(m.Questions[i].Name, sent) {
			m.Questions[i].Name = orig
		}
	}
	for _, sec := range [][]dnsmessage.Resource{m.Answers, m.Authorities, m.Additionals} {
		for i := range sec {
			if equalFold(sec[i].Header.Name, sent) {
				sec[i].Header.Name = orig
			}
		}
	}
}

// equalFold compares names the way DNS does: ASCII case-insensitively.
func equalFold(a, b dnsmessage.Name) bool {
	if a.Length != b.Length {
		return false
	}
	for i := 0; i < int(a.Length); i++ {
		x, y := a.Data[i], b.Data[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// writeFrame and readFrame are RFC 7766's framing: a two-byte big-endian
// length, then the message.
func writeFrame(w io.Writer, msg []byte) error {
	if len(msg) > 0xffff {
		return fmt.Errorf("message of %d bytes does not fit a TCP frame", len(msg))
	}
	b := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(b, uint16(len(msg)))
	copy(b[2:], msg)
	_, err := w.Write(b)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(r, b); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return b, nil
}
