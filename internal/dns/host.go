package dns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// HostTTL is the TTL on a host answer. The address is a hash of the name,
// so it never changes; an hour only bounds what a cache keeps of a server
// that has since gone.
const HostTTL = time.Hour

// hostMaxConns bounds the TCP connections a host server holds at once.
const hostMaxConns = 64

// Host answers a project's name under .internal on the host, from the name
// alone: Lookup is a pure function (project.FromName, then project.Address),
// so there is nothing to register, nothing kept and nothing that could be
// out of date. It forwards nothing. A name outside .internal is REFUSED, as
// the host's resolver sends it only .internal; one under it that is not a
// project's name is NXDOMAIN. A project's name answers A with its address,
// and every other type, AAAA included, with no records.
//
// It is not a session's Server: no allowlist, no upstream, no resolved set
// to record in. Every query is a line, as a session's are.
type Host struct {
	// Lookup is a name's address, normalised, and whether it is a project's.
	Lookup func(name string) (netip.Addr, bool)
	Log    *slog.Logger
}

// ServeUDP answers each datagram on c until ctx ends or c fails.
func (h *Host) ServeUDP(ctx context.Context, c net.PacketConn) error {
	stop := context.AfterFunc(ctx, func() { _ = c.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()
	buf := make([]byte, 0xffff)
	for {
		n, peer, err := c.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if resp := h.Answer(buf[:n], true, peer.String()); resp != nil {
			_, _ = c.WriteTo(resp, peer)
		}
	}
}

// ServeTCP answers DNS over TCP (RFC 7766) on each connection l accepts,
// at most hostMaxConns at once, until ctx ends or l fails.
func (h *Host) ServeTCP(ctx context.Context, l net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	slots := make(chan struct{}, hostMaxConns)
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer c.Close()
			stop := context.AfterFunc(ctx, func() { _ = c.Close() })
			defer stop()
			for {
				_ = c.SetDeadline(time.Now().Add(DefaultTCPIdle))
				msg, _, err := readQueryFrame(c)
				if err != nil {
					return
				}
				resp := h.Answer(msg, false, c.RemoteAddr().String())
				if resp == nil || writeFrame(c, resp) != nil {
					return
				}
			}
		}()
	}
}

// Answer is the reply to one query, or nil for none: to a response, and to
// anything with no id to reply to. udp bounds the reply as a datagram.
func (h *Host) Answer(req []byte, udp bool, peer string) []byte {
	l := hostLine{peer: peer}
	resp := h.answer(req, udp, &l)
	h.log(&l)
	return resp
}

func (h *Host) answer(req []byte, udp bool, l *hostLine) []byte {
	var p dnsmessage.Parser
	hdr, err := p.Start(req)
	if err != nil {
		l.decision, l.reason = DecisionDropped, "malformed header"
		return nil
	}
	if hdr.Response {
		l.decision, l.reason = DecisionDropped, "not a query"
		return nil
	}
	limit := tcpLimit
	if udp {
		limit = udpLimit
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{
		ID: hdr.ID, Response: true, OpCode: hdr.OpCode,
		RecursionDesired: hdr.RecursionDesired, Authoritative: true,
	}}
	q, err := p.Question()
	if err != nil {
		return l.refuse(&m, "malformed question", dnsmessage.RCodeFormatError, limit)
	}
	m.Questions = []dnsmessage.Question{q}
	l.name, l.qtype = logName(q.Name.String()), strings.TrimPrefix(q.Type.String(), "Type")
	if _, err := p.Question(); !errors.Is(err, dnsmessage.ErrSectionDone) {
		return l.refuse(&m, "more than one question", dnsmessage.RCodeFormatError, limit)
	}
	edns, err := readEDNS(&p)
	if err != nil {
		return l.refuse(&m, "malformed records", dnsmessage.RCodeFormatError, limit)
	}
	if edns.present {
		if udp {
			limit = max(udpLimit, int(edns.size))
		}
		var opt dnsmessage.ResourceHeader
		if err := opt.SetEDNS0(upstreamUDPSize, dnsmessage.RCodeSuccess, false); err == nil {
			m.Additionals = []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}}
		}
	}
	if hdr.OpCode != 0 {
		return l.refuse(&m, fmt.Sprintf("opcode %d", hdr.OpCode), dnsmessage.RCodeNotImplemented, limit)
	}
	if q.Class != dnsmessage.ClassINET {
		return l.refuse(&m, "class "+strings.TrimPrefix(q.Class.String(), "Class"), dnsmessage.RCodeRefused, limit)
	}
	name := Normalize(q.Name.String())
	if name != "internal" && !strings.HasSuffix(name, ".internal") {
		return l.refuse(&m, "not .internal", dnsmessage.RCodeRefused, limit)
	}
	a, ok := h.Lookup(name)
	if !ok || !a.Is4() {
		return l.refuse(&m, "not a project's", dnsmessage.RCodeNameError, limit)
	}
	l.decision = DecisionLocal
	if q.Type == dnsmessage.TypeA {
		l.answers = []string{a.String()}
		m.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: uint32(HostTTL / time.Second)},
			Body:   &dnsmessage.AResource{A: a.As4()},
		}}
	}
	return l.pack(&m, limit)
}

type hostLine struct {
	peer, name, qtype string
	decision, reason  string
	rcode             dnsmessage.RCode
	answers           []string
	truncated, failed bool
}

func (l *hostLine) refuse(m *dnsmessage.Message, reason string, rcode dnsmessage.RCode, limit int) []byte {
	l.decision, l.reason, l.rcode = DecisionRefused, reason, rcode
	m.Header.RCode = rcode
	return l.pack(m, limit)
}

// pack is m, or m truncated with no records when it does not fit.
func (l *hostLine) pack(m *dnsmessage.Message, limit int) []byte {
	b, err := m.Pack()
	if err == nil && len(b) <= limit {
		return b
	}
	l.truncated = err == nil
	m.Header.Truncated = err == nil
	m.Answers = nil
	if b, err = m.Pack(); err != nil {
		l.failed = true
		return nil
	}
	return b
}

func (h *Host) log(l *hostLine) {
	attrs := []any{"peer", l.peer}
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
	if l.truncated {
		attrs = append(attrs, "truncated", true)
	}
	if l.failed {
		attrs = append(attrs, "error", "packing the reply")
	}
	h.Log.Info("host dns", attrs...)
}
