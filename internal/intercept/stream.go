package intercept

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// hopHeaders are a hop's own headers, never carried to the next, as
// ReverseProxy drops them.
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// withoutHops removes a hop's own headers, and every header its Connection
// names.
func withoutHops(h http.Header) {
	for _, v := range h.Values("Connection") {
		for tok := range strings.SplitSeq(v, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				h.Del(tok)
			}
		}
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// stream carries a Docker request that switches to tcp: an exec's or an
// attach's stdin one way and its output the other.
//
// frisket makes the round trip itself rather than through ReverseProxy,
// which copies from the hijacked connection and not from the reader the
// hijack hands back, so stdin a client sent straight after its request is
// lost; and whose half-close hangs on the daemon's side being a response
// body that happens to pass CloseWrite on. Here the socket is frisket's own,
// and each direction ends on its own -- the client's end of input closes the
// socket's write side, and the daemon's end of output sends the client
// close_notify -- so a client that has sent all its stdin still receives
// the output to come. The stream is over when both have ended, or when the
// session has.
func (i *Interceptor) stream(lw *logWriter, r *http.Request, ic *interceptedConn) {
	rec, _ := r.Context().Value(recordKey{}).(*record)
	d := ic.route.docker
	ctx := r.Context()

	s := &streamConns{}
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-finished:
			return
		case <-ic.done:
		case <-i.closing:
		case <-ctx.Done():
		}
		s.end()
	}()
	defer s.end()

	back, err := d.dial(ctx)
	if err != nil {
		upstreamFailed(lw, r, err)
		return
	}
	if !s.hold(back) {
		upstreamFailed(lw, r, errors.New("the session ended"))
		return
	}

	out := r.Clone(ctx)
	out.URL = &url.URL{Scheme: d.target.Scheme, Host: d.target.Host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	out.Host, out.RequestURI, out.Close, out.Trailer = "", "", false, nil
	withoutHops(out.Header)
	for _, k := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Expect"} {
		// As ReverseProxy drops them for a route with Rewrite, which is
		// every route; and Expect, since the body is already whole and there
		// is nothing for the daemon to say continue to.
		out.Header.Del(k)
	}
	out.Header.Set("Connection", "Upgrade")
	out.Header.Set("Upgrade", "tcp")
	if rec != nil {
		rec.dockerHeaders(out.Header)
	}
	if _, ok := out.Header["User-Agent"]; !ok {
		// Request.Write would otherwise add Go's own.
		out.Header["User-Agent"] = []string{""}
	}
	bw := bufio.NewWriter(back)
	if err := out.Write(bw); err != nil {
		upstreamFailed(lw, r, err)
		return
	}
	if err := bw.Flush(); err != nil {
		upstreamFailed(lw, r, err)
		return
	}
	br := bufio.NewReader(back)
	res, err := http.ReadResponse(br, out)
	for err == nil && res.StatusCode < 200 && res.StatusCode != http.StatusSwitchingProtocols {
		// An interim answer is not the one this is waiting for.
		res, err = http.ReadResponse(br, out)
	}
	if err != nil {
		upstreamFailed(lw, r, err)
		return
	}
	defer res.Body.Close()
	// The daemon has answered: its version capped, and the names the
	// request held let go.
	_ = d.modify(res)

	if res.StatusCode != http.StatusSwitchingProtocols {
		// No switch, so an ordinary answer: an error, or a stream of output
		// alone.
		withoutHops(res.Header)
		for k, vs := range res.Header {
			lw.Header()[k] = vs
		}
		lw.WriteHeader(res.StatusCode)
		if _, err := io.Copy(lw, res.Body); err != nil && rec != nil {
			rec.fail(err)
		}
		return
	}
	if !asciiEqualFold(strings.TrimSpace(res.Header.Get("Upgrade")), "tcp") {
		upstreamFailed(lw, r, errors.New("the daemon switched to a protocol other than tcp"))
		return
	}

	front, brw, err := lw.Hijack()
	if err != nil {
		if rec != nil {
			rec.fail(err)
		}
		return
	}
	if !s.hold(front) {
		return
	}
	res.Body = nil
	if err := res.Write(brw); err != nil {
		return
	}
	if err := brw.Flush(); err != nil {
		return
	}
	// What the client sent after its request, before the switch was
	// answered, is stdin already read.
	early, _ := brw.Reader.Peek(brw.Reader.Buffered())
	if rec != nil {
		rec.reqBytes.Add(int64(len(early)))
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		// However its input ends, the daemon is told there is no more of
		// it, and its output is still carried: a daemon that stopped
		// reading may have more to say.
		_, _ = io.Copy(back, io.MultiReader(bytes.NewReader(early), front))
		_ = back.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		if _, err := io.Copy(front, br); err != nil {
			// The daemon broke off, or the client cannot be written to:
			// either way there is nothing more to carry.
			s.end()
			return
		}
		if cw, ok := front.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

// closeWriter is a connection that can finish sending and still receive.
type closeWriter interface{ CloseWrite() error }

// streamConns are a stream's two connections, closed together, once, by
// whichever of its end, the session's or frisket's comes first.
type streamConns struct {
	mu    sync.Mutex
	ended bool
	conns []net.Conn
}

// hold adds a connection to be closed at the end, or closes it now if the
// end has come.
func (s *streamConns) hold(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		_ = c.Close()
		return false
	}
	s.conns = append(s.conns, c)
	return true
}

func (s *streamConns) end() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ended = true
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
}
