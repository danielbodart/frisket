package intercept

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

// gRPC over HTTP/2 as it is on the wire, framed here rather than by grpc-go
// (decision 1): each message a flag byte and a four-byte length before it,
// and the call's status in trailers, or in the headers of a response with no
// body.
func grpcFrame(msg string) []byte {
	b := make([]byte, 5+len(msg))
	binary.BigEndian.PutUint32(b[1:], uint32(len(msg)))
	copy(b[5:], msg)
	return b
}

func readGRPCFrame(r io.Reader) (string, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return "", err
	}
	b := make([]byte, binary.BigEndian.Uint32(h[1:]))
	_, err := io.ReadFull(r, b)
	return string(b), err
}

var chatOperation = &Operation{ID: "chat", Summary: "Chat"}

// grpcEcho echoes each message as it arrives and ends with
// FAILED_PRECONDITION in its trailers -- declared ahead for Chat, as
// grpc-go's ServeHTTP does, and not for anything else, as its own server
// does -- and answers Fail with PERMISSION_DENIED and no body at all.
func grpcEcho(t *testing.T) *upstream {
	return newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		if r.URL.Path == "/pkg.Echo/Fail" {
			w.Header().Set("Grpc-Status", "7")
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/pkg.Echo/Chat" {
			w.Header().Set("Trailer", "Grpc-Status")
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			msg, err := readGRPCFrame(r.Body)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return
			}
			_, _ = w.Write(grpcFrame(msg))
			w.(http.Flusher).Flush()
		}
		if r.URL.Path == "/pkg.Echo/Chat" {
			w.Header().Set("Grpc-Status", "9")
			return
		}
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "9")
	})
}

func grpcRoute(up *upstream, t *testing.T, j *journal) Route {
	cred, _ := tokenFile(t, j, realToken)
	r := apiRoute(up, cred)
	r.Scope = Scope{Paths: []PathRule{
		{Methods: []string{"POST"}, Prefix: "/pkg.Echo"},
		{Methods: []string{"POST"}, Path: "/pkg.Echo/Chat", Ask: true, Operation: chatOperation},
	}}
	return r
}

// A bidirectional stream is asked about by its first message -- the client
// sends it and waits for the answer, so frisket may not wait for more -- and
// once admitted flows both ways, message by message, to its status.
func TestABidirectionalStreamIsAskedAboutByItsFirstMessage(t *testing.T) {
	j := &journal{}
	up := grpcEcho(t)
	asked := make(chan Question, 1)
	allow := make(chan struct{})
	asker := &answers{answer: func(q Question) (bool, error) {
		asked <- q
		<-allow
		return true, nil
	}}
	f := newFixtureAsking(t, j, slog.LevelInfo, asker, grpcRoute(up, t, j))
	c := f.client(t, true)

	pr, pw := io.Pipe()
	req := newRequest(t, "POST", "https://"+apiHost+"/pkg.Echo/Chat", pr)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	type result struct {
		res *http.Response
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := c.Do(req)
		done <- result{res, err}
	}()

	if _, err := pw.Write(grpcFrame("first")); err != nil {
		t.Fatal(err)
	}
	var q Question
	select {
	case q = <-asked:
	case <-time.After(5 * time.Second):
		t.Fatal("never asked: frisket waited for more than the first message")
	}
	if q.Body != string(grpcFrame("first")) || !q.BodyMore || q.BodyLength != 0 || q.Operation != chatOperation {
		t.Fatalf("question: body %q, more %v, length %d, operation %v", q.Body, q.BodyMore, q.BodyLength, q.Operation)
	}
	if n := len(up.requests()); n != 0 {
		t.Fatalf("upstream saw the stream before it was admitted")
	}
	close(allow)

	var res *http.Response
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		res = r.res
	case <-time.After(5 * time.Second):
		t.Fatal("no response headers after the stream was admitted")
	}
	defer res.Body.Close()
	if msg, err := readGRPCFrame(res.Body); err != nil || msg != "first" {
		t.Fatalf("first reply %q %v", msg, err)
	}
	for i := range 3 {
		msg := fmt.Sprintf("message %d", i)
		if _, err := pw.Write(grpcFrame(msg)); err != nil {
			t.Fatal(err)
		}
		if got, err := readGRPCFrame(res.Body); err != nil || got != msg {
			t.Fatalf("reply %d: %q %v", i, got, err)
		}
	}
	_ = pw.Close()
	if _, err := io.ReadAll(res.Body); err != nil {
		t.Fatal(err)
	}
	if got := res.Trailer.Get("Grpc-Status"); got != "9" {
		t.Fatalf("trailer grpc-status %q", got)
	}

	l := f.journal.waitLines(t, "request", 1)[0]
	if l["rule"] != RuleAsked || l["status"] != float64(200) || l["grpc_status"] != float64(9) {
		t.Fatalf("log: %v", l)
	}
	if n := len(asker.questions); n != 1 {
		t.Fatalf("asked %d times", n)
	}
}

// A gRPC call's line carries its status, from its trailers or from a response
// that is headers alone; anything else has none.
func TestAGRPCCallIsLoggedByItsStatus(t *testing.T) {
	j := &journal{}
	up := grpcEcho(t)
	f := newFixture(t, j, grpcRoute(up, t, j))
	c := f.client(t, true)
	for _, path := range []string{"/pkg.Echo/Fail", "/pkg.Echo/Say"} {
		req := newRequest(t, "POST", "https://"+apiHost+path, strings.NewReader(string(grpcFrame("hi"))))
		req.Header.Set("Content-Type", "application/grpc+proto")
		if res, _ := get(t, c, req); res.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", path, res.StatusCode)
		}
	}
	get(t, c, newRequest(t, "POST", "https://"+apiHost+"/pkg.Echo/Say", strings.NewReader("{}")))
	lines := f.journal.waitLines(t, "request", 3)
	for i, want := range []any{float64(7), float64(9), nil} {
		if lines[i]["grpc_status"] != want || lines[i]["status"] != float64(200) {
			t.Errorf("line %d: %v", i, lines[i])
		}
	}
}
