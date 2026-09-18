package egress

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// A spliced connection, as the test sees it: the workload's end, the upstream
// server's end, and the splice running between the two ends frisket holds.
type spliced struct {
	workload, server *net.TCPConn
	held             [2]*net.TCPConn
	done             chan SpliceResult
}

// startSplice wires workload <-> [frisket's two ends, spliced] <-> server. The
// caller defers close.
func startSplice(t tb, ctx context.Context, idle time.Duration) *spliced {
	t.Helper()
	workload, fromWorkload := tcpPair(t)
	toServer, server := tcpPair(t)
	s := &spliced{workload: workload, server: server, held: [2]*net.TCPConn{fromWorkload, toServer}, done: make(chan SpliceResult, 1)}
	go func() { s.done <- Splice(ctx, fromWorkload, toServer, idle) }()
	return s
}

func (s *spliced) close() {
	for _, c := range []*net.TCPConn{s.workload, s.server, s.held[0], s.held[1]} {
		_ = c.Close()
	}
}

func (s *spliced) wait(t tb, within time.Duration) SpliceResult {
	t.Helper()
	select {
	case r := <-s.done:
		return r
	case <-time.After(within):
		t.Fatalf("the splice did not finish within %v", within)
		return SpliceResult{}
	}
}

// writeChunks writes b in the given chunk sizes, cycling through them.
func writeChunks(c *net.TCPConn, b []byte, chunks []int) error {
	for i := 0; len(b) > 0; i++ {
		n := min(max(chunks[i%len(chunks)], 1), len(b))
		if _, err := c.Write(b[:n]); err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// THE HALF-CLOSE REGRESSION. The workload sends its request and shuts down its
// write side; the upstream reads to EOF -- which it only sees if the FIN was
// passed on -- and only THEN sends a large response, a little later. ottergate
// returns when the first direction finishes and tears both down, so this
// response never arrives there.
func TestTheResponseAfterAHalfCloseArrivesWhole(t *testing.T) {
	s := startSplice(t, context.Background(), time.Minute)
	defer s.close()
	req := []byte("GET / HTTP/1.0\r\n\r\n")
	resp := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB

	if _, err := s.workload.Write(req); err != nil {
		t.Fatal(err)
	}
	if err := s.workload.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		got, err := io.ReadAll(s.server)
		if err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(got, req) {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		time.Sleep(50 * time.Millisecond)
		_, err = s.server.Write(resp)
		_ = s.server.CloseWrite()
		serverDone <- err
	}()
	got, err := io.ReadAll(s.workload)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
	if !bytes.Equal(got, resp) {
		t.Fatalf("the workload got %d bytes of a %d-byte response", len(got), len(resp))
	}
	r := s.wait(t, 5*time.Second)
	if r.Out != int64(len(req)) || r.In != int64(len(resp)) || r.Err != nil || r.Idle {
		t.Fatalf("result = %+v, want out %d, in %d, no error", r, len(req), len(resp))
	}
}

// THE SPLICE PRESERVES BYTES IN BOTH DIRECTIONS, under random chunking on
// both sides and every order of the two half-closes: the server may answer
// before, during or after the workload finishes sending, and either side may
// shut down first.
func TestTheSplicePreservesBytesUnderRandomChunkingAndHalfCloses(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		up := rapid.SliceOfN(rapid.Byte(), 0, 64<<10).Draw(t, "up")
		down := rapid.SliceOfN(rapid.Byte(), 0, 64<<10).Draw(t, "down")
		upChunks := rapid.SliceOfN(rapid.IntRange(1, 9000), 1, 8).Draw(t, "up-chunks")
		downChunks := rapid.SliceOfN(rapid.IntRange(1, 9000), 1, 8).Draw(t, "down-chunks")
		// Whether the server waits for the workload's EOF before answering,
		// and how long each side dawdles before shutting its write side.
		serverWaits := rapid.Bool().Draw(t, "server-waits-for-eof")
		workloadDelay := time.Duration(rapid.IntRange(0, 5).Draw(t, "workload-delay-ms")) * time.Millisecond
		serverDelay := time.Duration(rapid.IntRange(0, 5).Draw(t, "server-delay-ms")) * time.Millisecond

		s := startSplice(t, context.Background(), time.Minute)
		defer s.close()

		type read struct {
			b   []byte
			err error
		}
		atWorkload, atServer := make(chan read, 1), make(chan read, 1)
		serverSawEOF := make(chan struct{})
		go func() {
			b, err := io.ReadAll(s.server)
			close(serverSawEOF)
			atServer <- read{b, err}
		}()
		go func() {
			b, err := io.ReadAll(s.workload)
			atWorkload <- read{b, err}
		}()
		go func() {
			if serverWaits {
				<-serverSawEOF
			}
			_ = writeChunks(s.server, down, downChunks)
			time.Sleep(serverDelay)
			_ = s.server.CloseWrite()
		}()
		if err := writeChunks(s.workload, up, upChunks); err != nil {
			t.Fatalf("workload write: %v", err)
		}
		time.Sleep(workloadDelay)
		if err := s.workload.CloseWrite(); err != nil {
			t.Fatalf("workload CloseWrite: %v", err)
		}

		gotUp, gotDown := <-atServer, <-atWorkload
		if gotUp.err != nil || gotDown.err != nil {
			t.Fatalf("read errors: server %v, workload %v", gotUp.err, gotDown.err)
		}
		if !bytes.Equal(gotUp.b, up) {
			t.Fatalf("upstream got %d bytes, want %d, and they differ", len(gotUp.b), len(up))
		}
		if !bytes.Equal(gotDown.b, down) {
			t.Fatalf("workload got %d bytes, want %d, and they differ", len(gotDown.b), len(down))
		}
		r := s.wait(t, 5*time.Second)
		if r.Out != int64(len(up)) || r.In != int64(len(down)) {
			t.Fatalf("counted out %d in %d, moved %d and %d", r.Out, r.In, len(up), len(down))
		}
	})
}

// IDLE, NOT ABSOLUTE. A stream that trickles a byte at a time for several
// times the idle limit lives, because every byte is activity; ottergate's
// fixed deadline would have killed it at the limit.
func TestASlowStreamOutlivesTheIdleLimit(t *testing.T) {
	const idle = 300 * time.Millisecond
	s := startSplice(t, context.Background(), idle)
	defer s.close()
	go func() {
		for i := range 12 {
			_, _ = s.server.Write([]byte{byte('a' + i)})
			time.Sleep(idle / 3)
		}
		_ = s.server.CloseWrite()
	}()
	_ = s.workload.CloseWrite()
	got, err := io.ReadAll(s.workload)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcdefghijkl" {
		t.Fatalf("the workload got %q", got)
	}
	if r := s.wait(t, 5*time.Second); r.Idle || r.Err != nil {
		t.Fatalf("a stream that was never idle for %v ended as %+v", idle, r)
	}
}

// And a connection on which nothing moves at all is closed after about the
// idle limit, and says so.
func TestASilentConnectionIsClosedForIdleness(t *testing.T) {
	const idle = 200 * time.Millisecond
	s := startSplice(t, context.Background(), idle)
	defer s.close()
	start := time.Now()
	r := s.wait(t, 5*time.Second)
	if !r.Idle {
		t.Fatalf("result = %+v, want idle", r)
	}
	if el := time.Since(start); el < idle {
		t.Fatalf("closed for idleness after %v, before the %v limit", el, idle)
	}
}

// A client that stops reading is not activity: the upstream fills the
// buffers, the counters stop, and the connection is reaped instead of holding
// a host descriptor forever. A per-read deadline would never notice -- the
// splice is blocked writing, not reading.
func TestAStalledReaderIsReaped(t *testing.T) {
	const idle = 300 * time.Millisecond
	s := startSplice(t, context.Background(), idle)
	defer s.close()
	go func() {
		chunk := make([]byte, 64<<10)
		for {
			if _, err := s.server.Write(chunk); err != nil {
				return
			}
		}
	}()
	r := s.wait(t, 10*time.Second)
	if !r.Idle {
		t.Fatalf("result = %+v, want idle", r)
	}
	if r.In == 0 {
		t.Fatalf("nothing was forwarded before the stall: %+v", r)
	}
}

func TestCancellingTheContextEndsTheSplice(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := startSplice(t, ctx, time.Minute)
	defer s.close()
	cancel()
	if r := s.wait(t, 5*time.Second); r.Err == nil {
		t.Fatalf("result = %+v, want the context's error", r)
	}
}
