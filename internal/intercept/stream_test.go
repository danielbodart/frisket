package intercept

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/steer"
)

const execBody = `{"Detach":false,"Tty":false}`

// switching answers a Docker request that asks to switch to tcp as the
// daemon does, with 101 UPGRADED, and then gives the connection to run;
// everything else it leaves to the fake daemon.
func switching(run func(conn net.Conn, in *bufio.Reader)) func(http.ResponseWriter, *http.Request) bool {
	return func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Upgrade") == "" {
			return false
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return true
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\n" +
			"Connection: Upgrade\r\nUpgrade: tcp\r\nApi-Version: 1.57\r\n\r\n")
		if brw.Flush() != nil {
			return true
		}
		run(conn, brw.Reader)
		return true
	}
}

// upgradeRequest is an exec's start, or an attach, as the Docker CLI sends
// it, asking to switch to tcp.
func upgradeRequest(path, body string) string {
	req := "POST " + path + " HTTP/1.1\r\nHost: " + dockerHost + "\r\nUser-Agent: Docker-Client/29.8.0 (linux)\r\n" +
		"Connection: Upgrade\r\nUpgrade: tcp\r\n"
	if body != "" {
		req += fmt.Sprintf("Content-Type: application/json\r\nContent-Length: %d\r\n", len(body))
	}
	return req + "\r\n" + body
}

// switched dials frisket as the CLI does, offering the protocols given,
// sends the request, and says what came back, with the stream after it.
func switched(t *testing.T, addr string, f *fixture, alpn []string, request string) (*tls.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: f.roots(), ServerName: dockerHost, NextProtos: alpn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if got := conn.ConnectionState().NegotiatedProtocol; len(alpn) > 0 && got != "http/1.1" || len(alpn) == 0 && got != "" {
		t.Fatalf("offered %q, negotiated %q", alpn, got)
	}
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn, br, res
}

func alpns(t *testing.T, fn func(t *testing.T, alpn []string)) {
	t.Run("http/1.1", func(t *testing.T) { fn(t, []string{"http/1.1"}) })
	t.Run("no ALPN", func(t *testing.T) { fn(t, nil) })
}

// A client that has sent all its stdin and closed its write side still
// receives everything the exec says afterwards, and the daemon is told the
// input is over, which is what lets it finish: the direction the client
// finished is closed, and the other is still carried.
func TestAnExecsOutputArrivesAfterItsClientHasFinishedSending(t *testing.T) {
	for _, tc := range []struct{ name, path, body string }{
		{"exec start", "/v1.55/exec/" + execID + "/start", execBody},
		{"attach", "/v1.55/containers/shop-db-1/attach?stream=1&stdin=1&stdout=1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alpns(t, func(t *testing.T, alpn []string) {
				f, d, j := dockerFixture(t)
				d.container(containerID, "shop-db-1", dockerProject)
				d.exec(execID, containerID)
				d.answer(switching(func(conn net.Conn, in *bufio.Reader) {
					stdin, err := io.ReadAll(in)
					if err != nil {
						return
					}
					// Only now, after the client's input is over, is there
					// anything to say.
					_, _ = fmt.Fprintf(conn, "read %q\n", stdin)
					time.Sleep(20 * time.Millisecond)
					_, _ = io.WriteString(conn, "and exited\n")
				}))

				conn, br, res := switched(t, f.addr, f, alpn, upgradeRequest(tc.path, tc.body))
				if res.StatusCode != http.StatusSwitchingProtocols || res.Header.Get("Upgrade") != "tcp" {
					t.Fatalf("status %d, headers %v", res.StatusCode, res.Header)
				}
				if v := res.Header.Get("Api-Version"); v != "1.56" {
					t.Fatalf("Api-Version %q on the switch, want the route's 1.56", v)
				}
				stdin := "SELECT 1;\n"
				if _, err := io.WriteString(conn, stdin); err != nil {
					t.Fatal(err)
				}
				if err := conn.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				out, err := io.ReadAll(br)
				if err != nil {
					t.Fatalf("after %q: %v", out, err)
				}
				want := fmt.Sprintf("read %q\nand exited\n", stdin)
				if string(out) != want {
					t.Fatalf("output %q, want %q", out, want)
				}

				seen := d.requests()
				if len(seen) != 1 || seen[0].header.Get("Upgrade") != "tcp" || seen[0].header.Get("Connection") != "Upgrade" ||
					seen[0].host != "docker" || !strings.Contains(seen[0].path, containerID+"/attach") && !strings.Contains(seen[0].path, execID) {
					t.Fatalf("the daemon saw %+v", seen)
				}
				line := j.waitLines(t, "request", 1)[0]
				if line["status"] != float64(http.StatusSwitchingProtocols) || line["decision"] != DecisionAllowed {
					t.Fatalf("logged %v", line)
				}
				if line["req_bytes"] != float64(len(tc.body)+len(stdin)) || line["resp_bytes"] != float64(len(want)) {
					t.Fatalf("bytes: logged %v, want %d in and %d out", line, len(tc.body)+len(stdin), len(want))
				}
			})
		})
	}
}

// Stdin the client sends straight after its request, before the switch is
// answered, is not lost in frisket's buffer: it reaches the daemon first.
func TestStdinSentWithTheRequestReachesTheDaemon(t *testing.T) {
	f, d, j := dockerFixture(t)
	d.container(containerID, "shop-db-1", dockerProject)
	d.exec(execID, containerID)
	d.answer(switching(func(conn net.Conn, in *bufio.Reader) {
		stdin, _ := io.ReadAll(in)
		_, _ = conn.Write(bytes.ToUpper(stdin))
	}))
	conn, br, res := switched(t, f.addr, f, []string{"http/1.1"},
		upgradeRequest("/v1.55/exec/"+execID+"/start", execBody)+"early stdin\n")
	if res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", res.StatusCode)
	}
	if _, err := io.WriteString(conn, "late stdin\n"); err != nil {
		t.Fatal(err)
	}
	_ = conn.CloseWrite()
	out, err := io.ReadAll(br)
	if err != nil || string(out) != "EARLY STDIN\nLATE STDIN\n" {
		t.Fatalf("output %q, %v", out, err)
	}
	line := j.waitLines(t, "request", 1)[0]
	if line["req_bytes"] != float64(len(execBody)+len("early stdin\nlate stdin\n")) {
		t.Fatalf("logged %v", line)
	}
}

// An exec that finishes before its client has closed its input delivers
// every byte it wrote, and then the client reads the end of it; the stream
// is over when the client, told so, closes.
func TestAnExecThatFinishesFirstDeliversAllItsOutput(t *testing.T) {
	alpns(t, func(t *testing.T, alpn []string) {
		f, d, j := dockerFixture(t)
		d.container(containerID, "shop-db-1", dockerProject)
		d.exec(execID, containerID)
		output := bytes.Repeat([]byte("0123456789abcdef"), 1<<16)
		d.answer(switching(func(conn net.Conn, _ *bufio.Reader) {
			_, _ = conn.Write(output)
		}))

		conn, br, res := switched(t, f.addr, f, alpn, upgradeRequest("/v1.55/exec/"+execID+"/start", execBody))
		if res.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("status %d", res.StatusCode)
		}
		out, err := io.ReadAll(br)
		if err != nil {
			t.Fatalf("after %d bytes: %v", len(out), err)
		}
		if !bytes.Equal(out, output) {
			t.Fatalf("received %d bytes, want the %d written", len(out), len(output))
		}
		_ = conn.Close()
		line := j.waitLines(t, "request", 1)[0]
		if line["status"] != float64(http.StatusSwitchingProtocols) || line["resp_bytes"] != float64(len(output)) {
			t.Fatalf("logged %v", line)
		}
	})
}

// A daemon that answers an upgrade without switching -- an exec that is not
// running, say -- is answered as it said, as an ordinary response.
func TestAnUpgradeAnsweredWithoutASwitchIsPassedThrough(t *testing.T) {
	alpns(t, func(t *testing.T, alpn []string) {
		f, d, j := dockerFixture(t)
		d.container(containerID, "shop-db-1", dockerProject)
		d.exec(execID, containerID)
		d.answer(func(w http.ResponseWriter, r *http.Request) bool {
			if r.Header.Get("Upgrade") == "" {
				return false
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Api-Version", "1.57")
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"message":"container is not running"}`)
			return true
		})
		_, _, res := switched(t, f.addr, f, alpn, upgradeRequest("/v1.55/exec/"+execID+"/start", execBody))
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusConflict || string(body) != `{"message":"container is not running"}` {
			t.Fatalf("status %d, body %q", res.StatusCode, body)
		}
		if res.Header.Get("Api-Version") != "1.56" || res.Header.Get("Upgrade") != "" {
			t.Fatalf("headers %v", res.Header)
		}
		line := j.waitLines(t, "request", 1)[0]
		if line["status"] != float64(http.StatusConflict) || line["decision"] != DecisionAllowed {
			t.Fatalf("logged %v", line)
		}
	})
}

// An upgraded stream is the session's: when the session ends, the stream
// ends with it, both ways, and its line is written.
func TestASessionsEndEndsAStreamInFlight(t *testing.T) {
	d := newDaemon(t)
	d.container(containerID, "shop-db-1", dockerProject)
	d.exec(execID, containerID)
	testOver := make(chan struct{})
	t.Cleanup(func() { close(testOver) })
	d.answer(switching(func(conn net.Conn, in *bufio.Reader) {
		// An exec that answers each line, then, once its stdin ends, keeps
		// its end open without writing, as `sleep infinity` or a quiet
		// attach would, so only the session's end can finish the stream.
		for {
			line, err := in.ReadString('\n')
			if err != nil {
				break
			}
			if _, err := io.WriteString(conn, strings.ToUpper(line)); err != nil {
				return
			}
		}
		<-testOver
	}))

	j := &journal{}
	routes := []Route{newUnixUpstream(t, d.socket)}
	ca, err := NewCA([]string{dockerHost})
	if err != nil {
		t.Fatal(err)
	}
	ic, err := New(Config{Routes: routes, Log: slog.New(slog.NewJSONHandler(j, nil)), Policy: "test-policy"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ic.Close() })
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	sess := steer.New("sess-test", j)
	sess.Dst = func(*net.TCPConn) netip.AddrPort { return serviceAddr443 }
	ctx, endSession := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = sess.Serve(ctx, ln, ic.For(ca, "/work/test"))
	}()
	t.Cleanup(func() { endSession(); <-served })
	f := &fixture{ca: ca, journal: j, ic: ic}

	conn, br, res := switched(t, ln.Addr().String(), f, []string{"http/1.1"}, upgradeRequest("/v1.55/exec/"+execID+"/start", execBody))
	if res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", res.StatusCode)
	}
	if _, err := io.WriteString(conn, "still here\n"); err != nil {
		t.Fatal(err)
	}
	if echo, err := br.ReadString('\n'); err != nil || echo != "STILL HERE\n" {
		t.Fatalf("echo %q, %v", echo, err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// The half-close alone must not finish the stream: the daemon is still
	// there, and could still write.
	time.Sleep(100 * time.Millisecond)
	if got := j.lines(t, "request"); len(got) != 0 {
		t.Fatalf("the stream finished before the session did: %v", got)
	}

	endSession()
	if _, err := br.ReadString('\n'); err == nil {
		t.Fatal("the client's side of the stream outlived the session")
	} else if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		t.Fatalf("the client's side was never closed: %v", err)
	}
	// The daemon never ends its side, so the stream can only have finished,
	// and been logged, because the session ended.
	line := j.waitLines(t, "request", 1)[0]
	if line["status"] != float64(http.StatusSwitchingProtocols) || line["req_bytes"] != float64(len(execBody)+len("still here\n")) {
		t.Fatalf("logged %v", line)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
