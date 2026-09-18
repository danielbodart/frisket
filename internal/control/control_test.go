package control

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"pgregory.net/rapid"
)

// serveOnce listens on a fresh socket and hands the first request to handle.
func serveOnce(t *testing.T, handle func(Request, []*os.File) Response) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.sock")
	ln, err := net.ListenUnix(Network, &net.UnixAddr{Name: path, Net: Network})
	if err != nil {
		t.Skipf("cannot listen on a seqpacket socket here: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		defer c.Close()
		req, files, err := ReadRequest(c)
		if err != nil {
			_ = WriteResponse(c, Response{Error: err.Error()})
			return
		}
		_ = WriteResponse(c, handle(req, files))
	}()
	return path
}

func countFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	return len(ents)
}

// The descriptors arrive, they are the same open files that were sent, and
// they arrive close-on-exec -- set by the kernel, not by us afterwards, so no
// fork in between can inherit a sandbox's listener.
func TestDescriptorsCrossTheSocketCloseOnExec(t *testing.T) {
	got := make(chan []*os.File, 1)
	path := serveOnce(t, func(req Request, files []*os.File) Response {
		got <- files
		return Response{Closed: req.Op == OpClose}
	})

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	resp, err := Call(context.Background(), path, Request{Op: OpClose, Name: "x"}, []*os.File{w})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Closed {
		t.Errorf("response = %+v", resp)
	}
	files := <-got
	if len(files) != 1 {
		t.Fatalf("received %d descriptors, sent 1", len(files))
	}
	defer files[0].Close()
	flags, err := unix.FcntlInt(files[0].Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Error("a received descriptor is inheritable; a fork would take the sandbox's listener with it")
	}
	if _, err := files[0].WriteString("same-file"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = r.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := r.Read(buf)
	if string(buf[:n]) != "same-file" {
		t.Errorf("read %q through the received descriptor's pipe", buf[:n])
	}
}

// A refusal is an error to the caller, never a success it forgot to check.
func TestAnErrorResponseIsAnError(t *testing.T) {
	path := serveOnce(t, func(Request, []*os.File) Response { return Response{Error: "refused: because"} })
	if _, err := Call(context.Background(), path, Request{Op: OpList}, nil); err == nil || !strings.Contains(err.Error(), "because") {
		t.Errorf("err = %v, want the daemon's refusal", err)
	}
}

// More descriptors than a request may carry is refused, and everything that
// did arrive is closed rather than left open with nobody holding it.
func TestTooManyDescriptorsAreRefusedAndClosed(t *testing.T) {
	path := serveOnce(t, func(Request, []*os.File) Response { return Response{} })
	before := countFDs(t)

	var files []*os.File
	for range MaxDescriptors + 2 {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		files = append(files, r)
	}
	defer CloseAll(files)

	// Call itself refuses; go under it to see what the server does.
	c, err := net.DialUnix(Network, nil, &net.UnixAddr{Name: path, Net: Network})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fds := make([]int, len(files))
	for i, f := range files {
		fds[i] = int(f.Fd())
	}
	if _, _, err := c.WriteMsgUnix([]byte(`{"op":"list"}`), unix.UnixRights(fds...), nil); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buf[:n]), "descriptors") {
		t.Errorf("answer = %s, want a refusal naming the descriptors", buf[:n])
	}
	CloseAll(files)
	files = nil
	_ = c.Close()
	// The server's copies are gone too: nothing it received outlived the
	// refusal.
	deadline := time.Now().Add(5 * time.Second)
	for countFDs(t) > before+1 { // +1: the listener, still open until cleanup
		if time.Now().After(deadline) {
			t.Fatalf("%d descriptors open before, %d after a refused request", before, countFDs(t))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCallRefusesToSendTooMany(t *testing.T) {
	files := make([]*os.File, MaxDescriptors+1)
	if _, err := Call(context.Background(), "/nonexistent", Request{Op: OpList}, files); err == nil {
		t.Error("accepted more descriptors than a request carries")
	}
}

func validSession() Session {
	return Session{
		Name:      "netless-123-456",
		Policy:    "standin",
		Set:       SetAll,
		Service:   []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")},
		Listeners: []string{"tcp4:127.0.0.1:15001", "udp6:[::1]:15353"},
		Netns:     "net:[4026533500]",
	}
}

func TestValidateRefusesWhatCannotBeHeld(t *testing.T) {
	ok := validSession()
	if err := ok.Validate(); err != nil {
		t.Fatalf("a valid session was refused: %v", err)
	}
	for name, mutate := range map[string]func(*Session){
		"fd store name with a colon": func(s *Session) { s.Name = "a:b" },
		"empty name":                 func(s *Session) { s.Name = "" },
		"no policy":                  func(s *Session) { s.Policy = "" },
		"unknown set":                func(s *Session) { s.Set = "everything" },
		"no listeners":               func(s *Session) { s.Listeners = nil },
		"wildcard listener":          func(s *Session) { s.Listeners = []string{"tcp4:0.0.0.0:15001"} },
		"no service address":         func(s *Session) { s.Service = nil },
		"unspecified service":        func(s *Session) { s.Service = []netip.Addr{netip.IPv4Unspecified()} },
	} {
		s := validSession()
		mutate(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Every accepted name is one systemd will take as an FDNAME: no ':', no
// control characters, at most 255 bytes.
func TestValidNamesAreValidFDNames(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := rapid.String().Draw(t, "name")
		if ValidName(s) != nil {
			return
		}
		if strings.ContainsAny(s, ":\n\x00") || len(s) > 255 {
			t.Fatalf("%q was accepted and is not a valid FDNAME", s)
		}
		for _, r := range s {
			if r < 0x20 || r > 0x7e {
				t.Fatalf("%q was accepted with %q in it", s, r)
			}
		}
	})
}
