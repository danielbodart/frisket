package sdnotify

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeSystemd is a NOTIFY_SOCKET that records what it was sent.
type fakeSystemd struct {
	c *net.UnixConn
}

func newFakeSystemd(t *testing.T) (*fakeSystemd, *Notifier) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify")
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Skipf("no unixgram socket here: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &fakeSystemd{c: c}, New(path)
}

func (f *fakeSystemd) next(t *testing.T) (string, []*os.File) {
	t.Helper()
	buf := make([]byte, 4096)
	oob := make([]byte, unix.CmsgSpace(4*16))
	_ = f.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, oobn, _, _, err := f.c.ReadMsgUnix(buf, oob)
	if err != nil {
		t.Fatal(err)
	}
	var files []*os.File
	msgs, _ := unix.ParseSocketControlMessage(oob[:oobn])
	for _, m := range msgs {
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			files = append(files, os.NewFile(uintptr(fd), "stored"))
		}
	}
	return string(buf[:n]), files
}

// A session's descriptors and the name they are stored under travel in one
// datagram: there is no state in which PID 1 holds some of a session.
func TestStoreSendsEveryDescriptorWithItsNameInOneMessage(t *testing.T) {
	sd, n := newFakeSystemd(t)
	a, b, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()

	if err := n.Store("netless-1-2", a, b); err != nil {
		t.Fatal(err)
	}
	state, files := sd.next(t)
	for _, f := range files {
		defer f.Close()
	}
	if state != "FDSTORE=1\nFDNAME=netless-1-2" {
		t.Errorf("state = %q", state)
	}
	if len(files) != 2 {
		t.Errorf("stored %d descriptors, sent 2", len(files))
	}

	if err := n.Remove("netless-1-2"); err != nil {
		t.Fatal(err)
	}
	if state, files := sd.next(t); state != "FDSTOREREMOVE=1\nFDNAME=netless-1-2" || len(files) != 0 {
		t.Errorf("remove sent %q with %d descriptors", state, len(files))
	}
}

func TestANilNotifierSaysSoRatherThanPretending(t *testing.T) {
	var n *Notifier
	if err := n.Ready("x"); err == nil || !strings.Contains(err.Error(), "NOTIFY_SOCKET") {
		t.Errorf("err = %v", err)
	}
}

// Descriptors meant for another process are not adopted: LISTEN_PID is
// inherited by everything this process forks.
func TestListenIgnoresDescriptorsMeantForAnotherProcess(t *testing.T) {
	fds, err := parseListen("1", "2", "control:x", 999, 3)
	if err != nil || fds != nil {
		t.Errorf("adopted %v, %v for pid 1 while being pid 999", fds, err)
	}
	if fds, err := parseListen("", "", "", 999, 3); err != nil || fds != nil {
		t.Errorf("nothing passed, got %v, %v", fds, err)
	}
	if _, err := parseListen("999", "lots", "", 999, 3); err == nil {
		t.Error("a LISTEN_FDS that is not a count was accepted")
	}
}

// The names come back in order, and a descriptor systemd did not name is
// "unknown" rather than taking its neighbour's name.
func TestListenNamesEachDescriptor(t *testing.T) {
	// Real descriptors at a known place, or CloseOnExec would act on
	// whatever the test runtime has there.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	const start = 200
	for i, f := range []*os.File{r, w} {
		if err := unix.Dup3(int(f.Fd()), start+i, 0); err != nil {
			t.Skipf("cannot place a descriptor at %d: %v", start+i, err)
		}
	}
	fds, err := parseListen("999", "2", "control", 999, start)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, f := range fds {
			_ = f.File.Close()
		}
	}()
	if len(fds) != 2 || fds[0].Name != "control" || fds[1].Name != "unknown" {
		t.Fatalf("got %+v", fds)
	}
	flags, _ := unix.FcntlInt(uintptr(start), unix.F_GETFD, 0)
	if flags&unix.FD_CLOEXEC == 0 {
		t.Error("an inherited descriptor was left inheritable")
	}
}
