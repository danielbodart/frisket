package galleyask

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"runtime/debug"
	"strings"
	"unicode"

	"github.com/danielbodart/frisket/internal/peer"
	"golang.org/x/sys/unix"
)

const maxArg = 1000

// Name is the program a link runs, by its argv0, since comm is cut at 15
// characters and a wrapped program's comm is its wrapper's.
func Name(l peer.Link) string {
	if len(l.Cmdline) > 0 && l.Cmdline[0] != "" {
		return Clean(filepath.Base(l.Cmdline[0]))
	}
	return Clean(l.Comm)
}

// Warnings are the lines that open a question for a Cut or SessionRoot
// chain.
func Warnings(r *peer.Requester) []string {
	var lines []string
	if r.SessionRoot {
		lines = append(lines, "launched through "+sessionRoot(r.Anchor))
	}
	if r.Cut {
		lines = append(lines, "the process chain was cut short")
	}
	return lines
}

func sessionRoot(a *peer.Link) string {
	switch {
	case a.Pid == 1:
		return "pid 1"
	case a.Comm == ".kgx-wrapped":
		return "the terminal server"
	}
	return "systemd --user"
}

// Clean cuts s at maxArg characters and escapes control, bidi and line
// separator characters.
func Clean(s string) string {
	if r := []rune(s); len(r) > maxArg {
		s = string(r[:maxArg])
	}
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Bidi_Control, unicode.Zl, unicode.Zp) {
			fmt.Fprintf(&b, `\u%04x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// WatchHangUp calls hungUp if c's peer hangs up before stop is called.
func WatchHangUp(c *net.UnixConn, log *slog.Logger, hungUp func()) (stop func(), err error) {
	efd, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	watching := make(chan struct{})
	go func() {
		defer close(watching)
		defer func() {
			if p := recover(); p != nil {
				log.Error("request panicked", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			}
		}()
		if pollHangUp(c, efd) {
			hungUp()
		}
	}()
	return func() {
		_, _ = unix.Write(efd, binary.NativeEndian.AppendUint64(nil, 1))
		<-watching
		unix.Close(efd)
	}, nil
}

func pollHangUp(c *net.UnixConn, stop int) (hungUp bool) {
	rc, err := c.SyscallConn()
	if err != nil {
		return false
	}
	_ = rc.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLRDHUP}, {Fd: int32(stop), Events: unix.POLLIN}}
		for {
			if _, err := unix.Poll(fds, -1); err != unix.EINTR {
				break
			}
		}
		hungUp = fds[0].Revents != 0
	})
	return hungUp
}
