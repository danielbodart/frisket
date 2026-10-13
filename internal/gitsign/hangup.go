package gitsign

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"

	"golang.org/x/sys/unix"
)

// watchHangUp calls hungUp if c's peer hangs up before stop is called: a
// requester that gives up on a sign hangs up on the upstream too, so a sign
// the upstream is still asking someone about is withdrawn rather than left
// for nobody.
//
// It waits on poll with no timeout, for POLLRDHUP on c or for stop's
// eventfd, never reading c: the agent protocol's reader owns that.
func watchHangUp(c *net.UnixConn, log *slog.Logger, hungUp func()) (stop func(), err error) {
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
