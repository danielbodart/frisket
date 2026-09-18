package egress

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultIdle is how long a spliced connection may move no bytes at all, in
// either direction, before it is torn down. An IDLE limit, not a lifetime:
// ottergate sets an absolute 30-second deadline and never extends it, which
// kills every download, SSE stream and websocket at 30 seconds regardless of
// how busy it is. Generous, because a false positive breaks a working
// connection and the cost of a true one is a descriptor held a little longer,
// which the session's connection cap already bounds.
const DefaultIdle = 10 * time.Minute

// SpliceResult is what happened on a spliced connection, for its log line.
type SpliceResult struct {
	// Out is bytes from the workload to the upstream; In is bytes back.
	Out, In int64
	// Idle is set when the connection was torn down for moving nothing for
	// the whole idle period.
	Idle bool
	// Err is the first error that was not an orderly end: not EOF, and not the
	// deadline we set ourselves to tear it down.
	Err error
}

// aLongTimeAgo is a deadline already passed, which unblocks every pending
// read and write on a connection at once.
var aLongTimeAgo = time.Unix(1, 0)

// Splice copies client<->upstream until BOTH directions have finished,
// propagating each half-close as it happens.
//
// WAIT FOR BOTH. ottergate returns when the first direction ends and its
// deferred Close tears down the other, so a client that sends its request and
// shuts down its write side -- which is how a request says "that is all" --
// gets its response cut off. Here, EOF from one side becomes CloseWrite on the
// other (a FIN, not a close), and the other direction carries on until it ends
// too.
//
// THE RAW CONNECTIONS, so Linux splices. io.Copy between two *net.TCPConn goes
// through TCPConn.ReadFrom, which uses splice(2) and never copies the payload
// into userspace. Wrapping either side -- to count bytes, or to push a deadline
// forward on every read, the obvious way to get an idle timeout -- silently
// turns that off.
//
// So the idle timeout is a watchdog BESIDE the copy, not inside it. It samples
// the kernel's own TCP_INFO counters (bytes received, bytes the peer
// acknowledged) on both sockets, and only when none of them has moved for the
// whole idle period does it set a past deadline on both, which ends both
// copies at once. A per-copy read deadline cannot do this: a slow stream whose
// every byte arrives inside the deadline is still one long ReadFrom, and a
// write stalled on a client that stopped reading is not a read at all.
//
// idle <= 0 disables the watchdog; ctx still ends the splice. The caller owns
// both connections and closes them.
func Splice(ctx context.Context, client, upstream *net.TCPConn, idle time.Duration) SpliceResult {
	var res SpliceResult
	var errOut, errIn error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		res.Out, errOut = io.Copy(upstream, client)
		// An orderly end OR an error: either way nothing more will be sent
		// upstream, and saying so is what lets the upstream finish its answer.
		_ = upstream.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		res.In, errIn = io.Copy(client, upstream)
		_ = client.CloseWrite()
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	var forced bool
	var tick <-chan time.Time
	if idle > 0 {
		t := time.NewTicker(max(idle/4, time.Millisecond))
		defer t.Stop()
		tick = t.C
	}
	last, lastMoved := progress(client, upstream), time.Now()
wait:
	for {
		select {
		case <-done:
			break wait
		case <-ctx.Done():
			forced = true
			res.Err = ctx.Err()
			break wait
		case now := <-tick:
			if p := progress(client, upstream); p != last {
				last, lastMoved = p, now
			} else if now.Sub(lastMoved) >= idle {
				forced, res.Idle = true, true
				break wait
			}
		}
	}
	if forced {
		_ = client.SetDeadline(aLongTimeAgo)
		_ = upstream.SetDeadline(aLongTimeAgo)
	}
	<-done
	if !forced {
		// Only report copy errors from a connection we did not end ourselves;
		// ours all say "deadline exceeded", which is not news.
		if errOut != nil {
			res.Err = errOut
		} else if errIn != nil {
			res.Err = errIn
		}
	}
	return res
}

// progress is a number that changes whenever any byte moves on either socket,
// in either direction, according to the kernel. Monotonic per socket, so any
// change at all is activity. A socket whose counters cannot be read
// contributes nothing, which errs towards "idle" and so towards closing.
func progress(conns ...*net.TCPConn) uint64 {
	var sum uint64
	for _, c := range conns {
		rc, err := c.SyscallConn()
		if err != nil {
			continue
		}
		_ = rc.Control(func(fd uintptr) {
			info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
			if err == nil {
				sum += info.Bytes_received + info.Bytes_acked
			}
		})
	}
	return sum
}
