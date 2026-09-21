// Package control is the wire between root's half of frisket and the daemon's:
// `frisket steer` creates a session's listeners inside a sandbox and hands them
// over here; `frisket serve` receives them and holds them.
//
// THE DESCRIPTORS CROSS TWO BOUNDARIES. setns(CLONE_NEWNET) needs CAP_SYS_ADMIN
// in the user namespace that owns the target AND in the caller's own, so the
// daemon -- which is not root, and runs as the user whose credentials it holds
// -- can never create a sandbox's listeners itself, not even for a namespace it
// owns. Root's helper makes them; this socket is how they reach the daemon. It
// is root-only, and it is never bound into a sandbox.
//
// One request per connection, one datagram each way. SOCK_SEQPACKET rather
// than a stream, so a request and the descriptors that ride on it arrive as one
// message or not at all: there is no framing to get wrong and no way for a
// descriptor to arrive attached to half of a request.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/danielbodart/frisket/internal/nsnet"
	"golang.org/x/sys/unix"
)

// Network is the socket type on both ends.
const Network = "unixpacket"

// DefaultPath is where the daemon's control socket lives. The NixOS module
// creates it through a socket unit, root-owned and 0600.
const DefaultPath = "/run/frisket/control.sock"

// The operations.
const (
	OpOpen  = "open"  // create a session, with its listeners attached
	OpClose = "close" // close a session and every descriptor it holds
	OpList  = "list"  // what the daemon holds, for connect's precondition and for people
)

// The steering sets. See PLAN.md, "Steering sets".
const (
	SetAll     = "all"
	SetService = "service"
)

// MaxDescriptors is the most a request may carry. A session is four listeners;
// the slack is for nothing, and anything beyond it is refused rather than
// silently truncated -- a truncated SCM_RIGHTS closes descriptors the sender
// believes were delivered.
const MaxDescriptors = 8

// maxMessage bounds a request. Parameters are a handful of short strings.
const maxMessage = 64 << 10

// Session is everything a session is, fixed at creation by root. AUTHORISATION
// IS BY LISTENER (PLAN.md decision 8): which socket a connection arrived on is
// which session it came from, and this record is what that socket means.
type Session struct {
	// Name is the session's id everywhere: in every log line, in the fd store
	// (FDNAME), and in the close that ends it. flong's machine name, in
	// practice, which is unique per session.
	Name string `json:"name"`
	// Policy is the path of the policy document the daemon serves the
	// session under: read when the session is opened, and read again when it
	// is restored, so a session restored after the document changed is
	// served under what it says now.
	Policy string `json:"policy"`
	// Params are the policy's parameters -- the workspace, for one.
	Params map[string]string `json:"params,omitempty"`
	// Set is the steering set the rules were built from.
	Set string `json:"set"`
	// Service is frisket's service address, one per family. A connection
	// whose original destination is one of these is for frisket itself.
	Service []netip.Addr `json:"service"`
	// Mark is the firewall mark the session's ruleset puts on everything it
	// steers. A datagram is served only if it carries it.
	Mark uint32 `json:"mark"`
	// Listeners are the specs, in descriptor order.
	Listeners []string `json:"listeners"`
	// Netns is the namespace as the helper saw it after its setns,
	// "net:[4026533500]" -- what connect checks it is talking about.
	Netns string `json:"netns"`
}

// Request is one message to the daemon.
type Request struct {
	Op      string   `json:"op"`
	Session *Session `json:"session,omitempty"` // OpOpen
	Name    string   `json:"name,omitempty"`    // OpClose
}

// Status is one session as the daemon holds it.
type Status struct {
	Session
	// Descriptors is how many the daemon holds for it right now: listeners,
	// live connections and the metadata record. Every one of them in the
	// sandbox's namespace pins it.
	Descriptors int `json:"descriptors"`
	// Restored is true for a session adopted from systemd's fd store at
	// start, rather than opened by this process.
	Restored bool `json:"restored"`
}

// Response is the daemon's answer.
type Response struct {
	Error    string   `json:"error,omitempty"`
	Closed   bool     `json:"closed,omitempty"` // OpClose: false means there was nothing to close
	Sessions []Status `json:"sessions,omitempty"`
	// CACert is the session's CA certificate, PEM (OpOpen): what root puts in
	// the sandbox for it to trust. Public; the key never leaves the daemon.
	CACert []byte `json:"caCert,omitempty"`
}

// ValidName refuses a name that cannot be an fd store name or a log field:
// systemd refuses ':' and control characters in FDNAME, and a name is also a
// path component nowhere and a shell word everywhere, so it is kept to a
// boring alphabet rather than to what happens to work today.
func ValidName(s string) error {
	if s == "" || len(s) > 64 {
		return fmt.Errorf("name %q: want 1 to 64 characters", s)
	}
	for i, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			(i > 0 && (r == '-' || r == '_' || r == '.'))
		if !ok {
			return fmt.Errorf("name %q: want letters, digits, and -_. after the first character", s)
		}
	}
	return nil
}

// maxPolicyPath bounds a policy's path, well inside a request.
const maxPolicyPath = 1024

// ValidPolicyPath refuses a policy path that is not absolute and clean, or
// carries anything that is not an ordinary printable character. It is a log
// field as well as a path, and only root ever sends one.
func ValidPolicyPath(p string) error {
	if p == "" || len(p) > maxPolicyPath || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("policy %q: want an absolute, clean path", p)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("policy %q: a control character", p)
		}
	}
	return nil
}

// Validate refuses a session the daemon could not hold as described.
func (s *Session) Validate() error {
	if err := ValidName(s.Name); err != nil {
		return fmt.Errorf("session %w", err)
	}
	if err := ValidPolicyPath(s.Policy); err != nil {
		return fmt.Errorf("session %s: %w", s.Name, err)
	}
	if s.Set != SetAll && s.Set != SetService {
		return fmt.Errorf("session %s: set %q is neither %q nor %q", s.Name, s.Set, SetAll, SetService)
	}
	if len(s.Listeners) == 0 || len(s.Listeners) > MaxDescriptors {
		return fmt.Errorf("session %s: %d listeners", s.Name, len(s.Listeners))
	}
	for _, l := range s.Listeners {
		if _, err := nsnet.ParseSpec(l); err != nil {
			return fmt.Errorf("session %s: %w", s.Name, err)
		}
	}
	// Zero is what every unmarked packet carries: a session with no mark
	// would refuse every datagram, and says so here instead.
	if s.Mark == 0 {
		return fmt.Errorf("session %s: no firewall mark", s.Name)
	}
	// The dispatch rule compares original destinations against these, so an
	// address that is not one would make "is this for frisket?" answer no for
	// everything -- and interception silently becomes egress.
	if len(s.Service) == 0 {
		return fmt.Errorf("session %s: no service address", s.Name)
	}
	for _, a := range s.Service {
		if !a.IsValid() || a.IsUnspecified() || a.Zone() != "" {
			return fmt.Errorf("session %s: service address %v", s.Name, a)
		}
	}
	return nil
}

// Call sends one request, with files riding on it, and returns the daemon's
// answer. A Response carrying an Error is returned as an error too, so a
// caller cannot mistake a refusal for a success by forgetting to look.
func Call(ctx context.Context, path string, req Request, files []*os.File) (Response, error) {
	if len(files) > MaxDescriptors {
		return Response{}, fmt.Errorf("%d descriptors is more than a request carries", len(files))
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, Network, path)
	if err != nil {
		return Response{}, fmt.Errorf("connecting to frisket at %s: %w", path, err)
	}
	defer c.Close()
	uc := c.(*net.UnixConn)
	if dl, ok := ctx.Deadline(); ok {
		_ = uc.SetDeadline(dl)
	} else {
		_ = uc.SetDeadline(time.Now().Add(30 * time.Second))
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	fds := make([]int, len(files))
	for i, f := range files {
		fds[i] = int(f.Fd())
	}
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	if _, _, err := uc.WriteMsgUnix(payload, oob, nil); err != nil {
		return Response{}, fmt.Errorf("sending %s to frisket: %w", req.Op, err)
	}

	buf := make([]byte, maxMessage)
	n, err := uc.Read(buf)
	if err != nil {
		return Response{}, fmt.Errorf("reading frisket's answer to %s: %w", req.Op, err)
	}
	var resp Response
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		return Response{}, fmt.Errorf("frisket's answer to %s: %w", req.Op, err)
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// ReadRequest reads one request and whatever descriptors came with it. The
// descriptors arrive close-on-exec, from the kernel, so there is no window in
// which a process forked by another goroutine could inherit a listener -- and
// with it a pin on a sandbox's namespace in a process nothing here can see.
//
// Anything malformed closes every descriptor that arrived: a descriptor that
// nobody took ownership of is a namespace pinned for the daemon's lifetime.
func ReadRequest(uc *net.UnixConn) (Request, []*os.File, error) {
	rc, err := uc.SyscallConn()
	if err != nil {
		return Request{}, nil, err
	}
	buf := make([]byte, maxMessage)
	oob := make([]byte, unix.CmsgSpace(4*MaxDescriptors))
	var n, oobn, flags int
	var recvErr error
	if err := rc.Read(func(fd uintptr) bool {
		n, oobn, flags, _, recvErr = unix.Recvmsg(int(fd), buf, oob, unix.MSG_CMSG_CLOEXEC)
		return recvErr != unix.EAGAIN
	}); err != nil {
		return Request{}, nil, err
	}
	if recvErr != nil {
		return Request{}, nil, recvErr
	}

	var fds []int
	if oobn > 0 {
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return Request{}, nil, fmt.Errorf("control message: %w", err)
		}
		for _, m := range msgs {
			got, err := unix.ParseUnixRights(&m)
			if err != nil {
				continue // credentials or anything else: not ours to keep
			}
			fds = append(fds, got...)
		}
	}
	files := make([]*os.File, len(fds))
	for i, fd := range fds {
		files[i] = os.NewFile(uintptr(fd), fmt.Sprintf("received-%d", i))
	}
	fail := func(err error) (Request, []*os.File, error) {
		CloseAll(files)
		return Request{}, nil, err
	}

	// Truncation is refused, not tolerated. A truncated control message has
	// already closed the descriptors that did not fit, so the request no
	// longer describes what arrived.
	if flags&unix.MSG_CTRUNC != 0 {
		return fail(fmt.Errorf("more than %d descriptors on one request", MaxDescriptors))
	}
	if flags&unix.MSG_TRUNC != 0 {
		return fail(fmt.Errorf("request larger than %d bytes", maxMessage))
	}
	var req Request
	if err := json.Unmarshal(buf[:n], &req); err != nil {
		return fail(fmt.Errorf("request: %w", err))
	}
	return req, files, nil
}

// WriteResponse answers the request read from uc.
func WriteResponse(uc *net.UnixConn, resp Response) error {
	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = uc.Write(b)
	return err
}

// CloseAll closes every file that is not nil. For the paths where ownership
// was never taken.
func CloseAll(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}
