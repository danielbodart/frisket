// Package courier is frisket-policy's service: it carries a project's policy
// file between the user's home, which only the user's own processes may
// read and write, and the root-run verifiers (the signer and the sudo gate),
// which may not. It runs as the user, with no network, and answers only the
// system units it is told to.
//
// It is trusted for one thing, which project a process is in: an anchor's
// working directory, up to the nearest policy file. It cannot forge one, since
// every reader verifies the signature against root's allowed signers, and it
// writes only a file whose signature already verifies.
//
// The wire is one JSON request and one JSON response, a line each, per
// connection; bytes travel as base64, as encoding/json writes []byte.
package courier

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/danielbodart/frisket/internal/peer"
	"github.com/danielbodart/frisket/projpolicy"
	"golang.org/x/sys/unix"
)

// Request is one operation.
//
//	{"op": "read", "pid": P, "start": S}
//	{"op": "write", "root": R, "oldDigest": D, "bytes": B, "sig": G}
type Request struct {
	Op string `json:"op"`

	// read: the anchor, a process of the user's, and its start time from
	// /proc/<pid>/stat, so a reused pid is refused.
	Pid   int    `json:"pid,omitempty"`
	Start uint64 `json:"start,omitempty"`

	// write: the project's directory, the digest of the file the new one
	// replaces ("" for none), and the new file and its signature.
	Root      string `json:"root,omitempty"`
	OldDigest string `json:"oldDigest,omitempty"`
	Bytes     []byte `json:"bytes,omitempty"`
	Sig       []byte `json:"sig,omitempty"`
}

// Response answers a Request. Error is set alone when it failed. A read
// that found no policy file is a Response with no Root.
type Response struct {
	Error     string `json:"error,omitempty"`
	Root      string `json:"root,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Bytes     []byte `json:"bytes,omitempty"`
	Sig       []byte `json:"sig,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

const (
	OpRead  = "read"
	OpWrite = "write"

	maxRequest = 4 << 20
	deadline   = 10 * time.Second
)

// ErrChanged is a write whose oldDigest is not the file's: it changed since
// it was read, and the write is refused rather than lose that change.
var ErrChanged = errors.New("the policy file changed since it was read")

// Server answers the courier's socket.
type Server struct {
	Name string // the policy file's name, as the config's fileName
	Home string // the user's home: what Find is bounded at and namespaces are named from
	UID  int    // the user's uid, which every anchor must be

	// Signers reads the allowed signers afresh for each write.
	Signers func() (*projpolicy.AllowedSigners, error)
	// Peers maps each system unit served to its user's uid: a peer must be
	// that uid, in that unit's cgroup.
	Peers map[string]int
	Log   *slog.Logger

	who        func(*net.UnixConn) (*peer.Requester, error)
	unitCgroup func(unit string) (uint64, error)
}

func (s *Server) defaults() {
	if s.who == nil {
		s.who = peer.FromConn
	}
	if s.unitCgroup == nil {
		s.unitCgroup = func(unit string) (uint64, error) {
			var st unix.Stat_t
			if err := unix.Stat(filepath.Join("/sys/fs/cgroup/system.slice", unit), &st); err != nil {
				return 0, err
			}
			return st.Ino, nil
		}
	}
}

func (s *Server) Serve(ln *net.UnixListener) error {
	s.defaults()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return err
		}
		go s.serve(c)
	}
}

func (s *Server) serve(c *net.UnixConn) {
	defer c.Close()
	defer func() {
		if p := recover(); p != nil {
			s.Log.Error("connection panicked", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
		}
	}()
	_ = c.SetDeadline(time.Now().Add(deadline))
	unit, pid, err := s.checkPeer(c)
	if err != nil {
		s.Log.Warn("refused", "reason", err.Error())
		reply(c, Response{Error: "refused: " + err.Error()})
		return
	}
	var req Request
	dec := json.NewDecoder(bufio.NewReader(io.LimitReader(c, maxRequest)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.Log.Warn("refused", "peer", unit, "peer_pid", pid, "reason", "request: "+err.Error())
		reply(c, Response{Error: "request: " + err.Error()})
		return
	}
	var resp Response
	switch req.Op {
	case OpRead:
		resp, err = s.read(req)
		attrs := []any{"peer", unit, "peer_pid", pid, "pid", req.Pid, "start", req.Start, "root", resp.Root, "digest", resp.Digest}
		if err != nil {
			s.Log.Warn("read", append(attrs, "outcome", "refuse", "err", err.Error())...)
		} else {
			s.Log.Info("read", append(attrs, "outcome", "ok", "signed", resp.Sig != nil)...)
		}
	case OpWrite:
		resp, err = s.write(req)
		attrs := []any{"peer", unit, "peer_pid", pid, "root", req.Root, "old", req.OldDigest, "digest", projpolicy.Digest(req.Bytes)}
		if err != nil {
			s.Log.Warn("write", append(attrs, "outcome", "refuse", "err", err.Error())...)
		} else {
			s.Log.Info("write", append(attrs, "outcome", "written")...)
		}
	default:
		err = fmt.Errorf("unknown op %q", req.Op)
		s.Log.Warn("refused", "peer", unit, "peer_pid", pid, "reason", err.Error())
	}
	if err != nil {
		resp = Response{Error: err.Error()}
	}
	reply(c, resp)
}

func reply(c *net.UnixConn, r Response) {
	b, _ := json.Marshal(r)
	_, _ = c.Write(append(b, '\n'))
}

// checkPeer is the unit the peer runs in, which must be one served, as its
// user's uid: the uid alone would let any process of the signer's or the
// gate's user in, and the cgroup alone any user a unit could run as.
func (s *Server) checkPeer(c *net.UnixConn) (string, int, error) {
	r, err := s.who(c)
	if err != nil {
		return "", 0, err
	}
	pid := 0
	if len(r.Chain) > 0 {
		pid = r.Chain[0].Pid
	}
	if r.CgroupID == 0 {
		return "", pid, fmt.Errorf("peer pid %d's cgroup cannot be read", pid)
	}
	for unit, uid := range s.Peers {
		ino, err := s.unitCgroup(unit)
		if err != nil || ino != r.CgroupID {
			continue
		}
		if r.PeerUID != uid {
			return unit, pid, fmt.Errorf("peer pid %d in %s is uid %d, not %d", pid, unit, r.PeerUID, uid)
		}
		return unit, pid, nil
	}
	cg := ""
	if len(r.Chain) > 0 {
		cg = r.Chain[0].Cgroup
	}
	return "", pid, fmt.Errorf("peer pid %d (uid %d) is in %s, not a unit this courier serves", pid, r.PeerUID, cg)
}

// read is the policy file above the anchor's working directory.
func (s *Server) read(req Request) (Response, error) {
	dir := filepath.Join("/proc", strconv.Itoa(req.Pid))
	if req.Pid <= 0 || req.Start == 0 {
		return Response{}, errors.New("read needs the anchor's pid and start")
	}
	if !peer.Alive(req.Pid, req.Start) {
		return Response{}, fmt.Errorf("pid %d is not the process that started at %d", req.Pid, req.Start)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		return Response{}, err
	}
	if int(st.Uid) != s.UID {
		return Response{}, fmt.Errorf("pid %d is uid %d's, not %d's", req.Pid, st.Uid, s.UID)
	}
	if err := sameRoot(filepath.Join(dir, "root")); err != nil {
		return Response{}, fmt.Errorf("pid %d: %w", req.Pid, err)
	}
	cwd, err := os.Readlink(filepath.Join(dir, "cwd"))
	if err != nil {
		return Response{}, err
	}
	if !peer.Alive(req.Pid, req.Start) {
		return Response{}, fmt.Errorf("pid %d exited while it was read", req.Pid)
	}
	if strings.HasSuffix(cwd, " (deleted)") || !filepath.IsAbs(cwd) {
		return Response{}, fmt.Errorf("pid %d's working directory %q is gone", req.Pid, cwd)
	}
	root, err := projpolicy.Find(cwd, s.Home, s.Name)
	if errors.Is(err, projpolicy.ErrNotFound) {
		return Response{}, nil
	}
	if err != nil {
		return Response{}, err
	}
	ns, err := projpolicy.Namespace(root, s.Home)
	if err != nil {
		return Response{}, err
	}
	path := filepath.Join(root, s.Name)
	b, err := projpolicy.ReadFile(path)
	if err != nil {
		return Response{}, err
	}
	sig, err := projpolicy.ReadFile(path + projpolicy.SigSuffix)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Response{}, err
	}
	return Response{Root: root, Namespace: ns, Bytes: b, Sig: sig, Digest: projpolicy.Digest(b)}, nil
}

// sameRoot refuses a process whose root is not this one's: a sandbox's
// working directory is a path in its own tree, which here names something
// else, or nothing.
func sameRoot(path string) error {
	var theirs, ours syscall.Stat_t
	if err := syscall.Stat(path, &theirs); err != nil {
		return err
	}
	if err := syscall.Stat("/", &ours); err != nil {
		return err
	}
	if theirs.Dev != ours.Dev || theirs.Ino != ours.Ino {
		return errors.New("its root is not the host's: it is in a sandbox")
	}
	return nil
}

// write replaces the policy file at root and its signature, if the file is
// still the one oldDigest names, the new one is canonical and its signature
// verifies there. The json is renamed into place before the sig, both from
// temporary files beside them, under an exclusive flock on root.
func (s *Server) write(req Request) (Response, error) {
	root := req.Root
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return Response{}, fmt.Errorf("root %q is not absolute and clean", root)
	}
	if root != s.Home && !strings.HasPrefix(root, strings.TrimSuffix(s.Home, "/")+"/") {
		return Response{}, fmt.Errorf("root %s is not under %s", root, s.Home)
	}
	if req.Bytes == nil || req.Sig == nil {
		return Response{}, errors.New("write needs bytes and sig")
	}
	if !projpolicy.Canonical(req.Bytes) {
		return Response{}, errors.New("the new file is not canonical")
	}
	ns, err := projpolicy.Namespace(root, s.Home)
	if err != nil {
		return Response{}, err
	}
	signers, err := s.Signers()
	if err != nil {
		return Response{}, err
	}
	if _, err := projpolicy.Verify(req.Bytes, req.Sig, ns, signers, "", time.Now()); err != nil {
		return Response{}, fmt.Errorf("the new signature does not verify in %s: %w", ns, err)
	}

	d, err := os.OpenFile(root, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Response{}, err
	}
	defer d.Close()
	if err := unix.Flock(int(d.Fd()), unix.LOCK_EX); err != nil {
		return Response{}, fmt.Errorf("flock %s: %w", root, err)
	}
	path := filepath.Join(root, s.Name)
	cur, err := projpolicy.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Response{}, err
	}
	if errors.Is(err, fs.ErrNotExist) {
		cur = nil
	}
	if got := projpolicy.Digest(cur); got != req.OldDigest {
		return Response{}, fmt.Errorf("%w: it is %q, not %q", ErrChanged, got, req.OldDigest)
	}
	jsonTmp, err := temp(root, s.Name, req.Bytes)
	if err != nil {
		return Response{}, err
	}
	defer os.Remove(jsonTmp)
	sigTmp, err := temp(root, s.Name+projpolicy.SigSuffix, req.Sig)
	if err != nil {
		return Response{}, err
	}
	defer os.Remove(sigTmp)
	if err := os.Rename(jsonTmp, path); err != nil {
		return Response{}, err
	}
	if err := os.Rename(sigTmp, path+projpolicy.SigSuffix); err != nil {
		return Response{}, err
	}
	if err := d.Sync(); err != nil {
		return Response{}, err
	}
	return Response{Root: root, Namespace: ns, Digest: projpolicy.Digest(req.Bytes)}, nil
}

func temp(dir, name string, b []byte) (string, error) {
	f, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return "", err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// Call sends one request to the courier at socket and returns its answer;
// a Response with Error set is returned as an error.
func Call(ctx context.Context, socket string, req Request) (*Response, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(deadline))
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	// A refused peer is answered before its request is read, and the
	// courier hangs up, so a failed write still reads the answer.
	_, werr := c.Write(append(b, '\n'))
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(io.LimitReader(c, 2*maxRequest))).Decode(&resp); err != nil {
		if werr != nil {
			return nil, werr
		}
		return nil, err
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	return &resp, nil
}

// Read asks the courier for the policy file above pid's working directory.
func Read(ctx context.Context, socket string, pid int, start uint64) (*Response, error) {
	return Call(ctx, socket, Request{Op: OpRead, Pid: pid, Start: start})
}

// Write asks the courier to replace root's policy file, if it is still old.
func Write(ctx context.Context, socket, root, oldDigest string, bytes, sig []byte) (*Response, error) {
	return Call(ctx, socket, Request{Op: OpWrite, Root: root, OldDigest: oldDigest, Bytes: bytes, Sig: sig})
}
