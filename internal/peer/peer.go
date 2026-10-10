// Package peer says who is on the other end of a unix socket: the peer's
// uid and user namespace, and the chain of processes above it, with the
// anchor a grant or window is keyed on.
package peer

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Not in x/sys yet: linux/pidfd.h, _IO(PIDFS_IOCTL_MAGIC, 9), Linux 6.11.
const pidfdGetUserNamespace = 0xff09

const depth = 16

var transient = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "fish": true, "dash": true,
	"env": true, "timeout": true, "nice": true, "nohup": true, "setsid": true,
	"script": true, "sudo": true, "ssh": true, "git": true,
}

var terminalLeaf = map[string]bool{"ssh": true, "git": true, "scp": true, "sftp": true, "rsync": true}

const terminalServer = ".kgx-wrapped"

var cgroupRoot = "/sys/fs/cgroup"

type Link struct {
	Pid, PPid, Sid int
	TTY            uint32
	Start          uint64
	UID            int
	Comm           string
	Cmdline        []string
	Cgroup         string
}

// Requester is a chain, leaf first, and what it resolves to. Anchor points
// into Chain, and is nil only for a Cut chain with no link to key on.
type Requester struct {
	Chain                      []Link
	Anchor                     *Link
	Cut, SessionRoot, Terminal bool
	PeerUID                    int
	CgroupID                   uint64
	PPid                       int
}

// FromConn reads the requester from the process the kernel recorded at
// connect, through SO_PEERPIDFD, never from a pid that may have been reused.
func FromConn(c *net.UnixConn) (*Requester, error) {
	cred, pidfd, err := credentials(c)
	if err != nil {
		return nil, err
	}
	defer unix.Close(pidfd)
	info, err := pidfdInfo(pidfd)
	if err != nil {
		return nil, err
	}
	var links []Link
	for pid := int(info.Pid); len(links) < depth; {
		l, err := readLink(pid)
		if len(links) == 0 {
			if _, aerr := pidfdInfo(pidfd); aerr != nil {
				return nil, aerr
			}
		}
		if err != nil {
			break
		}
		links = append(links, l)
		if l.Pid == 1 {
			break
		}
		pid = l.PPid
	}
	r := resolve(links)
	r.PeerUID, r.CgroupID, r.PPid = int(cred.Uid), info.Cgroupid, int(info.Ppid)
	return r, nil
}

// Proc is a peer process alone: its SO_PEERCRED uid, and its pid and kernel
// ppid from SO_PEERPIDFD, each with its starttime. PPidStart is 0 when the
// parent cannot be read.
type Proc struct {
	UID, Pid, PPid   int
	Start, PPidStart uint64
}

func ProcOf(c *net.UnixConn) (Proc, error) {
	cred, pidfd, err := credentials(c)
	if err != nil {
		return Proc{}, err
	}
	defer unix.Close(pidfd)
	info, err := pidfdInfo(pidfd)
	if err != nil {
		return Proc{}, err
	}
	self, err := readStat("/proc/" + strconv.Itoa(int(info.Pid)))
	if err != nil {
		return Proc{}, err
	}
	if _, err := pidfdInfo(pidfd); err != nil {
		return Proc{}, err
	}
	p := Proc{UID: int(cred.Uid), Pid: int(info.Pid), PPid: int(info.Ppid), Start: self.Start}
	if parent, err := readStat("/proc/" + strconv.Itoa(p.PPid)); err == nil {
		p.PPidStart = parent.Start
	}
	return p, nil
}

// Alive is whether pid is still the process that started at start.
func Alive(pid int, start uint64) bool {
	l, err := readStat("/proc/" + strconv.Itoa(pid))
	return err == nil && l.Start == start
}

// FromLinks resolves a chain collected elsewhere, leaf first.
func FromLinks(links []Link) *Requester {
	r := resolve(links)
	if len(r.Chain) > 0 {
		r.PeerUID, r.PPid = r.Chain[0].UID, r.Chain[0].PPid
	}
	return r
}

// IsMainOf is true for the main process of the system unit: uid, ppid 1,
// the unit's name as comm, and the unit's cgroup by inode, stat'ed now.
func (r *Requester) IsMainOf(unit string, uid int) bool {
	if len(r.Chain) == 0 || r.PeerUID != uid || r.PPid != 1 || r.CgroupID == 0 ||
		r.Chain[0].Comm != strings.TrimSuffix(unit, ".service") {
		return false
	}
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(cgroupRoot, "system.slice", unit), &st); err != nil {
		return false
	}
	return st.Ino == r.CgroupID
}

func resolve(links []Link) *Requester {
	n := min(len(links), depth)
	for i := 1; i < n; i++ {
		if links[i].Pid != links[i-1].PPid || links[i].Start > links[i-1].Start {
			n = i
			break
		}
	}
	r := &Requester{Chain: links[:n:n]}
	r.Cut = n == 0 || r.Chain[n-1].Pid != 1
	for i := range r.Chain {
		if terminal(r.Chain, i) {
			r.Terminal = true
			r.Anchor = &r.Chain[i]
			break
		}
	}
	for i := 0; r.Anchor == nil && i < n; i++ {
		if tabShell(r.Chain, i) || !transient[r.Chain[i].Comm] {
			r.Anchor = &r.Chain[i]
		}
	}
	if a := r.Anchor; a != nil {
		r.SessionRoot = a.Pid == 1 || systemdUser(*a) || a.Comm == terminalServer
	}
	return r
}

func tabShell(chain []Link, i int) bool {
	l := chain[i]
	return i+1 < len(chain) && chain[i+1].Comm == terminalServer &&
		l.Comm == "bash" && len(l.Cmdline) == 1 && l.Sid == l.Pid && pts(l.TTY)
}

func terminal(chain []Link, shell int) bool {
	if !tabShell(chain, shell) || shell+2 >= len(chain) || !systemdUser(chain[shell+2]) {
		return false
	}
	for _, l := range chain[:shell] {
		if !terminalLeaf[l.Comm] {
			return false
		}
	}
	return true
}

func systemdUser(l Link) bool {
	return l.Comm == "systemd" && l.Pid != 1 && l.PPid == 1
}

// pts is a Unix98 pty slave: majors 136 to 143.
func pts(tty uint32) bool {
	major := (tty >> 8) & 0xfff
	return major >= 136 && major <= 143
}

const pidfdWant = unix.PIDFD_INFO_PID | unix.PIDFD_INFO_CREDS | unix.PIDFD_INFO_CGROUPID

// pidfdInfo checks the mask before any field: a dead pidfd reads as uid 0.
func pidfdInfo(pidfd int) (*unix.PidfdInfo, error) {
	info := unix.PidfdInfo{Mask: pidfdWant}
	if err := unix.IoctlPidfdInfo(pidfd, &info); err != nil {
		return nil, fmt.Errorf("PIDFD_GET_INFO: %w", err)
	}
	if info.Mask&pidfdWant != pidfdWant {
		return nil, errors.New("the peer has exited")
	}
	return &info, nil
}

func readLink(pid int) (Link, error) {
	dir := "/proc/" + strconv.Itoa(pid)
	l, err := readStat(dir)
	if err != nil {
		return Link{}, err
	}
	status, err := os.ReadFile(dir + "/status")
	if err != nil {
		return Link{}, err
	}
	cmdline, err := os.ReadFile(dir + "/cmdline")
	if err != nil {
		return Link{}, err
	}
	cgroup, err := os.ReadFile(dir + "/cgroup")
	if err != nil {
		return Link{}, err
	}
	again, err := readStat(dir)
	if err != nil {
		return Link{}, err
	}
	if again.Start != l.Start {
		return Link{}, fmt.Errorf("pid %d was replaced while it was read", pid)
	}
	if l.UID, err = statusUID(status); err != nil {
		return Link{}, fmt.Errorf("pid %d: %w", pid, err)
	}
	if s := strings.TrimSuffix(string(cmdline), "\x00"); s != "" {
		l.Cmdline = strings.Split(s, "\x00")
	}
	for line := range strings.Lines(string(cgroup)) {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			l.Cgroup = strings.TrimSuffix(p, "\n")
		}
	}
	return l, nil
}

func readStat(dir string) (Link, error) {
	b, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return Link{}, err
	}
	s := string(b)
	lp, rp := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if lp < 0 || rp < lp {
		return Link{}, fmt.Errorf("%s/stat: no comm", dir)
	}
	f := strings.Fields(s[rp+1:])
	if len(f) < 20 {
		return Link{}, fmt.Errorf("%s/stat: %d fields", dir, len(f))
	}
	var l Link
	var tty int64
	l.Comm = s[lp+1 : rp]
	l.Pid, err = strconv.Atoi(strings.TrimSpace(s[:lp]))
	if err == nil {
		l.PPid, err = strconv.Atoi(f[1])
	}
	if err == nil {
		l.Sid, err = strconv.Atoi(f[3])
	}
	if err == nil {
		tty, err = strconv.ParseInt(f[4], 10, 32)
		l.TTY = uint32(tty)
	}
	if err == nil {
		l.Start, err = strconv.ParseUint(f[19], 10, 64)
	}
	if err != nil {
		return Link{}, fmt.Errorf("%s/stat: %w", dir, err)
	}
	return l, nil
}

func statusUID(status []byte) (int, error) {
	for line := range strings.Lines(string(status)) {
		if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				return strconv.Atoi(f[0])
			}
		}
	}
	return 0, errors.New("no Uid in status")
}

// Cred is the peer's SO_PEERCRED: its uid in this user namespace and its pid
// in this pid namespace, as the kernel recorded them at connect.
func Cred(c *net.UnixConn) (*unix.Ucred, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := rc.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	if credErr != nil {
		return nil, fmt.Errorf("SO_PEERCRED: %w", credErr)
	}
	return cred, nil
}

func credentials(c *net.UnixConn) (*unix.Ucred, int, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return nil, -1, err
	}
	var cred *unix.Ucred
	var credErr, pidfdErr error
	pidfd := -1
	if err := rc.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		pidfd, pidfdErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	}); err != nil {
		return nil, -1, err
	}
	if credErr != nil {
		if pidfdErr == nil {
			unix.Close(pidfd)
		}
		return nil, -1, fmt.Errorf("SO_PEERCRED: %w", credErr)
	}
	if pidfdErr != nil {
		return nil, -1, fmt.Errorf("SO_PEERPIDFD: %w", pidfdErr)
	}
	return cred, pidfd, nil
}

// Userns names a user namespace: the device and inode of its nsfs file.
type Userns struct{ dev, ino uint64 }

func OwnUserns() (Userns, error) {
	f, err := os.Open("/proc/self/ns/user")
	if err != nil {
		return Userns{}, err
	}
	defer f.Close()
	return nsID(int(f.Fd()))
}

func nsID(fd int) (Userns, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return Userns{}, err
	}
	return Userns{st.Dev, st.Ino}, nil
}

// Check refuses any peer but uid, and any peer outside userns.
//
// THE UID ALONE IS NOT ENOUGH. A sandbox's workload runs as the same host uid
// as the launcher that started it, mapped through the sandbox's user
// namespaces, and SO_PEERCRED reports it as that uid. A peer whose namespace
// cannot be read is refused.
func Check(c *net.UnixConn, uid int, userns Userns) error {
	cred, pidfd, err := credentials(c)
	if err != nil {
		return err
	}
	defer unix.Close(pidfd)
	if int(cred.Uid) != uid {
		return fmt.Errorf("uid %d may not use this socket", cred.Uid)
	}
	nsfd, err := unix.IoctlRetInt(pidfd, pidfdGetUserNamespace)
	if err != nil {
		return fmt.Errorf("pid %d's user namespace: %w", cred.Pid, err)
	}
	ns, err := nsID(nsfd)
	unix.Close(nsfd)
	if err != nil {
		return fmt.Errorf("pid %d's user namespace: %w", cred.Pid, err)
	}
	if ns != userns {
		return fmt.Errorf("pid %d is in another user namespace and may not use this socket", cred.Pid)
	}
	return nil
}
