package serve

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// Neither is in x/sys yet. SO_PEERPIDFD is Linux 6.5, and the ioctl that
// opens a pidfd's user namespace is 6.11.
const (
	soPeerPidfd           = 77     // asm-generic/socket.h
	pidfdGetUserNamespace = 0xff09 // linux/pidfd.h: _IO(PIDFS_IOCTL_MAGIC, 9)
)

// checkPeer refuses anyone but ControlUID, and anyone not in the daemon's own
// user namespace -- the initial one, under its unit.
//
// THE UID ALONE IS NOT ENOUGH. A sandbox's workload runs as the same host uid
// as the launcher that started it, mapped through the sandbox's user
// namespaces, and SO_PEERCRED reports it as that uid. The mount namespace is
// what keeps the workload off this socket; the user namespace is the second
// check, and it costs one ioctl. A peer whose namespace cannot be read is
// refused: this is a question with a safe answer.
func (d *Daemon) checkPeer(c *net.UnixConn) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var credErr error
	var pidfd int
	var pidfdErr error
	if err := rc.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		pidfd, pidfdErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, soPeerPidfd)
	}); err != nil {
		return err
	}
	if pidfdErr == nil {
		defer unix.Close(pidfd)
	}
	if credErr != nil {
		return fmt.Errorf("SO_PEERCRED: %w", credErr)
	}
	if int(cred.Uid) != d.ControlUID {
		return fmt.Errorf("uid %d may not use the control socket", cred.Uid)
	}
	if pidfdErr != nil {
		return fmt.Errorf("SO_PEERPIDFD: %w; the peer's user namespace cannot be checked", pidfdErr)
	}
	// From the pidfd and not from /proc/<pid>: the process the kernel
	// recorded at connect, never another that reused its pid since.
	nsfd, err := unix.IoctlRetInt(pidfd, pidfdGetUserNamespace)
	if err != nil {
		return fmt.Errorf("pid %d's user namespace: %w", cred.Pid, err)
	}
	peer, err := nsID(nsfd)
	unix.Close(nsfd)
	if err != nil {
		return fmt.Errorf("pid %d's user namespace: %w", cred.Pid, err)
	}
	if peer != d.userns {
		return fmt.Errorf("pid %d is in another user namespace and may not use the control socket", cred.Pid)
	}
	return nil
}

// nsKey names a namespace: the device and inode of its nsfs file.
type nsKey struct{ dev, ino uint64 }

func nsID(fd int) (nsKey, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nsKey{}, err
	}
	return nsKey{st.Dev, st.Ino}, nil
}

// ownUserns is this process's user namespace.
func ownUserns() (nsKey, error) {
	f, err := os.Open("/proc/self/ns/user")
	if err != nil {
		return nsKey{}, err
	}
	defer f.Close()
	return nsID(int(f.Fd()))
}
