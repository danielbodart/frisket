// Package nsmount puts files into a sandbox: a tmpfs of their own, written
// from the host, made read-only, and attached at a directory inside the
// sandbox's mount namespace. It is how a session's CA certificate reaches it
// (PLAN.md, decision 4).
//
// NOTHING IS WRITTEN ON THE HOST. The tmpfs is made detached (fsopen and
// fsmount), filled through its descriptor, and exists only as the mount it
// becomes inside the sandbox -- so it goes when the sandbox's namespace does,
// however the session ends, with nothing to clean up.
//
// The mount is made by root, in a mount namespace owned by the initial user
// namespace. So the workload cannot unmount it, remount it writable, or
// write through it; and a user namespace it makes of its own gets the mount
// locked, as the kernel locks every mount it inherits from a more privileged
// namespace. Measured: in a flong session, every one of those refused.
package nsmount

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// File is one file to put in the sandbox.
type File struct {
	Name string
	Data []byte
}

// nsGetNSType is NS_GET_NSTYPE, _IO(0xb7, 0x3), which x/sys does not name.
const nsGetNSType = 0xb703

// Attach mounts files, read-only, at dir inside the mount namespace at mntns
// -- /proc/<pid>/ns/mnt of a process in the sandbox. dir is absolute, and is
// made if it is missing. The files are 0644 and the directory 0755, owned by
// root, so a workload of any uid reads them and none writes them.
//
// It refuses the caller's own mount namespace: the mount would land on the
// host.
func Attach(mntns, dir string, files []File) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == "/" {
		return fmt.Errorf("nsmount: %q is not an absolute directory to mount at", dir)
	}
	for _, f := range files {
		if f.Name == "" || f.Name == "." || f.Name == ".." || strings.ContainsRune(f.Name, '/') {
			return fmt.Errorf("nsmount: %q is not a file name", f.Name)
		}
	}
	ns, err := openMountNamespace(mntns)
	if err != nil {
		return err
	}
	defer ns.Close()

	tree, err := filled(files)
	if err != nil {
		return err
	}
	defer unix.Close(tree)

	// ONE THREAD ENTERS, AND IS NEVER GIVEN BACK. setns into a mount namespace
	// refuses a thread that shares its filesystem context, and every thread
	// of a Go process does; unsharing CLONE_FS gives this one its own. It is
	// locked and never unlocked, so the runtime retires it when the goroutine
	// ends rather than handing a thread that is in the sandbox's namespace to
	// something else.
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		done <- attachInside(int(ns.Fd()), tree, dir)
	}()
	return <-done
}

// openMountNamespace opens path and checks it is a mount namespace, and not
// this process's.
func openMountNamespace(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("nsmount: opening mount namespace %s: %w", path, err)
	}
	t, err := unix.IoctlRetInt(int(f.Fd()), nsGetNSType)
	if err != nil || t != unix.CLONE_NEWNS {
		f.Close()
		return nil, fmt.Errorf("nsmount: %s is not a mount namespace", path)
	}
	var theirs, ours unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &theirs); err != nil {
		f.Close()
		return nil, fmt.Errorf("nsmount: %s: %w", path, err)
	}
	if err := unix.Stat("/proc/thread-self/ns/mnt", &ours); err != nil {
		f.Close()
		return nil, fmt.Errorf("nsmount: this process's mount namespace: %w", err)
	}
	if theirs.Dev == ours.Dev && theirs.Ino == ours.Ino {
		f.Close()
		return nil, fmt.Errorf("nsmount: %s is this process's own mount namespace, not a sandbox's", path)
	}
	return f, nil
}

// filled is a detached tmpfs holding files, read-only from here on.
func filled(files []File) (tree int, err error) {
	fs, err := unix.Fsopen("tmpfs", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("nsmount: fsopen tmpfs: %w", err)
	}
	defer unix.Close(fs)
	size := 64 << 10
	for _, f := range files {
		size += len(f.Data)
	}
	// Sized to what it holds, and no more inodes than its files and its root:
	// read-only once attached, but bounded before that too.
	for k, v := range map[string]string{
		"mode":      "0755",
		"size":      strconv.Itoa(size),
		"nr_inodes": strconv.Itoa(len(files) + 1),
	} {
		if err := unix.FsconfigSetString(fs, k, v); err != nil {
			return -1, fmt.Errorf("nsmount: tmpfs %s=%s: %w", k, v, err)
		}
	}
	if err := unix.FsconfigCreate(fs); err != nil {
		return -1, fmt.Errorf("nsmount: creating the tmpfs: %w", err)
	}
	tree, err = unix.Fsmount(fs, unix.FSMOUNT_CLOEXEC, unix.MOUNT_ATTR_NOSUID|unix.MOUNT_ATTR_NODEV|unix.MOUNT_ATTR_NOEXEC)
	if err != nil {
		return -1, fmt.Errorf("nsmount: fsmount: %w", err)
	}
	defer func() {
		if err != nil {
			unix.Close(tree)
			tree = -1
		}
	}()
	for _, f := range files {
		if err := writeFile(tree, f); err != nil {
			return -1, fmt.Errorf("nsmount: %s: %w", f.Name, err)
		}
	}
	if err := unix.MountSetattr(tree, "", unix.AT_EMPTY_PATH, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}); err != nil {
		return -1, fmt.Errorf("nsmount: making the tmpfs read-only: %w", err)
	}
	return tree, nil
}

func writeFile(tree int, f File) error {
	fd, err := unix.Openat(tree, f.Name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), f.Name)
	defer file.Close()
	// Whatever the umask.
	if err := file.Chmod(0o644); err != nil {
		return err
	}
	if _, err := file.Write(f.Data); err != nil {
		return err
	}
	return file.Close()
}

// attachInside runs on a locked thread of its own: it enters the namespace
// and attaches tree at dir there.
func attachInside(ns, tree int, dir string) error {
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		return fmt.Errorf("nsmount: unshare CLONE_FS: %w", err)
	}
	if err := unix.Setns(ns, unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("nsmount: entering the mount namespace: %w", err)
	}
	// Resolved inside, with no symlink followed anywhere on the way: a link
	// in the sandbox's root pointing out of the directory is not followed to
	// wherever it points. The workload has not started yet, so nothing of its
	// is there; this holds if that ever changes.
	how := &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	parent, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(dir), how)
	if err != nil {
		return fmt.Errorf("nsmount: %s inside the sandbox: %w", filepath.Dir(dir), err)
	}
	defer unix.Close(parent)
	base := filepath.Base(dir)
	if err := unix.Mkdirat(parent, base, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("nsmount: making %s inside the sandbox: %w", dir, err)
	}
	target, err := unix.Openat2(parent, base, how)
	if err != nil {
		return fmt.Errorf("nsmount: %s inside the sandbox: %w", dir, err)
	}
	defer unix.Close(target)
	if err := unix.MoveMount(tree, "", target, "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
		return fmt.Errorf("nsmount: attaching at %s inside the sandbox: %w", dir, err)
	}
	return nil
}
