// Package watch follows a file on the host that is replaced under frisket:
// credential files, and the host's resolv.conf.
package watch

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// File calls its load function whenever the file at a path may have changed.
//
// THE DIRECTORY IS WATCHED, NOT THE FILE. Claude Code, codex and gh write their
// credential files by temp-file-and-rename, and so do the tools that rewrite
// resolv.conf. An inotify watch on the file follows the inode: after the first
// rename it is watching a file that no longer has a name, and every later
// change is missed. A watch on the directory sees the new name arrive
// (IN_MOVED_TO) whichever inode it is.
//
// Where no watch can be trusted it falls back to comparing the file's identity
// on every Check, which costs a stat and cannot miss a change. That is when the
// directory is itself a symlink, which inotify resolves once and never again
// (sops-nix switches /run/secrets that way); when the file is a symlink, whose
// target changes in a directory nobody is watching (systemd-resolved's
// /etc/resolv.conf); and when the watch was lost.
type File struct {
	path  string
	base  string
	dir   string
	label string
	load  func()
	log   *slog.Logger

	// polling is set when the watch cannot be relied on; Check then compares
	// the file's identity itself.
	polling atomic.Bool
	// id is the file's identity as of the last load.
	id atomic.Pointer[identity]
	// mu serialises loads, so an event and a Check racing each other cannot
	// publish an older read over a newer one.
	mu sync.Mutex

	inotify *os.File
	done    sync.WaitGroup
	closed  atomic.Bool
}

// identity is enough of a stat to tell that a path now names different
// content: a rename changes the inode, an in-place write the size or times.
// It follows symlinks, so a link pointed elsewhere is a different identity.
type identity struct {
	dev, ino     uint64
	size         int64
	mtime, ctime syscall.Timespec
}

// New watches path, calling load once now and again whenever the file may have
// changed. load is never called concurrently with itself. label names the
// watcher in its log lines, as "<label> watch".
//
// A file that is missing now is not an error here: it may appear later, and
// load is what decides what an absent file means. A directory that cannot be
// watched IS an error, because that is configuration and not state.
func New(path, label string, load func(), log *slog.Logger) (*File, error) {
	if load == nil || log == nil {
		return nil, errors.New("watch: a load function and a logger are both required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	f := &File{
		path:  abs,
		base:  filepath.Base(abs),
		dir:   filepath.Dir(abs),
		label: label,
		load:  load,
		log:   log,
	}

	if resolved, err := filepath.EvalSymlinks(f.dir); err != nil {
		return nil, fmt.Errorf("directory of %s: %w", abs, err)
	} else if resolved != f.dir {
		f.degrade("directory is a symlink (" + resolved + "), and a watch would stay on whatever it named when the watch was added")
	}

	if !f.polling.Load() {
		// Non-blocking, so the fd can go into the runtime's poller: a Read
		// blocked in a raw syscall is not interrupted by Close, and Close
		// would then hang for as long as nothing changed in the directory.
		fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
		if err != nil {
			return nil, fmt.Errorf("inotify: %w", err)
		}
		f.inotify = os.NewFile(uintptr(fd), "inotify:"+f.dir)
		if err := f.addWatch(); err != nil {
			_ = f.inotify.Close()
			return nil, fmt.Errorf("watch %s: %w", f.dir, err)
		}
	}

	// Load after the watch exists, never before: a rename landing between a
	// read and the watch would otherwise be missed for good.
	f.reload()

	if f.inotify != nil {
		f.done.Add(1)
		go f.watch()
	}
	return f, nil
}

func (f *File) addWatch() error {
	const mask = syscall.IN_CLOSE_WRITE | syscall.IN_MOVED_TO | syscall.IN_MOVED_FROM |
		syscall.IN_CREATE | syscall.IN_DELETE | syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF |
		syscall.IN_ONLYDIR
	return rawConn(f.inotify, func(fd uintptr) error {
		_, err := syscall.InotifyAddWatch(int(fd), f.dir, mask)
		return err
	})
}

// Check is called on use. Where the watch cannot be relied on it reloads if the
// file's identity has changed since the last load; otherwise it does nothing,
// and costs nothing.
func (f *File) Check() {
	if !f.polling.Load() {
		return
	}
	id, _ := stat(f.path)
	if last := f.id.Load(); last != nil && *last == id {
		return
	}
	f.reload()
}

// Path is the file watched, absolute, for log lines.
func (f *File) Path() string { return f.path }

// Polling reports whether changes are found by Check rather than the watch.
func (f *File) Polling() bool { return f.polling.Load() }

// Close stops watching. Nothing is loaded after it returns.
func (f *File) Close() error {
	if f.closed.Swap(true) || f.inotify == nil {
		return nil
	}
	err := f.inotify.Close()
	f.done.Wait()
	return err
}

// reload takes the file's identity, loads it, and only then publishes the
// identity. Taken before the read, so a change that lands during it is a new
// identity and loaded again rather than missed; published after, so a Check
// that sees it knows the load it belongs to is done, and does not return
// ahead of it.
func (f *File) reload() {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, _ := stat(f.path)
	if !f.polling.Load() {
		if fi, err := os.Lstat(f.path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			target, _ := filepath.EvalSymlinks(f.path)
			f.degrade("file is a symlink (" + target + "), and the directory watched is not the one its target changes in")
		}
	}
	f.load()
	f.id.Store(&id)
}

func stat(path string) (identity, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return identity{}, err
	}
	return identity{
		dev: uint64(st.Dev), ino: uint64(st.Ino), size: st.Size,
		mtime: st.Mtim, ctime: st.Ctim,
	}, nil
}

// watch reads inotify events until Close.
func (f *File) watch() {
	defer f.done.Done()
	// Room for many events at once; a name is at most NAME_MAX+1 bytes.
	buf := make([]byte, 64*(syscall.SizeofInotifyEvent+syscall.NAME_MAX+1))
	for {
		n, err := f.inotify.Read(buf)
		if err != nil {
			if f.closed.Load() {
				return
			}
			f.degrade("inotify read failed: " + err.Error())
			return
		}
		relevant, lost := f.scan(buf[:n])
		if lost {
			// The directory went away or was moved, or the kernel dropped
			// events. Try to watch the path again -- it may name a new
			// directory now -- and read the file whatever happens, since an
			// event we did not see may have been the one that mattered.
			if err := f.addWatch(); err != nil {
				f.degrade("watch lost and could not be re-added: " + err.Error())
				f.reload()
				return
			}
			f.reload()
			continue
		}
		if relevant {
			f.reload()
		}
	}
}

// scan reports whether a batch of events touches the file, and whether the
// watch itself was lost or overflowed.
func (f *File) scan(buf []byte) (relevant, lost bool) {
	for len(buf) >= syscall.SizeofInotifyEvent {
		ev := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[0]))
		end := syscall.SizeofInotifyEvent + int(ev.Len)
		if end > len(buf) {
			return relevant, true
		}
		name := buf[syscall.SizeofInotifyEvent:end]
		for i, c := range name {
			if c == 0 {
				name = name[:i]
				break
			}
		}
		switch {
		case ev.Mask&(syscall.IN_Q_OVERFLOW|syscall.IN_IGNORED|syscall.IN_DELETE_SELF|syscall.IN_MOVE_SELF) != 0:
			lost = true
		case string(name) == f.base:
			relevant = true
		}
		buf = buf[end:]
	}
	return relevant, lost
}

// degrade switches to checking the file on every Check. It is logged, because
// a watcher that has quietly stopped noticing changes is exactly the failure
// this type exists to prevent.
func (f *File) degrade(reason string) {
	f.polling.Store(true)
	f.log.Warn(f.label+" watch", "path", f.path, "mode", "polling", "reason", reason)
}

// rawConn runs fn with the inotify descriptor, without taking it out of the
// runtime's poller the way (*os.File).Fd would.
func rawConn(f *os.File, fn func(fd uintptr) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	if err := rc.Control(func(fd uintptr) { inner = fn(fd) }); err != nil {
		return err
	}
	return inner
}
