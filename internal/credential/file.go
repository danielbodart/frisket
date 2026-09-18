package credential

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// maxFileSize bounds a credential file. They are a few hundred bytes; a file
// of megabytes is not a credential, and reading it on every change would be a
// way to make frisket spend memory on the user's behalf.
const maxFileSize = 1 << 20

// File is a credential read from a file on the host and re-read when it
// changes.
//
// THE DIRECTORY IS WATCHED, NOT THE FILE. Claude Code, codex and gh all write
// their credential files by temp-file-and-rename, and an inotify watch on the
// file follows the inode: after the first rename it is watching a file that
// no longer has a name, and every later change is missed. A watch on the
// directory sees the new name arrive (IN_MOVED_TO) whichever inode it is.
//
// Where no watch can be trusted -- the directory is itself a symlink, which
// inotify resolves once and never again (sops-nix switches /run/secrets that
// way), or the watch was lost -- it falls back to comparing the file's
// identity on every Get, which costs a stat and cannot miss a change.
type File struct {
	path    string
	base    string
	dir     string
	extract Extractor
	log     *slog.Logger

	state atomic.Pointer[loaded]
	// polling is set when the watch cannot be relied on; Get then checks the
	// file's identity itself.
	polling atomic.Bool
	// reload serialises reads of the file, so an event and a Get racing each
	// other cannot store an older read over a newer one.
	reload sync.Mutex

	inotify *os.File
	done    sync.WaitGroup
	closed  atomic.Bool
}

// loaded is one read of the file, published atomically so Get never takes a
// lock on the request path.
type loaded struct {
	secret Secret
	err    error
	id     identity
}

// identity is enough of a stat to tell that a path now names different
// content: a rename changes the inode, an in-place write the size or times.
type identity struct {
	dev, ino     uint64
	size         int64
	mtime, ctime syscall.Timespec
}

// WatchFile reads the credential at path with extract, and keeps it current.
//
// A file that is missing or malformed now is not an error here: it may appear
// later, and until it does every Get fails, loudly, which is the behaviour a
// route needs. A directory that cannot be watched IS an error, because that is
// configuration and not state.
func WatchFile(path string, extract Extractor, log *slog.Logger) (*File, error) {
	if extract == nil {
		return nil, errors.New("credential: WatchFile needs an extractor")
	}
	if log == nil {
		return nil, errors.New("credential: WatchFile needs a logger")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	f := &File{
		path:    abs,
		base:    filepath.Base(abs),
		dir:     filepath.Dir(abs),
		extract: extract,
		log:     log,
	}

	if resolved, err := filepath.EvalSymlinks(f.dir); err != nil {
		return nil, fmt.Errorf("credential: directory of %s: %w", abs, err)
	} else if resolved != f.dir {
		f.polling.Store(true)
		f.log.Warn("credential watch",
			"path", f.path,
			"mode", "polling",
			"reason", "directory is a symlink ("+resolved+"), and a watch would stay on whatever it named when the watch was added",
		)
	}

	if !f.polling.Load() {
		// Non-blocking, so the fd can go into the runtime's poller: a Read
		// blocked in a raw syscall is not interrupted by Close, and Close
		// would then hang for as long as nothing changed in the directory.
		fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
		if err != nil {
			return nil, fmt.Errorf("credential: inotify: %w", err)
		}
		f.inotify = os.NewFile(uintptr(fd), "inotify:"+f.dir)
		if err := f.addWatch(); err != nil {
			_ = f.inotify.Close()
			return nil, fmt.Errorf("credential: watch %s: %w", f.dir, err)
		}
	}

	// Load after the watch exists, never before: a rename landing between a
	// read and the watch would otherwise be missed for good.
	f.load()

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

// Get returns the credential as of the last change to the file.
func (f *File) Get() (Secret, error) {
	if f.polling.Load() {
		f.refreshIfChanged()
	}
	s := f.state.Load()
	return s.secret, s.err
}

// Path is the file this source reads, for log lines.
func (f *File) Path() string { return f.path }

// Close stops watching. Get keeps returning the last value read.
func (f *File) Close() error {
	if f.closed.Swap(true) || f.inotify == nil {
		return nil
	}
	err := f.inotify.Close()
	f.done.Wait()
	return err
}

func (f *File) refreshIfChanged() {
	id, _ := stat(f.path)
	if s := f.state.Load(); s != nil && s.id == id {
		return
	}
	f.load()
}

// load reads the file and publishes the result, logging when the outcome
// changes. It logs the path, whether a credential was produced and when it
// expires -- never the value, and never an error that could quote it.
func (f *File) load() {
	f.reload.Lock()
	defer f.reload.Unlock()

	next := &loaded{}
	next.id, _ = stat(f.path)
	raw, err := readBounded(f.path)
	if err == nil {
		next.secret, err = f.extract(raw)
	}
	if err != nil {
		next.secret = Secret{}
		if !errors.Is(err, ErrUnavailable) {
			err = fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		next.err = err
	}

	// Logged BEFORE it is published, so no request can use a credential the
	// log has not yet said changed. Load-then-Store is safe: f.reload
	// serialises every writer.
	if prev := f.state.Load(); prev == nil || !sameOutcome(prev, next) {
		f.logOutcome(next)
	}
	f.state.Store(next)
}

func (f *File) logOutcome(next *loaded) {
	attrs := []any{"path", f.path}
	if next.err != nil {
		attrs = append(attrs, "outcome", "unavailable", "error", next.err.Error())
		f.log.Error("credential", attrs...)
		return
	}
	attrs = append(attrs, "outcome", "loaded")
	if !next.secret.Expires.IsZero() {
		attrs = append(attrs, "expires", next.secret.Expires.UTC())
	}
	f.log.Info("credential", attrs...)
}

func sameOutcome(a, b *loaded) bool {
	if (a.err == nil) != (b.err == nil) {
		return false
	}
	if a.err != nil {
		return a.err.Error() == b.err.Error()
	}
	return a.secret.Value == b.secret.Value && a.secret.Expires.Equal(b.secret.Expires)
}

func readBounded(path string) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	raw, err := io.ReadAll(io.LimitReader(fh, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxFileSize {
		return nil, fmt.Errorf("larger than %d bytes", maxFileSize)
	}
	return raw, nil
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
				f.load()
				return
			}
			f.load()
			continue
		}
		if relevant {
			f.load()
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

// degrade switches to checking the file on every Get. It is logged, because a
// source that has quietly stopped noticing changes is exactly the failure
// this type exists to prevent.
func (f *File) degrade(reason string) {
	f.polling.Store(true)
	f.log.Warn("credential watch", "path", f.path, "mode", "polling", "reason", reason)
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
