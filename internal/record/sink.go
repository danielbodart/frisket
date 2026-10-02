package record

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// MaxSink is how large a sink may grow. One line is a few hundred bytes, so
// this is a long session's worth many times over; past it, one line says the
// rest was dropped, and the journal still has every line it did not
// rate-limit.
const MaxSink = 64 << 20

// sinkName is what a sink's file may be called: no dot first, no slash.
var sinkName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)

// CheckSinkPath holds a document's sink to the one place the daemon keeps
// records: a file directly in dir, by its absolute, clean path. dir empty is
// a daemon that keeps none, and refuses every sink. Only the shape is
// checked; whether the file can be opened is OpenSink's.
func CheckSinkPath(path, dir string) error {
	if dir == "" {
		return errors.New("record sink: this daemon keeps no records (no -record-dir)")
	}
	return checkShape(path, dir)
}

// CheckSinkShape is CheckSinkPath for a document checked away from the
// daemon, which does not know where the daemon keeps records: an absolute,
// clean path to a file, in some directory.
func CheckSinkShape(path string) error { return checkShape(path, "") }

func checkShape(path, dir string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("record sink %q: not an absolute, clean path", path)
	}
	if !sinkName.MatchString(filepath.Base(path)) {
		return fmt.Errorf("record sink %q: a file name of letters, digits, '.', '_' and '-', not starting with '.'", path)
	}
	if dir != "" && filepath.Dir(path) != filepath.Clean(dir) {
		return fmt.Errorf("record sink %q: not directly in %s, where this daemon keeps records", path, dir)
	}
	return nil
}

// Sink is a file of record lines, appended to and bounded.
type Sink struct {
	mu        sync.Mutex
	f         *os.File
	size      int64
	max       int64
	truncated bool
	now       func() time.Time
}

// OpenSink opens path for appending, creating it 0600: a regular file, not
// followed if it is a link, owned by this process's user, with no other
// name. One that has
// already reached the bound is opened truncated, and written no more.
func OpenSink(path string) (*Sink, error) {
	return openSink(path, MaxSink)
}

func openSink(path string, max int64) (*Sink, error) {
	// Read as well as appended to, by the one descriptor, for its last
	// line.
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_APPEND|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("record sink %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, fmt.Errorf("record sink %s: %w", path, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		f.Close()
		return nil, fmt.Errorf("record sink %s: not a regular file", path)
	case int(st.Uid) != os.Getuid():
		f.Close()
		return nil, fmt.Errorf("record sink %s: owned by uid %d, not this daemon's", path, st.Uid)
	case st.Mode&0o077 != 0:
		f.Close()
		return nil, fmt.Errorf("record sink %s: readable or writable by others", path)
	case st.Nlink != 1:
		// A hard link planted in the records directory to some other file
		// of this user's -- its authorized_keys, say -- passes every check
		// above, and would be appended to.
		f.Close()
		return nil, fmt.Errorf("record sink %s: %d links, not one", path, st.Nlink)
	}
	full, err := endsTruncated(f, st.Size)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Sink{f: f, size: st.Size, max: max, truncated: full || st.Size >= max, now: time.Now}, nil
}

// endsTruncated is whether a sink's last line is the one that says it was
// bounded: a sink reopened after it, by a restarted daemon, stays full,
// though the last line it dropped was one that might fit now.
func endsTruncated(f *os.File, size int64) (bool, error) {
	if size == 0 {
		return false, nil
	}
	tail := make([]byte, min(size, 128))
	if _, err := f.ReadAt(tail, size-int64(len(tail))); err != nil {
		return false, fmt.Errorf("record sink %s: %w", f.Name(), err)
	}
	return bytes.Contains(tail[bytes.LastIndexByte(tail[:len(tail)-1], '\n')+1:], []byte(`"truncated":true`)), nil
}

// Write appends one line, unless the sink is full; the first line past the
// bound is a line saying so, instead. A line no grant comes of -- a hard
// refusal, DNS telemetry -- is appended only while the sink is under half
// its bound, and dropped past it, so that it never fills what an answered
// subject's line needs.
func (s *Sink) Write(l Line) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.truncated || s.f == nil {
		return nil
	}
	if noise(l) && s.size+int64(len(b)) > s.max/2 {
		return nil
	}
	if s.size+int64(len(b)) > s.max {
		s.truncated = true
		b, _ = json.Marshal(struct {
			Time      time.Time `json:"time"`
			Truncated bool      `json:"truncated"`
			Max       int64     `json:"max"`
		}{s.now().UTC(), true, s.max})
		b = append(b, '\n')
	}
	n, err := s.f.Write(b)
	s.size += int64(n)
	return err
}

// noise is whether a line is one no grant comes of.
func noise(l Line) bool { return l.Source == SourceHard || l.Source == SourceTelemetry }

// Close closes the file.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}
