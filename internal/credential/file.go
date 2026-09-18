package credential

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/danielbodart/frisket/internal/watch"
)

// maxFileSize bounds a credential file. They are a few hundred bytes; a file
// of megabytes is not a credential, and reading it on every change would be a
// way to make frisket spend memory on the user's behalf.
const maxFileSize = 1 << 20

// File is a credential read from a file on the host and re-read when it
// changes -- by rename too, which is how Claude Code, codex and gh write theirs.
// How a change is noticed is internal/watch's.
type File struct {
	path    string
	extract Extractor
	log     *slog.Logger

	state atomic.Pointer[loaded]
	watch *watch.File
}

// loaded is one read of the file, published atomically so Get never takes a
// lock on the request path.
type loaded struct {
	secret Secret
	err    error
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
	f := &File{path: abs, extract: extract, log: log}
	w, err := watch.New(abs, "credential", f.load, log)
	if err != nil {
		return nil, fmt.Errorf("credential: %w", err)
	}
	f.watch = w
	return f, nil
}

// Get returns the credential as of the last change to the file.
func (f *File) Get() (Secret, error) {
	f.watch.Check()
	s := f.state.Load()
	return s.secret, s.err
}

// Path is the file this source reads, for log lines.
func (f *File) Path() string { return f.path }

// Close stops watching. Get keeps returning the last value read.
func (f *File) Close() error { return f.watch.Close() }

// load reads the file and publishes the result, logging when the outcome
// changes. It logs the path, whether a credential was produced and when it
// expires -- never the value, and never an error that could quote it.
//
// The watcher never calls it concurrently with itself.
func (f *File) load() {
	next := &loaded{}
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
	// log has not yet said changed. Load-then-Store is safe: the watcher
	// serialises every call.
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
