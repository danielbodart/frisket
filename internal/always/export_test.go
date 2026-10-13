package always

import (
	"context"

	"github.com/danielbodart/quoin/policysign"
)

// Fake replaces what signs and writes, for a test.
func (w *Writer) Fake(sign func(context.Context, policysign.Request) ([]byte, error),
	write func(ctx context.Context, root, oldDigest string, b, sig []byte) error) {
	w.sign, w.write = sign, write
}

// Wait is until the session's write, if one is under way, is done.
func (s *Session) Wait() {
	s.mu.Lock()
	defer s.mu.Unlock()
}
