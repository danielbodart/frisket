package intercept

import (
	"context"
	"io"
	"time"
)

// BodyPreview is how much of an asked request's body its question carries,
// and all of it that is read before a person answers: what one reads in a
// dialog, a git push's ref updates, a write's JSON, a stream's first message.
const BodyPreview = 4096

// previewIdle is how long a body, once it has started, may produce nothing
// before it is asked about with what it has sent. A client streaming an RPC
// sends its first message and waits for an answer, and a preview waiting for
// more would wait for ever. The sandbox is on this machine, so a body that is
// ready arrives in far less. Before its first byte a body is waited for: a
// question never shows an empty preview of a body still to come.
var previewIdle = 500 * time.Millisecond

type chunk struct {
	b   []byte
	err error
}

// preview reads the start of body: up to BodyPreview bytes, until it ends,
// or until, having started, it produces nothing for previewIdle. more is whether the body had
// not ended there. rest is the whole body again, the preview first, for
// sending on.
func preview(ctx context.Context, body io.ReadCloser) (head []byte, more bool, rest io.ReadCloser, err error) {
	reads := make(chan chunk, 1)
	read := func(n int) {
		go func() {
			b := make([]byte, n)
			k, err := body.Read(b)
			reads <- chunk{b[:k], err}
		}()
	}
	idle := time.NewTimer(previewIdle)
	idle.Stop()
	defer idle.Stop()
	read(BodyPreview + 1)
	for {
		select {
		case c := <-reads:
			head = append(head, c.b...)
			switch {
			case c.err != nil && c.err != io.EOF:
				return nil, false, nil, c.err
			case len(head) > BodyPreview:
				return head[:BodyPreview], true, &resumed{head: head, err: c.err, body: body}, nil
			case c.err == io.EOF:
				return head, false, &resumed{head: head, err: io.EOF, body: body}, nil
			}
			if len(c.b) > 0 {
				idle.Reset(previewIdle)
			}
			read(BodyPreview + 1 - len(head))
		case <-idle.C:
			return head, true, &resumed{head: head, pending: reads, body: body}, nil
		case <-ctx.Done():
			return nil, false, nil, ctx.Err()
		}
	}
}

// resumed is a body with its start already read: that, then whatever a read
// still outstanding brings, then the rest.
type resumed struct {
	head    []byte
	pending <-chan chunk
	err     error
	body    io.ReadCloser
}

func (r *resumed) Read(p []byte) (int, error) {
	if len(r.head) == 0 && r.err == nil && r.pending != nil {
		c := <-r.pending
		r.pending = nil
		r.head, r.err = c.b, c.err
	}
	if len(r.head) > 0 {
		n := copy(p, r.head)
		r.head = r.head[n:]
		return n, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	return r.body.Read(p)
}

func (r *resumed) Close() error { return r.body.Close() }
