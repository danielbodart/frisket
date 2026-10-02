package intercept

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// all is a body that gives everything it has, and its end, in one read.
type all struct{ s string }

func (a *all) Read(p []byte) (int, error) {
	n := copy(p, a.s)
	a.s = a.s[n:]
	if a.s == "" {
		return n, io.EOF
	}
	return n, nil
}

func (a *all) Close() error { return nil }

func TestAPreviewIsTheStartAndTheRestIsAllOfIt(t *testing.T) {
	for _, tc := range []struct {
		body string
		head string
		more bool
	}{
		{"", "", false},
		{"short", "short", false},
		{strings.Repeat("a", BodyPreview), strings.Repeat("a", BodyPreview), false},
		{strings.Repeat("b", BodyPreview+1), strings.Repeat("b", BodyPreview), true},
		{strings.Repeat("c", 3*BodyPreview), strings.Repeat("c", BodyPreview), true},
	} {
		head, more, rest, err := preview(context.Background(), &all{tc.body})
		if err != nil || string(head) != tc.head || more != tc.more {
			t.Errorf("%d bytes: head %d, more %v, %v", len(tc.body), len(head), more, err)
			continue
		}
		if b, err := io.ReadAll(rest); err != nil || string(b) != tc.body {
			t.Errorf("%d bytes: rest %d, %v", len(tc.body), len(b), err)
		}
	}
}

func TestAPreviewEndsWhereTheBodyPauses(t *testing.T) {
	defer func(d time.Duration) { previewIdle = d }(previewIdle)
	previewIdle = 20 * time.Millisecond
	pr, pw := io.Pipe()
	go func() { _, _ = pw.Write([]byte("abc")) }()
	head, more, rest, err := preview(context.Background(), pr)
	if err != nil || string(head) != "abc" || !more {
		t.Fatalf("head %q, more %v, %v", head, more, err)
	}
	go func() {
		_, _ = pw.Write([]byte("def"))
		_ = pw.Close()
	}()
	if b, err := io.ReadAll(rest); err != nil || string(b) != "abcdef" {
		t.Fatalf("rest %q, %v", b, err)
	}
}

func TestAPreviewStopsWhenTheClientDoes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() {
		_, _ = pw.Write([]byte("a"))
		cancel()
	}()
	if _, _, _, err := preview(ctx, pr); err == nil {
		t.Fatal("no error when the client went")
	}
}

// From the start, a stream that sends nothing at all is previewed empty once
// it has been idle -- ssh's stdin, held open and silent -- and what it sends
// later still follows in the rest.
func TestAPreviewFromTheStartEndsOnAStreamThatNeverSends(t *testing.T) {
	pr, pw := io.Pipe()
	head, more, rest, err := Preview(context.Background(), pr, 20*time.Millisecond, true)
	if err != nil || len(head) != 0 || !more {
		t.Fatalf("head %q, more %v, %v", head, more, err)
	}
	go func() {
		_, _ = pw.Write([]byte("late"))
		_ = pw.Close()
	}()
	if b, err := io.ReadAll(rest); err != nil || string(b) != "late" {
		t.Fatalf("rest %q, %v", b, err)
	}
}
