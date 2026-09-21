package intercept

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
)

// RefusalMessage is where a Refusal's body takes frisket's message.
const RefusalMessage = "{{message}}"

// Refusal is how a route says no in its API's own error shape, so a client
// that reads that shape says why rather than that something failed: wrangler
// prints the message of a Cloudflare error envelope, and nothing of a plain
// text one. The status is frisket's either way.
//
// The message is frisket's own -- its reason, and the name of the operation
// the request matched, from the configuration -- and never anything the
// request carried.
type Refusal struct {
	ContentType string
	// Body holds RefusalMessage exactly once. For a JSON content type the
	// message goes in escaped as the inside of a JSON string, so the
	// placeholder belongs inside one.
	Body string
}

// refusalShape is a Refusal checked once, when the route is built. Nil is plain
// text.
type refusalShape struct {
	contentType   string
	before, after string
	json          bool
}

func compileRefusal(r *Refusal) (*refusalShape, error) {
	if r == nil {
		return nil, nil
	}
	media, _, err := mime.ParseMediaType(r.ContentType)
	if err != nil {
		return nil, fmt.Errorf("refusal content type %q: %w", r.ContentType, err)
	}
	if strings.Count(r.Body, RefusalMessage) != 1 {
		return nil, fmt.Errorf("refusal body holds %s %d times, not once", RefusalMessage, strings.Count(r.Body, RefusalMessage))
	}
	before, after, _ := strings.Cut(r.Body, RefusalMessage)
	c := &refusalShape{
		contentType: r.ContentType,
		before:      before,
		after:       after,
		json:        media == "application/json" || strings.HasSuffix(media, "+json"),
	}
	// A body that is not JSON with a message in it would be a refusal the
	// client cannot read either -- which is the whole of what this is for.
	if c.json && !json.Valid([]byte(c.fill(`a "quoted" message`))) {
		return nil, errors.New("refusal body is not JSON once the message is in it: the placeholder belongs inside a JSON string")
	}
	return c, nil
}

func (c *refusalShape) fill(message string) string {
	if c.json {
		b, _ := json.Marshal(message)
		message = string(b[1 : len(b)-1])
	}
	return c.before + message + c.after
}

// refuse answers a request frisket will not send on: with the route's own
// error shape if it has one, plain text otherwise.
func (rt *route) refuse(w http.ResponseWriter, status int, reason string, op *Operation) {
	message := "frisket: refused: " + reason
	if op != nil {
		message += " (" + op.Summary + ")"
	}
	w.Header().Set("Cache-Control", "no-store")
	if rt.refusal == nil {
		http.Error(w, message, status)
		return
	}
	w.Header().Set("Content-Type", rt.refusal.contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(rt.refusal.fill(message)))
}
