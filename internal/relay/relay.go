// Package relay carries a session's connections to its Docker project's
// ports on to the project's own address on the host. The session's ruleset
// steers 127.0.0.1:P, [::1]:P and the project's address at P to frisket's
// TCP listener, for each of the project's ports P; this is what serves them
// there.
//
// It relays only to the project's address, at the port the connection was
// steered for, and only while the daemon reports a running container of the
// project publishing exactly that address and port. What answers on the
// host at <address>:P is decided by the host's sockets, not by the steering:
// a host Postgres on *:5432, a dev server, or another session's pasta
// republishing its own listener as *:P would all take the dial when the
// project's container is down. The daemon's word that its container holds
// the exact bind is what makes the dial reach the container, since an exact
// bind outranks every wildcard.
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/danielbodart/frisket/internal/dockerapi"
	"github.com/danielbodart/frisket/internal/egress"
	"github.com/danielbodart/frisket/internal/steer"
)

// What the relay line says happened, as egress's line says it: refused is
// frisket saying no, failed is the host not answering.
const (
	DecisionRelayed = "relayed"
	DecisionRefused = "refused"
	DecisionFailed  = "failed"
)

// Why a connection was not relayed.
const (
	// ReasonNotAPort is a port the session's document does not name: one it
	// named before a restore, whose ruleset still steers it.
	ReasonNotAPort = "not a docker port"
	// ReasonNotPublished is a daemon that reports no running container of
	// the project publishing the port on the project's address.
	ReasonNotPublished = "no owned container publishes it"
	// ReasonLookup is a daemon that could not say.
	ReasonLookup = "daemon lookup failed"
	// ReasonDial is a check that passed and a dial that did not.
	ReasonDial = "dial failed"
)

const (
	// dialTimeout bounds the dial to the project's address.
	dialTimeout = 5 * time.Second
	// lookupTimeout and maxLookup are the route's own bounds on a question
	// to the daemon: 10 seconds, and 4 MiB of answer.
	lookupTimeout = 10 * time.Second
	maxLookup     = 4 << 20
	// lookupAgent says, in the daemon's own log, that frisket was asking.
	lookupAgent = "frisket"
)

var idRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Handler relays one session's steered connections to its Docker project's
// ports. Every field is fixed by the session's policy document when its
// handlers are built.
type Handler struct {
	// Transport is the Docker route's own transport to the daemon's socket.
	// The ownership check goes through it and nothing else.
	Transport http.RoundTripper
	// APIVersion is the route's highest, "1.NN", which the check asks at.
	APIVersion string
	// Project is the owner/repo whose containers the session may reach.
	Project string
	// Address is the project's loopback address on the host: the only
	// address a connection is ever relayed to.
	Address netip.Addr
	// Ports are the ports the document names. A steered port not among them
	// is refused.
	Ports []uint16
	// Log is the session's; it gets one line per connection.
	Log *slog.Logger
	// Idle is the splice's idle limit, and zero is none: a database pool
	// keeps connections idle for longer than egress.DefaultIdle, and
	// Docker's own publish never cuts them. The session's close still ends
	// a relayed connection, and its connection cap bounds how many are held.
	Idle time.Duration

	// splice is egress.Splice when nil; a test sets it to see the idle
	// limit a relayed connection is handed.
	splice func(ctx context.Context, client, upstream *net.TCPConn, idle time.Duration) egress.SpliceResult
}

var _ steer.Handler = (*Handler)(nil)

// Steers is whether orig is for the relay: 127.0.0.1, ::1 or the project's
// address, compared as addresses rather than spellings, at any port. The
// port is the handler's to judge, so that one the document no longer names
// is refused with a line rather than sent to egress.
func (h *Handler) Steers(orig netip.AddrPort) bool {
	a := orig.Addr().Unmap().WithZone("")
	return a == netip.AddrFrom4([4]byte{127, 0, 0, 1}) || a == netip.IPv6Loopback() || a == h.Address.Unmap().WithZone("")
}

// ServeConn owns c and closes it.
func (h *Handler) ServeConn(ctx context.Context, c *steer.Conn) {
	start := time.Now()
	port := c.Orig.Port()
	to := netip.AddrPortFrom(h.Address, port)
	line := relayLine{conn: c, to: to}

	if !slices.Contains(h.Ports, port) {
		line.decision, line.reason = DecisionRefused, ReasonNotAPort
		h.refuse(c, line, start)
		return
	}
	if err := h.published(ctx, port); err != nil {
		line.decision, line.reason = DecisionRefused, ReasonNotPublished
		var lf *lookupError
		if errors.As(err, &lf) {
			line.reason, line.err = ReasonLookup, err
		}
		h.refuse(c, line, start)
		return
	}

	// Its own dialer, over IPv4 from the host's namespace. Never egress's,
	// whose classifier refuses loopback, and nothing but a destination fixed
	// here ever reaches this one.
	d := net.Dialer{Timeout: dialTimeout}
	nc, err := d.DialContext(ctx, "tcp4", to.String())
	if err != nil {
		line.decision, line.reason, line.err = DecisionFailed, ReasonDial, err
		h.refuse(c, line, start)
		return
	}
	up := nc.(*net.TCPConn)
	defer up.Close()
	defer c.Close()

	line.decision = DecisionRelayed
	splice := h.splice
	if splice == nil {
		splice = egress.Splice
	}
	line.splice = splice(ctx, c.TCPConn, up, h.Idle)
	line.err = line.splice.Err
	h.log(line, start)
}

// refuse answers the client as a closed port would, with a reset, and logs.
func (h *Handler) refuse(c *steer.Conn, line relayLine, start time.Time) {
	_ = c.SetLinger(0)
	_ = c.Close()
	h.log(line, start)
}

// lookupError is a daemon that could not say whether the port is published.
type lookupError struct{ why string }

func (e *lookupError) Error() string { return "daemon lookup failed: " + e.why }

// container is as much of one listed container as the check reads.
type container struct {
	ID     string `json:"Id"`
	Labels map[string]string
	State  string
	Ports  []struct {
		IP         string
		PublicPort int
		Type       string
	}
}

// published asks the daemon whether a running container of the project
// publishes port on the project's address, over TCP. The filters narrow the
// daemon's answer; every condition is checked here again, on what it
// answered, so the relay does not rest on the daemon honouring them.
func (h *Handler) published(ctx context.Context, port uint16) error {
	filters, err := json.Marshal(map[string][]string{
		"label":   {dockerapi.LabelKey + "=" + h.Project},
		"publish": {strconv.Itoa(int(port)) + "/tcp"},
		"status":  {"running"},
	})
	if err != nil {
		return &lookupError{"no filters"}
	}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	target := "http://docker/v" + h.APIVersion + "/containers/json?" + url.Values{"filters": {string(filters)}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return &lookupError{"no request"}
	}
	req.Header.Set("User-Agent", lookupAgent)
	client := http.Client{
		Transport: h.Transport,
		// A redirect is an answer frisket does not take.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       lookupTimeout,
	}
	res, err := client.Do(req)
	if err != nil {
		// The transport's own error, never the URL around it.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return &lookupError{err.Error()}
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxLookup+1))
	switch {
	case err != nil:
		return &lookupError{"answer unread"}
	case len(body) > maxLookup:
		return &lookupError{fmt.Sprintf("answer over %d bytes", maxLookup)}
	case res.StatusCode != http.StatusOK:
		return &lookupError{fmt.Sprintf("status %d", res.StatusCode)}
	}
	var list []container
	if err := json.Unmarshal(body, &list); err != nil {
		return &lookupError{"not the daemon's JSON"}
	}
	for _, c := range list {
		if !idRE.MatchString(c.ID) {
			return &lookupError{"no ID"}
		}
		if c.Labels[dockerapi.LabelKey] != h.Project || c.State != "running" {
			continue
		}
		for _, p := range c.Ports {
			ip, err := netip.ParseAddr(p.IP)
			if err == nil && ip.Unmap() == h.Address.Unmap() && p.PublicPort == int(port) && p.Type == "tcp" {
				return nil
			}
		}
	}
	return errors.New(ReasonNotPublished)
}

type relayLine struct {
	conn     *steer.Conn
	to       netip.AddrPort
	decision string
	reason   string
	splice   egress.SpliceResult
	err      error
}

// log writes the connection's one line, in egress's shape, so one query over
// the journal finds both.
func (h *Handler) log(l relayLine, start time.Time) {
	attrs := []any{
		"session", l.conn.Session,
		"conn", l.conn.ID,
		"peer", l.conn.Peer.String(),
		"orig", l.conn.Orig.String(),
		"to", l.to.String(),
		"project", h.Project,
		"decision", l.decision,
	}
	if l.reason != "" {
		attrs = append(attrs, "reason", l.reason)
	}
	attrs = append(attrs,
		"out", l.splice.Out,
		"in", l.splice.In,
		"idle", l.splice.Idle,
		// Milliseconds, as egress's duration_ms.
		"duration", float64(time.Since(start).Microseconds())/1000,
	)
	if l.err != nil {
		attrs = append(attrs, "error", l.err.Error())
	}
	h.Log.Info("relay", attrs...)
}
