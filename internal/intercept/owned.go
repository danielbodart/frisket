package intercept

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danielbodart/frisket/internal/docker"
)

// Refusals of what a request names, as the log and the client read them.
const (
	// ReasonNotOwned is an object the daemon has that does not carry this
	// project's label.
	ReasonNotOwned = "not this project's"
	// ReasonAbsent is an object that does not exist: the daemon's own 404
	// for what a path names, and a refusal for what a body names, since the
	// daemon would make an absent volume without the label.
	ReasonAbsent = "no such object"
	// ReasonLookup is a daemon that could not say whose an object is. 502:
	// frisket could not act, and nothing it could not check goes.
	ReasonLookup = "daemon lookup failed"
)

const (
	// lookupTimeout bounds one question to the daemon.
	lookupTimeout = 10 * time.Second
	// maxLookup bounds what the daemon's answer may be.
	maxLookup = 4 << 20
	// maxAbsent bounds the daemon's own 404, which the client is given.
	maxAbsent = 64 << 10
	// lookupAgent says, in the daemon's own log, which requests were
	// frisket asking rather than a client acting.
	lookupAgent = "frisket"
	// anonymousLabel is what the daemon labels a volume it named itself.
	anonymousLabel = "com.docker.volume.anonymous"
)

// facts are the whole of what frisket reads of the daemon's answer about an
// object: its ID, its labels -- a container's under Config -- and, for an
// exec, its container's ID. Nothing else is decoded.
type facts struct {
	ID     string `json:"Id"`
	Config *struct {
		Labels map[string]string
	}
	Labels      map[string]string
	ContainerID string
}

// listed is one container of a list, as far as an anonymous volume's check
// reads it.
type listed struct {
	ID     string `json:"Id"`
	Labels map[string]string
	Mounts []struct {
		Type, Name string
	}
}

// answer is a response frisket gives in the daemon's place, which the
// daemon gave it: the 404 for an object a path names that does not exist.
type answer struct {
	status      int
	contentType string
	body        []byte
}

func (a *answer) write(w http.ResponseWriter) {
	if a.contentType != "" {
		w.Header().Set("Content-Type", a.contentType)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(a.status)
	_, _ = w.Write(a.body)
}

// objectRefusal is why an object a request names is not acted on: its
// reason and status, what the log says, and, for an absent one named by the
// path, the daemon's own answer to give instead.
type objectRefusal struct {
	reason  string
	status  int
	account string
	answer  *answer
}

func (e *objectRefusal) Error() string { return e.reason }

func notOwned(account string) error {
	return &objectRefusal{reason: ReasonNotOwned, status: http.StatusForbidden, account: account + " not this project's"}
}

func absent(account string, a *answer) error {
	return &objectRefusal{reason: ReasonAbsent, status: http.StatusForbidden, account: account + " absent", answer: a}
}

func lookupFailed(account, why string) error {
	return &objectRefusal{reason: ReasonLookup, status: http.StatusBadGateway, account: account + " lookup failed: " + why}
}

// claim is one request's dealings with the daemon: the names it holds, and
// what it has already been told, so that nothing is asked twice.
type claim struct {
	route *dockerRoute
	ctx   context.Context
	held  []func()
	// seen is each answer by the path it was asked at: the facts, or the
	// refusal it came to.
	seen map[string]asked
}

type asked struct {
	facts  *facts
	answer *answer
	err    error
}

func (d *dockerRoute) claim(ctx context.Context) *claim {
	return &claim{route: d, ctx: ctx, seen: map[string]asked{}}
}

// release lets go of every name the request holds.
func (c *claim) release() {
	for _, let := range slices.Backward(c.held) {
		let()
	}
	c.held = nil
}

// lock takes every name, in order, so that two requests that each need two
// never wait on each other.
func (c *claim) lock(keys []nameKey) error {
	slices.SortFunc(keys, func(a, b nameKey) int {
		return strings.Compare(a.kind+"\x00"+a.name, b.kind+"\x00"+b.name)
	})
	for _, k := range slices.Compact(keys) {
		let, err := heldNames.take(c.ctx, k)
		if err != nil {
			return err
		}
		c.held = append(c.held, let)
	}
	return nil
}

// ask is the daemon's facts about the object at p, a path after the
// version: found, absent with the daemon's own 404, or a refusal.
func (c *claim) ask(p, account string) (*facts, *answer, error) {
	if a, ok := c.seen[p]; ok {
		return a.facts, a.answer, a.err
	}
	var f facts
	body, a, err := c.get(p, account)
	if err == nil && a == nil {
		if json.Unmarshal(body, &f) != nil {
			err = lookupFailed(account, "not the daemon's JSON")
		}
	}
	res := asked{answer: a, err: err}
	if err == nil && a == nil {
		res.facts = &f
	}
	c.seen[p] = res
	return res.facts, res.answer, res.err
}

// get asks the daemon, at its highest version the route speaks, over the
// route's own socket. A 200 is its body; a 404 is its own answer, bounded,
// to give the client; anything else is a refusal.
func (c *claim) get(p, account string) ([]byte, *answer, error) {
	ctx, cancel := context.WithTimeout(c.ctx, lookupTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v"+c.route.APIVersions.Max+p, nil)
	if err != nil {
		return nil, nil, lookupFailed(account, "no request")
	}
	req.Header.Set("User-Agent", lookupAgent)
	res, err := c.route.lookups.Do(req)
	if err != nil {
		// The transport's own error, never the URL around it, which is
		// what the request named.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, nil, lookupFailed(account, err.Error())
	}
	defer func() { _ = res.Body.Close() }()
	bound := maxLookup
	if res.StatusCode == http.StatusNotFound {
		bound = maxAbsent
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, int64(bound)+1))
	switch {
	case err != nil:
		return nil, nil, lookupFailed(account, "answer unread")
	case len(body) > bound:
		return nil, nil, lookupFailed(account, fmt.Sprintf("answer over %d bytes", bound))
	}
	switch res.StatusCode {
	case http.StatusOK:
		return body, nil, nil
	case http.StatusNotFound:
		a := &answer{status: http.StatusNotFound, body: body}
		if ct := res.Header.Get("Content-Type"); ct != "" {
			if _, _, err := mime.ParseMediaType(ct); err == nil {
				a.contentType = ct
			}
		}
		return nil, a, nil
	}
	return nil, nil, lookupFailed(account, fmt.Sprintf("status %d", res.StatusCode))
}

// owns is whether labels carry this project's.
func (c *claim) owns(labels map[string]string) bool {
	v, ok := labels[docker.LabelKey]
	return ok && v == c.route.Project
}

// path answers for the object a path's segment names, and gives what to
// forward in its place: a container's or network's full ID, which cannot
// come to name another object between the check and the act; a volume's
// name, which is held; an exec's ID, which is already whole.
func (c *claim) path(kind, seg string) (forward, account string, err error) {
	name := kind + "=" + seg
	switch kind {
	case "container":
		id, err := c.container(seg, name)
		if err != nil {
			return "", "", err
		}
		return id, "container=" + short(id) + " owned", nil
	case "exec":
		f, a, err := c.ask("/exec/"+url.PathEscape(seg)+"/json", "exec="+short(seg))
		switch {
		case err != nil:
			return "", "", err
		case a != nil:
			return "", "", absent("exec="+short(seg), a)
		case !execSegRE.MatchString(f.ContainerID):
			return "", "", lookupFailed("exec="+short(seg), "no container ID")
		}
		id, err := c.container(f.ContainerID, "exec="+short(seg)+" container="+short(f.ContainerID))
		if err != nil {
			return "", "", err
		}
		return seg, "exec=" + short(seg) + " container=" + short(id) + " owned", nil
	case "volume":
		f, a, err := c.ask("/volumes/"+url.PathEscape(seg), name)
		switch {
		case err != nil:
			return "", "", err
		case a != nil:
			return "", "", absent(name, a)
		case !c.owns(f.Labels):
			return "", "", notOwned(name)
		}
		return seg, name + " owned", nil
	case "network":
		f, a, err := c.ask("/networks/"+url.PathEscape(seg), name)
		switch {
		case err != nil:
			return "", "", err
		case a != nil:
			return "", "", absent(name, a)
		case !execSegRE.MatchString(f.ID):
			return "", "", lookupFailed(name, "no ID")
		case !c.owns(f.Labels):
			return "", "", notOwned(name)
		}
		return f.ID, "network=" + short(f.ID) + " owned", nil
	}
	return "", "", &objectRefusal{reason: reasonUndecided, status: http.StatusForbidden}
}

// container is the full ID of an owned container, by any name the daemon
// knows it by.
func (c *claim) container(ref, account string) (string, error) {
	f, a, err := c.ask("/containers/"+url.PathEscape(ref)+"/json", account)
	switch {
	case err != nil:
		return "", err
	case a != nil:
		return "", absent(account, a)
	case !execSegRE.MatchString(f.ID):
		return "", lookupFailed(account, "no ID")
	case f.Config == nil || !c.owns(f.Config.Labels):
		return "", notOwned(account)
	}
	return f.ID, nil
}

// body answers for each name a body holds, by what the body does with it,
// and gives the full ID of each network it attaches to, by its name, for
// the body to name it by upstream.
func (c *claim) body(lookups []docker.Lookup) (account []string, networks map[string]string, err error) {
	networks = map[string]string{}
	for _, l := range lookups {
		acct, id, err := c.named(l)
		if err != nil {
			return account, nil, err
		}
		account = append(account, acct)
		if id != "" {
			networks[l.Name] = id
		}
	}
	return account, networks, nil
}

// named answers for one name a body holds, and gives, for a network it
// attaches to, that network's full ID.
func (c *claim) named(l docker.Lookup) (account, id string, err error) {
	switch {
	case l.Kind == "network" && l.Use == docker.Create:
		// Held, and nothing to ask: the daemon refuses a network's name
		// twice, and what it makes is stamped.
		return "network=" + l.Name + " held", "", nil
	case l.Kind == "network" && l.Use == docker.Attach:
		name := "network " + l.Name
		f, a, err := c.ask("/networks/"+url.PathEscape(l.Name), name)
		switch {
		case err != nil:
			return "", "", err
		case a != nil:
			return "", "", absent(name, nil)
		case !execSegRE.MatchString(f.ID):
			return "", "", lookupFailed(name, "no ID")
		case !c.owns(f.Labels):
			return "", "", notOwned(name)
		}
		return name + " owned as " + short(f.ID), f.ID, nil
	case l.Kind != "volume":
		return "", "", &objectRefusal{reason: reasonUndecided, status: http.StatusForbidden, account: l.Kind + " " + l.Name + " unknown"}
	}
	account, err = c.volume(l)
	return account, "", err
}

// volume answers for a volume a body names.
func (c *claim) volume(l docker.Lookup) (string, error) {
	name := map[docker.Use]string{docker.Bind: "bind ", docker.Mount: "mount ", docker.Create: "volume="}[l.Use] + l.Name
	f, a, err := c.ask("/volumes/"+url.PathEscape(l.Name), name)
	switch {
	case err != nil:
		return "", err
	case a != nil && l.Use == docker.Create:
		// Made by this request, and stamped.
		return name + " absent", nil
	case a != nil:
		// The daemon would make it, and without the label.
		return "", absent(name, nil)
	case c.owns(f.Labels):
		return name + " owned", nil
	case l.Use != docker.Mount:
		return "", notOwned(name)
	}
	// A volume the daemon named itself, which Compose carries over when it
	// recreates a container: this project's only if one of its own
	// containers mounts it.
	if _, anon := f.Labels[anonymousLabel]; !anon {
		return "", notOwned(name)
	}
	ok, err := c.mountedByOwn(l.Name, name)
	switch {
	case err != nil:
		return "", err
	case !ok:
		return "", notOwned(name)
	}
	return name + " anonymous, mounted by this project's", nil
}

// mountedByOwn is whether a container with this project's label mounts the
// volume, as the daemon lists them. The list's filters are the daemon's to
// apply, and each container it returns is checked again here.
func (c *claim) mountedByOwn(volume, account string) (bool, error) {
	filters, err := json.Marshal(map[string][]string{
		"label":  {docker.LabelKey + "=" + c.route.Project},
		"volume": {volume},
	})
	if err != nil {
		return false, lookupFailed(account, "no filters")
	}
	q := url.Values{"all": {"1"}, "filters": {string(filters)}}
	body, a, err := c.get("/containers/json?"+q.Encode(), account)
	if err != nil {
		return false, err
	}
	if a != nil {
		return false, lookupFailed(account, "status 404")
	}
	var list []listed
	if json.Unmarshal(body, &list) != nil {
		return false, lookupFailed(account, "not the daemon's JSON")
	}
	for _, ct := range list {
		if !execSegRE.MatchString(ct.ID) || !c.owns(ct.Labels) {
			continue
		}
		for _, m := range ct.Mounts {
			if m.Type == "volume" && m.Name == volume {
				return true, nil
			}
		}
	}
	return false, nil
}

// short is an ID as the log shows it, as the daemon's own CLI does.
func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// nameKey is a name on one daemon.
type nameKey struct {
	socket, kind, name string
}

// nameLocks are the names requests hold, across every session: they all
// reach the daemon through this one process, so a name checked by one
// request cannot be deleted or made by another before the first acts on it.
type nameLocks struct {
	mu   sync.Mutex
	held map[nameKey]*nameLock
}

// nameLock is a name's turn, and how many hold or wait for it.
type nameLock struct {
	turn chan struct{}
	refs int
}

var heldNames = &nameLocks{held: map[nameKey]*nameLock{}}

// take waits for the name's turn, or for the request to be given up, and
// returns what lets it go.
func (n *nameLocks) take(ctx context.Context, k nameKey) (func(), error) {
	n.mu.Lock()
	l := n.held[k]
	if l == nil {
		l = &nameLock{turn: make(chan struct{}, 1)}
		n.held[k] = l
	}
	l.refs++
	n.mu.Unlock()
	select {
	case l.turn <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() {
				<-l.turn
				n.drop(k, l)
			})
		}, nil
	case <-ctx.Done():
		n.drop(k, l)
		return nil, ctx.Err()
	}
}

func (n *nameLocks) drop(k nameKey, l *nameLock) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if l.refs--; l.refs == 0 {
		delete(n.held, k)
	}
}

// waiting is how many requests hold or wait for a name.
func (n *nameLocks) waiting(k nameKey) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	if l := n.held[k]; l != nil {
		return l.refs
	}
	return 0
}
