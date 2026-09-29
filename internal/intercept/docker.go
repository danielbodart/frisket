package intercept

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielbodart/frisket/internal/docker"
)

// DockerRoute makes a route a Docker Engine's: its upstream is the daemon's
// unix socket, dialled by the route's own transport and nothing else, and
// every request is held to the rule it matched, which only ever narrows what
// the daemon is asked (PLAN.md, decision 13's carve-out). It is the whole of
// what the route knows of the project: the host decided every field of it.
type DockerRoute struct {
	// Project is the owner/repo whose objects this route acts on, as the host
	// derived it from the checkout's remote.
	Project string
	// APIVersions are the versions a request's /v1.NN may name, and the
	// paths that may be asked with none.
	APIVersions APIVersions
	// Images are the references a container may run and a pull may fetch,
	// each by its exact string.
	Images []string
	// Address is the project's loopback address, and must be
	// docker.Address(Project).
	Address netip.Addr
	// Ports are the host ports its containers may publish.
	Ports []uint16
	// Names are what the address is known by, and must be
	// docker.Names(Project).
	Names []string
	// MaxBody bounds a JSON body.
	MaxBody int64
	// Bodies are the tables a rule's body is judged by, by their operation.
	Bodies map[string]*docker.Table
}

// APIVersions are "1.NN", Min to Max; Unversioned are paths, exactly, that
// need no version.
type APIVersions struct {
	Min, Max    string
	Unversioned []string
}

// DockerRule is what an admitting rule on a Docker route checks before a
// request goes: what it acts on, the query it may have, the body it must
// have, and the protocol it may switch to.
type DockerRule struct {
	// Owned is what the request acts on, which fixes in frisket's code what
	// is checked and rewritten: none, container, exec, volume, network,
	// image, imagePull, list, createContainer, createVolume or
	// createNetwork.
	Owned string
	// Param is the index of the "*" naming the object, in the segments after
	// the version.
	Param int
	// Query are the only keys the query may have, each once. Nil: no query.
	Query map[string]QueryCheck
	// Body is the table the body is judged by. Empty: there must be no body.
	Body string
	// Upgrade is the one protocol the request may switch to, "tcp". Empty:
	// none.
	Upgrade string
}

// QueryCheck judges one query value: any, bool, int, containerName,
// filters, imageName, imageTag or enum.
type QueryCheck struct {
	Check string
	// Filters are the keys a list's filters may use.
	Filters []string
	// Enum are the values an enum allows.
	Enum []string
}

// Refusal reasons on a Docker route, as the log and the client read them.
const (
	ReasonAPIVersion  = "api version not allowed"
	ReasonUnversioned = "unversioned request"
	ReasonHTTP11Only  = "HTTP/1.1 only"
	ReasonNoBody      = "body on an operation that takes none"
	ReasonUpgrade     = "upgrade not allowed"
	ReasonImage       = "image not listed"
	ReasonParam       = "not a name"
	// ReasonUnasked is a request that needs the daemon asked who owns what it
	// names, which nothing here yet asks: refused, never let through
	// unchecked.
	ReasonUnasked = "ownership not checked"
	// reasonUndecided is an admitting rule whose checks never ran.
	reasonUndecided = "docker request unchecked"
)

var ownedKinds = []string{"none", "container", "exec", "volume", "network", "image", "imagePull", "list",
	"createContainer", "createVolume", "createNetwork"}

// withParam are the kinds whose object is named by a path segment.
var withParam = []string{"container", "exec", "volume", "network", "image"}

// creates pairs each kind that creates an object with the one table that
// judges its body, both ways: the table's name is what stamps the label.
var creates = map[string]string{
	"createContainer": "ContainerCreate",
	"createVolume":    "VolumeCreate",
	"createNetwork":   "NetworkCreate",
}

var queryChecks = []string{"any", "bool", "int", "containerName", "filters", "imageName", "imageTag", "enum"}

var (
	projectRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9._-]{1,100}$`)
	versionRE  = regexp.MustCompile(`^1\.(0|[1-9][0-9]*)$`)
	versionish = regexp.MustCompile(`^v[0-9.]*$`)
	versionSeg = regexp.MustCompile(`^v1\.(0|[1-9][0-9]*)$`)
	nameSegRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
	execSegRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	intRE      = regexp.MustCompile(`^-?[0-9]{1,10}$`)
	contNameRE = regexp.MustCompile(`^/?[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
	contHexRE  = regexp.MustCompile(`^/?[0-9a-f]+$`)
)

const (
	// maxDockerPorts bounds the ports a project may publish.
	maxDockerPorts = 64
	// maxDockerBody bounds what a route's maxBody may be.
	maxDockerBody = 1 << 20
)

// validateDocker holds a Docker route to the whole of section 1.1: a unix
// socket and nothing else as its upstream, no credential on a hop that is
// plain HTTP, and rules that each say what they check.
func (r *Route) validateDocker(u *url.URL, wild bool) error {
	d := r.Docker
	if d == nil {
		return fmt.Errorf("route %s: a unix upstream is only a Docker route's", r.Name)
	}
	if u.Scheme != "unix" || u.Opaque != "" || u.Host != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || strings.Contains(r.Upstream, "%") || !path.IsAbs(u.Path) || path.Clean(u.Path) != u.Path {
		return fmt.Errorf("route %s: upstream %q must be unix:// and an absolute, clean path", r.Name, r.Upstream)
	}
	if wild {
		return fmt.Errorf("route %s: a Docker route is for one name", r.Name)
	}
	if r.Credential != nil || r.Inject != nil || r.Placeholder != "" || r.SessionKey != nil || r.UpstreamCAs != nil {
		return fmt.Errorf("route %s: a Docker route's hop is plain HTTP, so it carries no credential and verifies no CA", r.Name)
	}
	s := r.Scope
	if s.Unmatched != UnmatchedRefuse || s.Git != nil || len(s.GraphQL) > 0 || s.GitHubAPI != nil {
		return fmt.Errorf("route %s: a Docker route has path rules only, and refuses what they do not match", r.Name)
	}
	if !projectRE.MatchString(d.Project) || strings.HasSuffix(d.Project, "/.") || strings.HasSuffix(d.Project, "/..") {
		return fmt.Errorf("route %s: project %q is not owner/repo", r.Name, d.Project)
	}
	lo, err := apiMinor(d.APIVersions.Min)
	if err != nil {
		return fmt.Errorf("route %s: apiVersions.min: %w", r.Name, err)
	}
	hi, err := apiMinor(d.APIVersions.Max)
	if err != nil {
		return fmt.Errorf("route %s: apiVersions.max: %w", r.Name, err)
	}
	if lo > hi {
		return fmt.Errorf("route %s: apiVersions.min %s is above max %s", r.Name, d.APIVersions.Min, d.APIVersions.Max)
	}
	for _, p := range d.APIVersions.Unversioned {
		if segs, err := splitPath(p); err != nil || strings.ContainsAny(p, "%?#") || versionish.MatchString(fold(segs[0])) {
			return fmt.Errorf("route %s: unversioned path %q is not a plain path", r.Name, p)
		}
	}
	if len(d.Images) == 0 {
		return fmt.Errorf("route %s: no images, and a container runs one", r.Name)
	}
	for _, img := range d.Images {
		if err := docker.ValidImage(img); err != nil {
			return fmt.Errorf("route %s: image %q: %w", r.Name, img, err)
		}
	}
	if want := docker.Address(d.Project); d.Address != want {
		return fmt.Errorf("route %s: address %s is not %s, the project's own", r.Name, d.Address, want)
	}
	if len(d.Ports) > maxDockerPorts {
		return fmt.Errorf("route %s: %d ports, and a project has at most %d", r.Name, len(d.Ports), maxDockerPorts)
	}
	for i, p := range d.Ports {
		if p < 1024 {
			return fmt.Errorf("route %s: port %d is below 1024", r.Name, p)
		}
		if slices.Contains(d.Ports[:i], p) {
			return fmt.Errorf("route %s: port %d twice", r.Name, p)
		}
	}
	if want := docker.Names(d.Project); !slices.Equal(d.Names, want) {
		return fmt.Errorf("route %s: names %q are not %q, the project's own", r.Name, d.Names, want)
	}
	if d.MaxBody < 1 || d.MaxBody > maxDockerBody {
		return fmt.Errorf("route %s: maxBody %d is not between 1 and %d", r.Name, d.MaxBody, maxDockerBody)
	}
	for name, t := range d.Bodies {
		if t == nil || t.Name() != name {
			return fmt.Errorf("route %s: body table %s is not the table compiled for it", r.Name, name)
		}
	}
	for _, p := range s.Paths {
		if err := d.validateRule(p); err != nil {
			return fmt.Errorf("route %s: %w", r.Name, err)
		}
	}
	return nil
}

// validateRule holds one rule on a Docker route to what it must say.
func (d *DockerRoute) validateRule(p PathRule) error {
	written := p.Path + p.Prefix
	switch {
	case p.Operation == nil:
		return fmt.Errorf("path rule %q has no operation, and every rule on a Docker route names one", written)
	case p.Ask:
		return fmt.Errorf("path rule %q asks, and nothing on a Docker route is asked about", written)
	case p.Refuse && p.Docker != nil:
		return fmt.Errorf("path rule %q refuses, and has nothing for a docker block to check", written)
	case p.Refuse:
		return nil
	case p.Docker == nil:
		return fmt.Errorf("path rule %q admits with no docker block, which is what says what it checks", written)
	case p.Path == "":
		return fmt.Errorf("path rule %q admits a prefix, and a Docker rule is one operation's exact path", written)
	}
	rule := p.Docker
	if !slices.Contains(ownedKinds, rule.Owned) {
		return fmt.Errorf("path rule %q: owned %q is not one frisket knows", written, rule.Owned)
	}
	if slices.Contains(withParam, rule.Owned) {
		segs := strings.Split(p.Path[1:], "/")
		if rule.Param < 0 || rule.Param >= len(segs) || segs[rule.Param] != wildcard {
			return fmt.Errorf("path rule %q: param %d is not a * of it", written, rule.Param)
		}
	} else if rule.Param != 0 {
		return fmt.Errorf("path rule %q: owned %s names no object by its path, so no param", written, rule.Owned)
	}
	if rule.Upgrade != "" && rule.Upgrade != "tcp" {
		return fmt.Errorf("path rule %q: upgrade %q: tcp or none", written, rule.Upgrade)
	}
	if rule.Body != "" {
		if _, ok := d.Bodies[rule.Body]; !ok {
			return fmt.Errorf("path rule %q: body %s is not among the route's tables", written, rule.Body)
		}
	}
	for owned, table := range creates {
		if (rule.Owned == owned) != (rule.Body == table) {
			return fmt.Errorf("path rule %q: owned %s and body %q: %s is judged by %s, and only it", written, rule.Owned, rule.Body, owned, table)
		}
	}
	for key, c := range rule.Query {
		if err := validateQueryCheck(rule.Owned, key, c); err != nil {
			return fmt.Errorf("path rule %q: query %q: %w", written, key, err)
		}
	}
	switch rule.Owned {
	case "list":
		if rule.Query["filters"].Check != "filters" {
			return fmt.Errorf("path rule %q: a list's filters are where the project's label goes, so it checks them", written)
		}
	case "imagePull":
		if rule.Query["fromImage"].Check != "imageName" {
			return fmt.Errorf("path rule %q: a pull's fromImage is its image, so it checks it", written)
		}
	}
	return nil
}

func validateQueryCheck(owned, key string, c QueryCheck) error {
	switch {
	case key == "":
		return errors.New("an empty key")
	case !slices.Contains(queryChecks, c.Check):
		return fmt.Errorf("check %q is not one frisket knows", c.Check)
	case (c.Check == "filters") != (len(c.Filters) > 0):
		return errors.New("filters, and only filters, lists filter keys")
	case (c.Check == "enum") != (len(c.Enum) > 0):
		return errors.New("an enum, and only an enum, lists values")
	case c.Check == "filters" && (owned != "list" || key != "filters"):
		return errors.New("a filters check is a list's filters")
	case c.Check == "imageName" && (owned != "imagePull" || key != "fromImage"):
		return errors.New("an imageName check is a pull's fromImage")
	case c.Check == "imageTag" && (owned != "imagePull" || key != "tag"):
		return errors.New("an imageTag check is a pull's tag")
	}
	return nil
}

// apiMinor is the NN of a version "1.NN".
func apiMinor(v string) (int, error) {
	m := versionRE.FindStringSubmatch(v)
	if m == nil {
		return 0, fmt.Errorf("%q is not 1.NN", v)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("%q is not 1.NN", v)
	}
	return n, nil
}

// dockerRoute is a DockerRoute checked, with what serving it needs.
type dockerRoute struct {
	DockerRoute
	min, max int
	// socket is the daemon's, and target what a request is addressed to on
	// it.
	socket string
	target *url.URL
	// objects is who is asked about what a request names before it goes.
	objects objects
}

func newDockerRoute(d DockerRoute, socket string) *dockerRoute {
	lo, _ := apiMinor(d.APIVersions.Min)
	hi, _ := apiMinor(d.APIVersions.Max)
	return &dockerRoute{
		DockerRoute: d,
		min:         lo,
		max:         hi,
		socket:      socket,
		target:      &url.URL{Scheme: "http", Host: "docker"},
		objects:     unasked{},
	}
}

// objects answers for the objects a request names: the one its path does,
// and the volumes and networks its body does. Each says what to forward in
// the path's place, what the log says of it, and why it is refused if it is.
type objects interface {
	path(r *http.Request, kind, seg string) (forward, account, reason string)
	body(r *http.Request, lookups []docker.Lookup) (account, reason string)
}

// unasked refuses every request that names an object: nothing yet asks the
// daemon whose it is, and a request is never let through on the assumption.
type unasked struct{}

func (unasked) path(*http.Request, string, string) (string, string, string) {
	return "", "", ReasonUnasked
}

func (unasked) body(*http.Request, []docker.Lookup) (string, string) { return "", ReasonUnasked }

// transport is the route's own connection to the daemon: its socket,
// whatever address a request names, and HTTP/1.1, the only protocol the
// daemon's socket speaks. It is never the egress dialer, which is not asked
// to reach a socket and must never be able to.
func (d *dockerRoute) transport() *http.Transport {
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, "unix", d.socket)
			if err != nil {
				return nil, dialFailed(ctx, err)
			}
			// The bare *net.UnixConn, so that an upgraded stream can close
			// its write side.
			return c, nil
		},
		DisableCompression: true,
		IdleConnTimeout:    90 * time.Second,
		Protocols:          &protocols,
	}
}

// dialFailed is a dial error without the socket's path, which says where on
// the host the daemon listens and goes into nothing a request's line keeps.
func dialFailed(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		// The syscall's own error, without the OpError around it, which
		// holds the path.
		inner := errors.Unwrap(op.Err)
		if inner == nil {
			inner = op.Err
		}
		return fmt.Errorf("docker socket: %s: %w", op.Op, inner)
	}
	return errors.New("docker socket: dial failed")
}

// version reads a request's /v1.NN, the first segment if it looks like a
// version to any reading of it. It gives the path to decide on, the version,
// "-" for none, and how many segments the version took; or why the path is
// refused. Nothing is normalised: a path that would need it is refused.
func (d *dockerRoute) version(escaped string) (stripped, api string, offset int, reason, account string) {
	if strings.Contains(escaped, "%") {
		// No ID, name, image or template needs one, and a path with none is
		// the same path to every reading of it.
		return "", "", 0, ReasonBadPath, "path escaped"
	}
	segs, err := splitPath(escaped)
	if err != nil {
		return "", "", 0, ReasonBadPath, ""
	}
	s0 := segs[0]
	if !versionish.MatchString(fold(s0)) {
		if !slices.Contains(d.APIVersions.Unversioned, escaped) {
			return "", "", 0, ReasonUnversioned, ""
		}
		return escaped, "-", 0, "", ""
	}
	m := versionSeg.FindStringSubmatch(s0)
	if m == nil {
		return "", "", 0, ReasonAPIVersion, "api=" + quoted(s0) + " not allowed"
	}
	minor, err := strconv.Atoi(m[1])
	if err != nil || minor < d.min || minor > d.max {
		return "", "", 0, ReasonAPIVersion, "api=" + quoted(s0) + " not allowed"
	}
	stripped = escaped[1+len(s0):]
	if stripped == "" {
		stripped = "/"
	}
	return stripped, s0[1:], 1, "", ""
}

// modify caps the version the daemon says it speaks at the route's highest:
// a client negotiates down to it from _ping, so a daemon newer than the
// route's rules is spoken to as though it were no newer.
func (d *dockerRoute) modify(res *http.Response) error {
	if v := res.Header.Get("Api-Version"); v != "" {
		if minor, err := apiMinor(v); err != nil || minor > d.max {
			res.Header.Set("Api-Version", d.APIVersions.Max)
		}
	}
	return inspect(res)
}

// dockerRule is an admitting rule on a Docker route, deferred to: it decides
// from the whole request, after the scope matched its path.
type dockerRule struct {
	DockerRule
	operation *Operation
	// route is set when the route is built.
	route *dockerRoute
}

// verdict is the scope's answer for a request the rule matched: refused
// until the rule's own checks have run.
func (d *dockerRule) verdict() Verdict {
	return Verdict{Outcome: Refuse, Reason: reasonUndecided, Operation: d.operation, deferred: d}
}

func (d *dockerRule) refuse(reason, account string) Verdict {
	return Verdict{Outcome: Refuse, Reason: reason, Operation: d.operation, Docker: account}
}

// refused is a refusal from the docker package: the client reads its reason
// and the table's words, the log what the request held.
func (d *dockerRule) refused(err error) Verdict {
	var ref *docker.Refusal
	if errors.As(err, &ref) {
		return d.refuse(ref.Error(), ref.Log)
	}
	return d.refuse(docker.ReasonUnreadable, "")
}

// decide runs the rule's checks, in the contract's order, and makes the
// request what goes upstream: its query and body re-encoded from what was
// checked, and its object's segment as the daemon said to name it.
func (d *dockerRule) decide(r *http.Request) Verdict {
	rt := d.route
	if rt == nil {
		return d.refuse(reasonUndecided, "")
	}
	var account []string
	if reason, acct := d.upgrade(r.Header); reason != "" {
		return d.refuse(reason, acct)
	}
	query, acct, err := d.query(r.URL.RawQuery)
	if err != nil {
		return d.refused(err)
	}
	account = append(account, acct...)

	// The object's segment as it was sent, never as the scope read it: the
	// scope matched on segments decoded and, for a stricter rule, folded,
	// and "MyDB." is not "mydb" to the daemon.
	_, _, offset, reason, _ := rt.version(r.URL.EscapedPath())
	if reason != "" {
		return d.refuse(reason, "")
	}
	raw := strings.Split(r.URL.EscapedPath()[1:], "/")
	at := -1
	if slices.Contains(withParam, d.Owned) {
		at = d.Param + offset
		if at >= len(raw) {
			return d.refuse(ReasonParam, "")
		}
		if reason, acct := d.param(raw[at]); reason != "" {
			return d.refuse(reason, acct)
		}
	}

	bodied := false
	var lookups []docker.Lookup
	if d.Body == "" {
		if reason := noBody(r); reason != "" {
			return d.refuse(reason, "")
		}
	} else {
		checked, err := d.body(r)
		if err != nil {
			return d.refused(err)
		}
		account = append(account, checked.Account...)
		lookups = checked.Lookups
		bodied = true
	}

	if at >= 0 && d.Owned != "image" {
		forward, acct, reason := rt.objects.path(r, d.Owned, raw[at])
		if acct != "" {
			account = append(account, acct)
		}
		if reason != "" {
			return d.refuse(reason, strings.Join(account, "; "))
		}
		raw[at] = forward
		p := "/" + strings.Join(raw, "/")
		r.URL.Path, r.URL.RawPath = p, p
	}
	if len(lookups) > 0 {
		acct, reason := rt.objects.body(r, lookups)
		if acct != "" {
			account = append(account, acct)
		}
		if reason != "" {
			return d.refuse(reason, strings.Join(account, "; "))
		}
	}
	r.URL.RawQuery, r.URL.ForceQuery = query, false
	return Verdict{Outcome: Admit, Reason: "path", Operation: d.operation, Docker: strings.Join(account, "; "), jsonBody: bodied}
}

// upgrade is why a request's protocol switch is refused: only the rule's
// own, named once, and never h2c or websocket.
func (d *dockerRule) upgrade(h http.Header) (reason, account string) {
	ups := h.Values("Upgrade")
	connUpgrade := false
	for _, v := range h.Values("Connection") {
		for tok := range strings.SplitSeq(v, ",") {
			if asciiEqualFold(strings.TrimSpace(tok), "upgrade") {
				connUpgrade = true
			}
		}
	}
	if len(ups) == 0 && !connUpgrade {
		return "", ""
	}
	if d.Upgrade == "" || len(ups) != 1 || !asciiEqualFold(strings.TrimSpace(ups[0]), d.Upgrade) {
		what := "connection upgrade"
		if len(ups) > 0 {
			what = "upgrade=" + quoted(strings.Join(ups, ","))
		}
		return ReasonUpgrade, what + " not allowed"
	}
	return "", ""
}

// query judges the query by the rule's checks and gives it back re-encoded,
// the list's filters narrowed to the project and a pull's image checked.
func (d *dockerRule) query(raw string) (string, []string, error) {
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return "", nil, &docker.Refusal{Reason: docker.ReasonQuery, Detail: "a query that does not parse", Log: "query unparsed"}
	}
	for _, key := range sortedKeys(vals) {
		c, ok := d.Query[key]
		if !ok {
			return "", nil, &docker.Refusal{Reason: docker.ReasonQuery, Detail: "a key this operation does not take", Log: "query=" + quoted(key) + " not allowed"}
		}
		vs := vals[key]
		if len(vs) != 1 {
			return "", nil, &docker.Refusal{Reason: docker.ReasonQuery, Detail: key + " more than once", Log: "query=" + key + " twice"}
		}
		if !c.judge(vs[0]) {
			return "", nil, &docker.Refusal{Reason: docker.ReasonQuery, Detail: key + " is not " + c.Check, Log: "query=" + key + " not " + c.Check}
		}
	}
	var account []string
	switch d.Owned {
	case "list":
		merged, err := docker.MergeFilter(vals.Get("filters"), d.Query["filters"].Filters, d.route.Project)
		if err != nil {
			return "", nil, err
		}
		vals.Set("filters", merged)
		account = append(account, "filters+label")
	case "imagePull":
		ref, err := d.pulled(vals)
		if err != nil {
			return "", nil, err
		}
		account = append(account, "image="+quoted(ref)+" listed")
	}
	return vals.Encode(), account, nil
}

// judge is whether a query value passes the check.
func (c QueryCheck) judge(v string) bool {
	switch c.Check {
	case "any", "filters", "imageName", "imageTag":
		// A list's filters and a pull's image are judged whole, after.
		return true
	case "bool":
		return v == "0" || v == "1" || v == "true" || v == "false"
	case "int":
		return intRE.MatchString(v)
	case "containerName":
		// Never all hex, so that it cannot be taken for an ID's prefix.
		return contNameRE.MatchString(v) && !contHexRE.MatchString(v)
	case "enum":
		return slices.Contains(c.Enum, v)
	}
	return false
}

// pulled is the image a pull fetches: fromImage with its tag, or its digest,
// which must be one the route lists exactly. A tag given beside a
// fromImage that already has one would be replaced by moby, and no tag with
// an untagged fromImage pulls every tag.
func (d *dockerRule) pulled(vals url.Values) (string, error) {
	refuse := func(detail, log string) error {
		return &docker.Refusal{Reason: ReasonImage, Detail: detail, Log: log}
	}
	from, tag := vals.Get("fromImage"), vals.Get("tag")
	switch {
	case from == "":
		return "", refuse("a pull names no image", "fromImage absent")
	case tag != "" && docker.Tagged(from):
		return "", refuse("a pull with a tag in fromImage and in tag", "fromImage="+quoted(from)+" tagged twice")
	case tag == "" && !docker.Tagged(from):
		return "", refuse("a pull of every tag", "fromImage="+quoted(from)+" untagged")
	}
	ref := from
	switch {
	case strings.HasPrefix(tag, "sha256:"):
		ref += "@" + tag
	case tag != "":
		ref += ":" + tag
	}
	if !slices.Contains(d.route.Images, ref) {
		return "", refuse("a pull of an image the route does not list", "image="+quoted(ref)+" not listed")
	}
	return ref, nil
}

// param is why the path's object segment is refused before anything is
// asked of it: an image must be listed, exactly, an exec an ID, and every
// other object named in the daemon's own grammar.
func (d *dockerRule) param(seg string) (reason, account string) {
	switch d.Owned {
	case "image":
		if !slices.Contains(d.route.Images, seg) {
			return ReasonImage, "image=" + quoted(seg) + " not listed"
		}
	case "exec":
		if !execSegRE.MatchString(seg) {
			return ReasonParam, "exec=" + quoted(seg) + " not an ID"
		}
	default:
		if !nameSegRE.MatchString(seg) {
			return ReasonParam, d.Owned + "=" + quoted(seg) + " not a name"
		}
	}
	return "", ""
}

// noBody is why a request to an operation that takes no body is refused if
// it has one: moby's ParseForm reads a form body as more query, which none
// of this route's checks would have seen. Nothing is asked of a
// Content-Type, since an empty /start carries none.
func noBody(r *http.Request) string {
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		return ReasonNoBody
	}
	if r.Body != nil && r.Body != http.NoBody {
		var one [1]byte
		n, err := io.ReadAtLeast(r.Body, one[:], 1)
		switch {
		case n > 0:
			return ReasonNoBody
		case !errors.Is(err, io.EOF):
			return ReasonStoppedWaiting
		}
		r.Body = http.NoBody
	}
	return ""
}

// body reads a JSON body, bounded by the route's maxBody, and judges it by
// the rule's table. What goes upstream is the tree that was judged,
// re-encoded.
func (d *dockerRule) body(r *http.Request) (docker.Checked, error) {
	refuse := func(reason, detail, log string) error {
		return &docker.Refusal{Reason: reason, Detail: detail, Log: log}
	}
	for _, v := range r.Header.Values("Content-Encoding") {
		if !asciiEqualFold(strings.TrimSpace(v), "identity") {
			return docker.Checked{}, refuse(docker.ReasonBody, "an encoded body", "content-encoding="+quoted(v))
		}
	}
	if !isJSON(r.Header.Values("Content-Type")) {
		return docker.Checked{}, refuse(docker.ReasonBody, "a body that is not application/json", "content-type not json")
	}
	body, whole, err := readUpTo(r, int(d.route.MaxBody))
	switch {
	case err != nil:
		return docker.Checked{}, refuse(ReasonStoppedWaiting, "", "")
	case !whole:
		return docker.Checked{}, refuse(docker.ReasonBody, fmt.Sprintf("a body over %d bytes", d.route.MaxBody), "body over maxBody")
	case len(body) == 0:
		return docker.Checked{}, refuse(docker.ReasonUnreadable, "an empty body", "body empty")
	}
	checked, err := d.route.Bodies[d.Body].Check(body, docker.Route{
		Project: d.route.Project,
		Address: d.route.Address,
		Ports:   d.route.Ports,
		Images:  d.route.Images,
	})
	if err != nil {
		return docker.Checked{}, err
	}
	r.Body = io.NopCloser(bytes.NewReader(checked.Body))
	r.ContentLength = int64(len(checked.Body))
	r.TransferEncoding = nil
	r.Header.Del("Content-Encoding")
	return checked, nil
}

// quoted is a request's value as the log holds it: Go-quoted, from at most
// 128 bytes of it.
func quoted(s string) string {
	const most = 128
	if len(s) > most {
		s = s[:most]
	}
	return strconv.Quote(s)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
