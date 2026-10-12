package policy

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/danielbodart/frisket/hostpattern"
)

// Lowered is a document of either version as the gateway builds it: in
// version 1's shape where that can say it, and beside it what only version
// 2 says. A version 1 document is its Policy alone.
type Lowered struct {
	Name   string
	Policy Policy
	// AllowPatterns are allow keys version 1's grammar has no word for, in
	// hostpattern's: "*.example.com" (one label), "*-ap.lan".
	AllowPatterns []string
	// LANPatterns are lan keys that are patterns, with their ports.
	LANPatterns map[string][]int
	// Scopes are each version 2 route's operations, ceiling and unmatched,
	// by route name; Policy's route of that name holds its endpoint
	// patterns as Paths.
	Scopes map[string]*ScopeV2
}

// ScopeV2 is what a version 2 route says that version 1 cannot.
type ScopeV2 struct {
	// Operations are the route's Paths, each answered.
	Operations []EndpointAnswer
	// Ceiling is the most lenient a pattern may answer each class:
	// "write", "guarded", and "" for a request no operation describes.
	Ceiling map[string]string
	// Unmatched is "allow", "ask" or "refuse", clamped.
	Unmatched string
}

// EndpointAnswer is one operation of a route and its answer: by its id or
// category if Named, which no endpoint pattern overrules, else by its
// class. Its Ask and Refuse are never set.
type EndpointAnswer struct {
	PathRule
	Answer string
	Named  bool
}

// Built-in answers, where no layer says.
const (
	builtinWrites    = "ask"
	builtinGuarded   = "refuse"
	builtinUnmatched = "refuse"
	// builtinSSHUnmatched is an SSH route's, as version 1's is.
	builtinSSHUnmatched = "ask"
)

// ReceivePackID is git's push, as an operation.
const ReceivePackID = "git-receive-pack"

// Load reads a document of either version, as its version field says.
func Load(b []byte) (*Lowered, error) {
	v, err := Version(b)
	if err != nil {
		return nil, err
	}
	if v == 1 {
		var d Document
		if err := Decode(b, &d); err != nil {
			return nil, err
		}
		return &Lowered{Name: d.Name, Policy: d.Policy}, nil
	}
	d, err := DecodeV2(b)
	if err != nil {
		return nil, err
	}
	return Lower(d)
}

// strictness orders answers: allow, then ask, then refuse.
func strictness(a string) int {
	switch a {
	case "allow":
		return 0
	case "ask":
		return 1
	}
	return 2
}

// stricter is the stricter of two answers, either of which may be empty.
func stricter(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	case strictness(b) > strictness(a):
		return b
	}
	return a
}

func checkAnswer(what, a string) error {
	switch a {
	case "", "allow", "ask", "refuse":
		return nil
	}
	return fmt.Errorf("%s %q: allow, ask or refuse", what, a)
}

func checkAnswers(what string, a *Answers) error {
	if a == nil {
		return nil
	}
	return errors.Join(
		checkAnswer(what+" writes", a.Writes),
		checkAnswer(what+" guarded", a.Guarded),
		checkAnswer(what+" unmatched", a.Unmatched),
	)
}

// of is an Answers' answer for class: "write", "guarded" or "unmatched".
func (a *Answers) of(class string) string {
	if a == nil {
		return ""
	}
	switch class {
	case "write":
		return a.Writes
	case "guarded":
		return a.Guarded
	case "unmatched":
		return a.Unmatched
	}
	return ""
}

// chain is the answers that apply to one route, innermost first, and its
// ceilings.
type chain struct {
	answers   []*Answers
	ceilings  []*Answers
	unmatched string // the built-in
}

// answer is class's answer: "read" is allowed, and anything else the first
// layer's that says, or the built-in.
func (c chain) answer(class string) string {
	if class == "read" {
		return "allow"
	}
	if class == "" {
		class = "unmatched"
	}
	for _, a := range c.answers {
		if s := a.of(class); s != "" {
			return s
		}
	}
	switch class {
	case "write":
		return builtinWrites
	case "guarded":
		return builtinGuarded
	}
	return c.unmatched
}

// ceiling is class's ceiling, "" for none: the strictest any layer sets.
func (c chain) ceiling(class string) string {
	if class == "read" {
		return ""
	}
	if class == "" {
		class = "unmatched"
	}
	out := ""
	for _, a := range c.ceilings {
		out = stricter(out, a.of(class))
	}
	return out
}

// clamp is a, made no more lenient than class's ceiling.
func (c chain) clamp(a, class string) string { return stricter(a, c.ceiling(class)) }

// Lower is a version 2 document as the gateway builds it. What it refuses
// is what no layer may say: an answer that is not one, a key in no
// grammar, an operation id or category no operation of the route has, an
// SSH pattern that sets what only a machine has.
func Lower(d DocumentV2) (*Lowered, error) {
	if d.Version != 2 {
		return nil, errors.New("not a version 2 document")
	}
	if err := errors.Join(checkAnswers("document", &d.Answers), checkAnswers("document ceiling", d.Ceiling)); err != nil {
		return nil, err
	}
	l := &Lowered{Name: d.Name, Scopes: map[string]*ScopeV2{}}
	l.Policy.Allow = []string{}
	for _, k := range slices.Sorted(maps.Keys(d.Allow)) {
		if !d.Allow[k] {
			continue
		}
		p, err := hostpattern.Compile(k)
		if err != nil {
			return nil, fmt.Errorf("allow: %w", err)
		}
		switch below, ok := p.Below(); {
		case p.Literal():
			l.Policy.Allow = append(l.Policy.Allow, k)
		case ok && below == "":
			l.Policy.Allow = append(l.Policy.Allow, "*")
		case ok:
			l.Policy.Allow = append(l.Policy.Allow, "*."+below)
		default:
			l.AllowPatterns = append(l.AllowPatterns, k)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(d.LAN)) {
		p, err := hostpattern.Compile(k)
		if err != nil {
			return nil, fmt.Errorf("lan: %w", err)
		}
		if p.Literal() {
			l.Policy.LAN = append(l.Policy.LAN, LANHost{Name: k, Ports: d.LAN[k].Ports})
			continue
		}
		if l.LANPatterns == nil {
			l.LANPatterns = map[string][]int{}
		}
		l.LANPatterns[k] = d.LAN[k].Ports
	}
	l.Policy.Record = d.Record
	for _, name := range slices.Sorted(maps.Keys(d.Routes)) {
		r, sc, err := lowerRoute(name, d.Routes[name], d)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", name, err)
		}
		l.Policy.Routes = append(l.Policy.Routes, r)
		l.Scopes[name] = sc
	}
	ssh, err := lowerSSH(d)
	if err != nil {
		return nil, err
	}
	l.Policy.SSH = ssh
	return l, nil
}

// lowerHost is a route host in version 1's words: a name, or "*.suffix"
// for "**.suffix". Anything else is refused: a route is for a name or the
// names below one, which is what its session CA is constrained to.
func lowerHost(h string) (string, error) {
	p, err := hostpattern.Compile(h)
	if err != nil {
		return "", err
	}
	if p.Literal() {
		return h, nil
	}
	if below, ok := p.Below(); ok && below != "" {
		return "*." + below, nil
	}
	return "", fmt.Errorf("host %q: a name, or **.name for every name below it", h)
}

// lowerUpstream is an upstream in version 1's words: https://**.suffix is
// https://*.suffix, the name each request was made to.
func lowerUpstream(u string) string {
	if rest, ok := strings.CutPrefix(u, "https://**."); ok {
		return "https://*." + rest
	}
	return u
}

// ParseEndpoint reads an endpoint pattern, "METHOD[,METHOD] /path": methods
// in capitals, and a path whose "*" segment is any one segment and whose
// last segment "**" is any number of them, none included. path is an exact
// template, or prefix is one a request is at or under.
func ParseEndpoint(key string) (methods []string, path, prefix string, err error) {
	m, p, ok := strings.Cut(key, " ")
	if !ok || m == "" || !strings.HasPrefix(p, "/") {
		return nil, "", "", fmt.Errorf("%q is not METHOD[,METHOD] /path", key)
	}
	for meth := range strings.SplitSeq(m, ",") {
		if meth == "" || strings.TrimFunc(meth, func(r rune) bool { return r >= 'A' && r <= 'Z' }) != "" {
			return nil, "", "", fmt.Errorf("%q: method %q is not one in capitals", key, meth)
		}
		if slices.Contains(methods, meth) {
			return nil, "", "", fmt.Errorf("%q names %s twice", key, meth)
		}
		methods = append(methods, meth)
	}
	switch {
	case p == "/**":
		prefix = "/"
	case strings.HasSuffix(p, "/**"):
		prefix = strings.TrimSuffix(p, "/**")
	default:
		path = p
	}
	if strings.Contains(path+prefix, "**") {
		return nil, "", "", fmt.Errorf("%q: ** is only the last segment", key)
	}
	return methods, path, prefix, nil
}

// IsEndpoint is whether an operations key is an endpoint pattern rather
// than an id or a category: a word, a space and a path.
func IsEndpoint(key string) bool {
	m, p, ok := strings.Cut(key, " ")
	return ok && m != "" && !strings.Contains(m, ":") && strings.HasPrefix(p, "/")
}

func lowerRoute(name string, r RouteV2, d DocumentV2) (Route, *ScopeV2, error) {
	if err := errors.Join(checkAnswers("route", &r.Answers), checkAnswers("route ceiling", r.Ceiling)); err != nil {
		return Route{}, nil, err
	}
	host, err := lowerHost(r.Host)
	if err != nil {
		return Route{}, nil, err
	}
	out := Route{
		Name: name, Host: host, Upstream: lowerUpstream(r.Upstream), UpstreamCA: r.UpstreamCA,
		CredentialFile: r.CredentialFile, CredentialJSON: r.CredentialJSON, Header: r.Header,
		BasicUser: r.BasicUser, Placeholder: r.Placeholder, Refusal: r.Refusal,
		SessionKey: r.SessionKey, Docker: r.Docker,
	}
	c := chain{answers: []*Answers{&r.Answers, &d.Answers}, ceilings: []*Answers{r.Ceiling, d.Ceiling}, unmatched: builtinUnmatched}
	for k, a := range r.Operations {
		if err := checkAnswer("operations "+k, a); err != nil {
			return Route{}, nil, err
		}
		if a == "" {
			return Route{}, nil, fmt.Errorf("operations %q: no answer", k)
		}
	}
	// encodedSlashes is whether an endpoint or pattern, by its key, takes
	// an encoded slash in a "*": its own key names it, or its path does.
	for k := range r.EncodedSlashes {
		t := k
		if IsEndpoint(k) {
			_, path, prefix, err := ParseEndpoint(k)
			if err != nil {
				return Route{}, nil, fmt.Errorf("encodedSlashes: %w", err)
			}
			t = path + prefix
		}
		t = strings.TrimSuffix(t, "/**")
		if !strings.HasPrefix(t, "/") || !strings.Contains(t, "*") {
			return Route{}, nil, fmt.Errorf("encodedSlashes %q: a path template, or an endpoint, with a * segment", k)
		}
	}
	encodedSlashes := func(key, path, prefix string) bool {
		t := path
		if prefix != "" {
			t = strings.TrimSuffix(prefix, "/") + "/**"
		}
		return r.EncodedSlashes[key] || r.EncodedSlashes[path+prefix] || r.EncodedSlashes[t]
	}
	ids, categories := map[string]bool{}, map[string]bool{}
	byName := func(op *Operation, id string) (string, bool) {
		if a, ok := r.Operations[id]; ok {
			return a, true
		}
		if op != nil && op.Category != "" {
			if a, ok := r.Operations["category:"+op.Category]; ok {
				return a, true
			}
		}
		return "", false
	}
	know := func(id string, op *Operation) {
		ids[id] = true
		if op != nil && op.Category != "" {
			categories[op.Category] = true
		}
	}

	sc := &ScopeV2{}
	for _, key := range slices.Sorted(maps.Keys(r.Paths)) {
		methods, path, prefix, err := ParseEndpoint(key)
		if err != nil {
			return Route{}, nil, fmt.Errorf("paths: %w", err)
		}
		e := r.Paths[key]
		op := e.Operation
		if op == nil || op.ID == "" || op.Summary == "" {
			return Route{}, nil, fmt.Errorf("paths %q: an operation, with an id and a summary", key)
		}
		switch op.Class {
		case "", "read", "write", "guarded":
		default:
			return Route{}, nil, fmt.Errorf("paths %q: operation %s: class %q: read, write or guarded", key, op.ID, op.Class)
		}
		know(op.ID, op)
		answer, named := byName(op, op.ID)
		if !named {
			answer = c.answer(op.Class)
		}
		sc.Operations = append(sc.Operations, EndpointAnswer{
			PathRule: PathRule{Methods: methods, Path: path, Prefix: prefix, EncodedSlashes: encodedSlashes(key, path, prefix), Operation: op, Docker: e.Docker},
			Answer:   c.clamp(answer, op.Class),
			Named:    named,
		})
	}

	for _, path := range slices.Sorted(maps.Keys(r.GraphQL)) {
		g := r.GraphQL[path]
		if err := checkAnswer("graphql "+path+" unmatched", g.Unmatched); err != nil {
			return Route{}, nil, err
		}
		unmatched := g.Unmatched
		if unmatched == "" {
			unmatched = c.answer("unmatched")
		}
		rule := GraphQLRule{Path: path, Unmatched: c.clamp(unmatched, "unmatched")}
		field := func(id string, f GraphQLFieldV2) GraphQLField {
			op := f.Operation
			if op != nil && op.ID != "" {
				id = op.ID
			}
			know(id, op)
			answer, named := byName(op, id)
			class := ""
			if op != nil {
				class = op.Class
			}
			if !named {
				if class == "" {
					answer = unmatched
				} else {
					answer = c.answer(class)
				}
			}
			out := GraphQLField{Operation: op}
			switch c.clamp(answer, class) {
			case "ask":
				out.Ask = true
			case "refuse":
				out.Refuse = true
			}
			return out
		}
		if g.Query != nil {
			q := field("query", *g.Query)
			rule.Query = &q
		}
		for _, f := range slices.Sorted(maps.Keys(g.Mutations)) {
			m := field(f, g.Mutations[f])
			m.Field = f
			rule.Mutations = append(rule.Mutations, m)
		}
		for _, f := range slices.Sorted(maps.Keys(g.Subscriptions)) {
			s := field(f, g.Subscriptions[f])
			s.Field = f
			rule.Subscriptions = append(rule.Subscriptions, s)
		}
		out.GraphQL = append(out.GraphQL, rule)
	}

	if g := r.Git; g != nil {
		out.Git = &GitRule{Repos: []string{}}
		for _, repo := range slices.Sorted(maps.Keys(g.Repos)) {
			if g.Repos[repo] {
				out.Git.Repos = append(out.Git.Repos, repo)
			}
		}
		know(ReceivePackID, nil)
		push := r.Operations[ReceivePackID]
		if push == "" {
			push = c.answer("write")
		}
		out.Git.Push = c.clamp(push, "write")
	}

	for _, key := range slices.Sorted(maps.Keys(r.Operations)) {
		a := r.Operations[key]
		switch {
		case strings.HasPrefix(key, "category:"):
			if !categories[strings.TrimPrefix(key, "category:")] {
				return Route{}, nil, fmt.Errorf("operations %q: no operation of the route's is of that category", key)
			}
		case IsEndpoint(key):
			methods, path, prefix, err := ParseEndpoint(key)
			if err != nil {
				return Route{}, nil, fmt.Errorf("operations: %w", err)
			}
			out.Paths = append(out.Paths, PathRule{
				Methods: methods, Path: path, Prefix: prefix,
				EncodedSlashes: encodedSlashes(key, path, prefix),
				Ask:            a == "ask", Refuse: a == "refuse",
			})
		case !ids[key]:
			return Route{}, nil, fmt.Errorf("operations %q: the route has no such operation; an endpoint is \"METHOD /path\"", key)
		}
	}

	unmatched := r.Unmatched
	if unmatched == "" {
		unmatched = c.answer("unmatched")
	}
	sc.Unmatched = c.clamp(unmatched, "unmatched")
	if r.Docker != nil {
		// A Docker route refuses what its rules do not match, whatever a
		// layer says of unmatched.
		sc.Unmatched = "refuse"
	}
	for _, class := range []string{"write", "guarded", "unmatched"} {
		if ceil := c.ceiling(class); ceil != "" {
			if sc.Ceiling == nil {
				sc.Ceiling = map[string]string{}
			}
			key := class
			if class == "unmatched" {
				key = ""
			}
			sc.Ceiling[key] = ceil
		}
	}
	return out, sc, nil
}

// RuleName splits an exec rule's key, as execrule names a rule: a command
// pattern, a pattern and "[arg GLOB]", or "[arg GLOB]" alone.
func RuleName(key string) (command, arg string) {
	i := strings.Index(key, "[arg ")
	if i < 0 || !strings.HasSuffix(key, "]") || i > 0 && key[i-1] != ' ' {
		return key, ""
	}
	return strings.TrimSuffix(key[:i], " "), key[i+len("[arg ") : len(key)-1]
}

// sshHostOnly is whether an SSH entry sets anything only a machine has.
func sshHostOnly(r SSHRouteV2) bool {
	return r.Address != "" || r.User != "" || len(r.HostKeys) > 0 || r.Agent != "" || r.KeyFile != "" ||
		r.PasswordFile != "" || r.Identity != "" || r.Shell
}

// lowerSSH is the document's SSH routes: each machine with the answers of
// every pattern that matches its name merged under its own, the widest
// first, and each rule answered.
func lowerSSH(d DocumentV2) ([]SSHRoute, error) {
	type pat struct {
		key string
		p   hostpattern.Pattern
	}
	var patterns []pat
	for _, k := range slices.Sorted(maps.Keys(d.SSH)) {
		p, err := hostpattern.Compile(k)
		if err != nil {
			return nil, fmt.Errorf("ssh: %w", err)
		}
		if p.Literal() {
			continue
		}
		if sshHostOnly(d.SSH[k]) || len(d.SSH[k].Commands) > 0 {
			return nil, fmt.Errorf("ssh %s: a pattern is no machine, and sets only env, exec, writes, guarded, unmatched and ceiling", k)
		}
		patterns = append(patterns, pat{k, p})
	}
	// Widest first, so the narrower are merged over them.
	slices.SortStableFunc(patterns, func(a, b pat) int {
		switch {
		case a.p.Narrower(b.p):
			return 1
		case b.p.Narrower(a.p):
			return -1
		}
		return 0
	})
	var out []SSHRoute
	for _, name := range slices.Sorted(maps.Keys(d.SSH)) {
		if p, _ := hostpattern.Compile(name); !p.Literal() {
			continue
		}
		own := d.SSH[name]
		eff := SSHRouteV2{Env: map[string]bool{}, Exec: map[string]string{}}
		var ceilings []*Answers
		layers := []SSHRouteV2{}
		for _, p := range patterns {
			if p.p.Match(name) {
				layers = append(layers, d.SSH[p.key])
			}
		}
		layers = append(layers, own)
		var answers []*Answers
		for i := range layers {
			l := layers[i]
			maps.Copy(eff.Env, l.Env)
			maps.Copy(eff.Exec, l.Exec)
			answers = append([]*Answers{&layers[i].Answers}, answers...)
			ceilings = append(ceilings, l.Ceiling)
			if err := errors.Join(checkAnswers("ssh "+name, &l.Answers), checkAnswers("ssh "+name+" ceiling", l.Ceiling)); err != nil {
				return nil, err
			}
		}
		c := chain{answers: append(answers, &d.Answers), ceilings: append(ceilings, d.Ceiling), unmatched: builtinSSHUnmatched}
		r := SSHRoute{
			Name: name, Address: own.Address, User: own.User, HostKeys: own.HostKeys, Agent: own.Agent,
			KeyFile: own.KeyFile, PasswordFile: own.PasswordFile, Identity: own.Identity, Shell: own.Shell,
		}
		for _, e := range slices.Sorted(maps.Keys(eff.Env)) {
			if eff.Env[e] {
				r.Env = append(r.Env, e)
			}
		}
		keys := map[string]bool{}
		for k := range eff.Exec {
			keys[k] = true
		}
		for k := range own.Commands {
			keys[k] = true
		}
		for _, key := range slices.Sorted(maps.Keys(keys)) {
			command, arg := RuleName(key)
			var op *Operation
			class := ""
			if o, ok := own.Commands[key]; ok {
				o := o
				op, class = &o, o.Class
			}
			a, ok := eff.Exec[key]
			if err := checkAnswer("ssh "+name+" exec "+key, a); err != nil {
				return nil, err
			}
			if !ok || a == "" {
				a = c.answer(class)
			}
			a = c.clamp(a, class)
			if arg != "" && a == "allow" {
				continue // an arg rule only tightens
			}
			r.Exec = append(r.Exec, ExecRule{Command: command, Arg: arg, Ask: a == "ask", Refuse: a == "refuse", Operation: op})
		}
		unmatched := c.clamp(c.answer("unmatched"), "unmatched")
		r.Unmatched = unmatched
		if unmatched == "allow" {
			// Every readable command no rule matches is admitted by the
			// least literal rule there is; what cannot be read is refused,
			// never admitted.
			if !slices.ContainsFunc(r.Exec, func(e ExecRule) bool { return e.Command == "**" && e.Arg == "" }) {
				r.Exec = append(r.Exec, ExecRule{Command: "**"})
			}
			r.Unmatched = "refuse"
		}
		out = append(out, r)
	}
	return out, nil
}
