package agentsrv

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/danielbodart/frisket/internal/courier"
	"github.com/danielbodart/frisket/internal/galleyask"
	"github.com/danielbodart/frisket/internal/peer"
	"github.com/danielbodart/frisket/projpolicy"
	"github.com/danielbodart/galley/wire"
	"golang.org/x/crypto/ssh"
)

// Policy is where the signer finds a project's signed policy: the courier
// that reads it from forUser's home, the allowed signers it must verify
// against, the file's name and the home its namespace is named from. A
// Server with none reads no project policy, offers no Always, and refuses
// policy-sign.
type Policy struct {
	Courier        string
	AllowedSigners string
	FileName       string
	Home           string
}

const courierTimeout = 3 * time.Second

// A project's signer section may set only these: the rest of the signer's
// settings are the host's.
type projectSigner struct {
	SSH *struct {
		Hosts map[string]*Rule `json:"hosts"`
	} `json:"ssh"`
	SSHSIG map[string]*Rule `json:"sshsig"`
}

// layer is a project's policy file as the signer reads it.
type layer struct {
	root, rootName, namespace string
	digest                    string // "" when there is no file yet
	cur                       []byte

	// apply: the file verifies and its signer section is one a project may
	// set, so its rules are merged over the host's.
	apply  bool
	signer any // the signer section, for MergePatch; nil when none
	hosts  map[string]bool
	sshsig map[string]bool

	// writable: Always may write over the file, absent or verified,
	// canonical and an object.
	writable bool
	doc      map[string]any
	signers  *projpolicy.AllowedSigners
	why      string
}

type layerCache struct {
	mu sync.Mutex
	m  map[string]*layer
}

const maxCached = 64

func (lc *layerCache) get(k string) *layer {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.m[k]
}

func (lc *layerCache) put(k string, l *layer) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.m == nil || len(lc.m) >= maxCached {
		lc.m = map[string]*layer{}
	}
	lc.m[k] = l
}

func (s *Server) policyDefaults() {
	if s.layers == nil {
		s.layers = &layerCache{}
	}
	if s.Policy == nil {
		return
	}
	if s.read == nil {
		s.read = func(ctx context.Context, pid int, start uint64) (*courier.Response, error) {
			return courier.Read(ctx, s.Policy.Courier, pid, start)
		}
	}
	if s.write == nil {
		s.write = func(ctx context.Context, root, old string, b, sig []byte) error {
			_, err := courier.Write(ctx, s.Policy.Courier, root, old, b, sig)
			return err
		}
	}
	if s.notify == nil {
		s.notify = galleyask.Notify
	}
	if s.inHost == nil {
		s.inHost = peer.InOwnUserns
	}
}

// project is the policy of the project the anchor is in, read through the
// courier and verified; nil when there is no policy configured, no anchor
// to ask about, no project, or the courier could not say.
func (c *conn) project(req *request) *layer {
	if req.proj != nil || req.projRead {
		return req.proj
	}
	req.projRead = true
	r := c.r
	if c.s.Policy == nil || r.Anchor == nil || r.Cut {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), courierTimeout)
	defer cancel()
	resp, err := c.s.read(ctx, r.Anchor.Pid, r.Anchor.Start)
	if err != nil {
		c.s.Log.Info("project policy unread", "err", err.Error(), "anchor", r.Anchor)
		return nil
	}
	if resp.Root == "" {
		return nil
	}
	sb, err := os.ReadFile(c.s.Policy.AllowedSigners)
	if err != nil {
		c.s.Log.Warn("project policy unread", "root", resp.Root, "err", err.Error())
		return nil
	}
	key := strings.Join([]string{resp.Root, resp.Digest, string(resp.Sig), projpolicy.Digest(sb)}, "\x00")
	if l := c.s.layers.get(key); l != nil {
		req.proj = l
		return l
	}
	l, err := c.s.load(resp, sb)
	if err != nil {
		c.s.Log.Warn("project policy unread", "root", resp.Root, "err", err.Error())
		return nil
	}
	if l.why != "" {
		c.s.Log.Info("project policy ignored", "root", l.root, "digest", l.digest, "why", l.why)
	}
	c.s.layers.put(key, l)
	req.proj = l
	return l
}

// load reads what the courier found, verified against the allowed signers.
func (s *Server) load(resp *courier.Response, signersFile []byte) (*layer, error) {
	root := resp.Root
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, fmt.Errorf("root %q is not absolute and clean", root)
	}
	ns, err := projpolicy.Namespace(root, s.Policy.Home)
	if err != nil {
		return nil, err
	}
	name, _ := projpolicy.RootName(root, s.Policy.Home)
	l := &layer{root: root, rootName: name, namespace: ns, digest: resp.Digest}
	if l.signers, err = projpolicy.ParseAllowedSigners(signersFile); err != nil {
		return nil, fmt.Errorf("%s: %w", s.Policy.AllowedSigners, err)
	}
	if resp.Digest == "" {
		l.writable, l.doc = true, map[string]any{"version": json.Number("2")}
		return l, nil
	}
	l.cur = resp.Bytes
	if l.cur == nil {
		l.cur = []byte{}
	}
	if projpolicy.Digest(l.cur) != resp.Digest {
		return nil, errors.New("the courier's digest is not its bytes'")
	}
	if resp.Sig == nil {
		l.why = "no " + s.Policy.FileName + projpolicy.SigSuffix
		return l, nil
	}
	if _, err := projpolicy.Verify(l.cur, resp.Sig, ns, l.signers, "", s.now()); err != nil {
		l.why = "its signature does not verify: " + err.Error()
		return l, nil
	}
	v, err := projpolicy.Decode(l.cur)
	if err != nil {
		l.why = err.Error()
		return l, nil
	}
	doc, ok := v.(map[string]any)
	if !ok {
		l.why = "it is not a JSON object"
		return l, nil
	}
	if err := l.readSigner(doc["signer"]); err != nil {
		l.why = "signer: " + err.Error()
		return l, nil
	}
	l.apply = true
	if projpolicy.Canonical(l.cur) {
		l.writable, l.doc = true, doc
	}
	return l, nil
}

// readSigner checks a project's signer section: only ssh.hosts and sshsig,
// each a map of allow, ask or null.
func (l *layer) readSigner(v any) error {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var ps projectSigner
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ps); err != nil {
		return fmt.Errorf("%w (a project may set ssh.hosts and sshsig)", err)
	}
	l.hosts, l.sshsig = map[string]bool{}, map[string]bool{}
	if ps.SSH != nil {
		for k, r := range ps.SSH.Hosts {
			if err := CheckHostRule(k); err != nil {
				return fmt.Errorf("ssh.hosts: %w", err)
			}
			if r != nil {
				if err := checkRule(*r); err != nil {
					return fmt.Errorf("ssh.hosts.%s: %w", k, err)
				}
				l.hosts[k] = true
			}
		}
	}
	for ns, r := range ps.SSHSIG {
		if ns == "" || strings.HasPrefix(ns, projpolicy.NamespacePrefix) {
			return fmt.Errorf("sshsig: %q is not a namespace a rule may name", ns)
		}
		if r != nil {
			if err := checkRule(*r); err != nil {
				return fmt.Errorf("sshsig.%s: %w", ns, err)
			}
			l.sshsig[ns] = true
		}
	}
	l.signer = v
	return nil
}

func checkRule(r Rule) error {
	if r != Allow && r != Ask {
		return fmt.Errorf("%q is not allow or ask", string(r))
	}
	return nil
}

// rules is the host's ssh.hosts and sshsig with a project's signer
// section merged over them, as RFC 7396 says.
func (s *Server) rules(l *layer) (hosts, sshsig map[string]Rule) {
	if l == nil || !l.apply || l.signer == nil {
		return s.Hosts, s.SSHSIG
	}
	base := map[string]any{"ssh": map[string]any{"hosts": anyRules(s.Hosts)}, "sshsig": anyRules(s.SSHSIG)}
	merged, _ := projpolicy.MergePatch(base, l.signer).(map[string]any)
	sshm, _ := merged["ssh"].(map[string]any)
	return ruleMap(sshm["hosts"]), ruleMap(merged["sshsig"])
}

func anyRules(m map[string]Rule) map[string]any {
	out := map[string]any{}
	for k, r := range m {
		out[k] = string(r)
	}
	return out
}

func ruleMap(v any) map[string]Rule {
	m, _ := v.(map[string]any)
	out := map[string]Rule{}
	for k, r := range m {
		if s, ok := r.(string); ok {
			out[k] = Rule(s)
		}
	}
	return out
}

// always is what an Always answer writes: the new file, over the one
// whose digest is old, signed by key.
type always struct {
	l    *layer
	name string
	path string // as the question shows it, ~/Projects/foo/chase.json
	new  []byte
	key  Key
}

// offerAlways adds Always to a bound, direct, grantable question to a
// known host from a project whose file Always may write over.
func (c *conn) offerAlways(req *request) {
	l := req.proj
	if c.s.Policy == nil || l == nil || !l.writable || req.class != classBound || !req.grantable || req.fwd || !req.known {
		return
	}
	name, err := ruleName(req.names)
	if err != nil {
		return
	}
	key, ok := c.policyKey(l.signers, l.namespace)
	if !ok {
		return
	}
	patch := map[string]any{"signer": map[string]any{"ssh": map[string]any{"hosts": map[string]any{name: string(Allow)}}}}
	b, err := projpolicy.Encode(projpolicy.MergePatch(l.doc, patch))
	if err != nil || len(b) > wire.MaxDiff || len(l.cur) > wire.MaxDiff {
		return
	}
	path := policyPath(l.rootName, c.s.Policy.FileName)
	req.always = &always{l: l, name: name, path: path, new: b, key: key}
	req.question.Diff = &wire.Diff{Path: path, Old: string(l.cur), New: string(b)}
	req.question.Always = true
	req.question.AlwaysText = fmt.Sprintf("Always allows %s from %s, signed into its %s.", name, l.rootName, c.s.Policy.FileName)
}

func policyPath(rootName, file string) string {
	return strings.TrimSuffix(rootName, "/") + "/" + file
}

// policyKey is the first key held whose allowed signers line lets it sign
// in namespace.
func (c *conn) policyKey(signers *projpolicy.AllowedSigners, namespace string) (Key, bool) {
	for _, k := range c.s.Keys {
		pub, err := ssh.NewPublicKey(k.Signer.Public())
		if err != nil {
			continue
		}
		if _, err := signers.Allowed(pub, "", namespace, c.s.now()); err == nil {
			return k, true
		}
	}
	return Key{}, false
}

func signPolicy(k Key, namespace string, b []byte) ([]byte, error) {
	signer, err := ssh.NewSignerFromSigner(k.Signer)
	if err != nil {
		return nil, err
	}
	return projpolicy.Sign(rand.Reader, signer, namespace, b)
}

// saveAlways signs the new file and has the courier write it over the
// one read, if it is still that one. Whatever happens the sign asked
// for is made: it was allowed.
func (c *conn) saveAlways(req *request) {
	a := req.always
	attrs := []any{"root", a.l.root, "host", a.name, "old", a.l.digest, "digest", projpolicy.Digest(a.new)}
	sig, err := signPolicy(a.key, a.l.namespace, a.new)
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*courierTimeout)
		err = c.s.write(ctx, a.l.root, a.l.digest, a.new, sig)
		cancel()
	}
	if err == nil {
		c.s.Log.Info("always", append(attrs, "outcome", "written")...)
		return
	}
	c.s.Log.Warn("always", append(attrs, "outcome", "not saved", "err", err.Error())...)
	text := fmt.Sprintf("The rule for %s was not saved into %s: %s\nThis login was allowed once.",
		a.name, a.path, galleyask.Clean(err.Error()))
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.s.notify(ctx, c.s.User, text); err != nil {
			c.s.Log.Info("always notice not shown", "err", err.Error())
		}
	}()
}

// PolicySignExtension is the agent extension a person signs a project's
// policy file through: the signer shows the change in galley and, if
// allowed, signs the new bytes in the project's namespace.
const PolicySignExtension = "policy-sign@frisket"

// PolicySignRequest is policy-sign's contents, as JSON: the project's
// directory and its policy file's name, the new bytes, and the bytes the
// old signature was made over with that signature, if there are any.
type PolicySignRequest struct {
	Root   string `json:"root"`
	Name   string `json:"name"`
	New    []byte `json:"new"`
	Old    []byte `json:"old,omitempty"`
	OldSig []byte `json:"oldSig,omitempty"`
}

// PolicySignResponse is policy-sign's answer, after SSH_AGENT_SUCCESS: the
// armoured signature, or why there is none.
type PolicySignResponse struct {
	Sig   []byte `json:"sig,omitempty"`
	Error string `json:"error,omitempty"`
}

const (
	agentSuccess     = 6
	classPolicySign  = "policy sign"
	maxPolicyRequest = 4 << 20
)

func policySignReply(r PolicySignResponse) []byte {
	b, _ := json.Marshal(r)
	return append([]byte{agentSuccess}, b...)
}

func (c *conn) policySign(contents []byte) []byte {
	sig, err := c.policySignErr(contents)
	if err != nil {
		return policySignReply(PolicySignResponse{Error: err.Error()})
	}
	return policySignReply(PolicySignResponse{Sig: sig})
}

func (c *conn) policySignErr(contents []byte) ([]byte, error) {
	refuse := func(why string) error {
		c.s.Log.Warn("refused", "reason", "policy-sign: "+why, "chain", c.r.Chain, "anchor", c.r.Anchor)
		return errors.New(why)
	}
	if c.s.Policy == nil {
		return nil, refuse("this signer has no project policy configured")
	}
	if c.s.frisket(c.r) {
		return nil, refuse("frisket's main process serves sandboxes, and signs no policy")
	}
	if err := c.s.inHost(c.c); err != nil {
		return nil, refuse(err.Error())
	}
	if len(contents) > maxPolicyRequest {
		return nil, refuse("the request is too big")
	}
	var p PolicySignRequest
	dec := json.NewDecoder(bytes.NewReader(contents))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, refuse("request: " + err.Error())
	}
	switch {
	case !filepath.IsAbs(p.Root) || filepath.Clean(p.Root) != p.Root:
		return nil, refuse(fmt.Sprintf("root %q is not absolute and clean", p.Root))
	case p.Name != c.s.Policy.FileName:
		return nil, refuse(fmt.Sprintf("%q is not the policy file, %s", p.Name, c.s.Policy.FileName))
	case p.New == nil || !projpolicy.Canonical(p.New):
		return nil, refuse("the new file is not canonical: run frisket policy fmt on it first")
	case len(p.New) > wire.MaxDiff || len(p.Old) > wire.MaxDiff:
		return nil, refuse("the file is too big to show")
	}
	ns, err := projpolicy.Namespace(p.Root, c.s.Policy.Home)
	if err != nil {
		return nil, refuse(err.Error())
	}
	rootName, _ := projpolicy.RootName(p.Root, c.s.Policy.Home)
	signers, err := projpolicy.ReadAllowedSigners(c.s.Policy.AllowedSigners)
	if err != nil {
		return nil, refuse(err.Error())
	}
	key, ok := c.policyKey(signers, ns)
	if !ok {
		return nil, refuse("no key here is an allowed signer in " + ns)
	}

	path := policyPath(rootName, p.Name)
	r := c.r
	req := &request{class: classPolicySign, namespace: ns, dest: path, key: key}
	pub, _ := ssh.NewPublicKey(key.Signer.Public())
	req.keyFP = ssh.FingerprintSHA256(pub)
	lines := galleyask.Warnings(r)
	lines = append(lines, fmt.Sprintf("Signs %s as %s's policy, in %s.", p.Name, rootName, galleyask.Clean(ns)))
	old := ""
	switch {
	case p.OldSig == nil:
		lines = append(lines, "The old file was unsigned, so the whole file is shown as new.")
	case p.Old == nil:
		lines = append(lines, "The old file's signed bytes were not sent, so the whole file is shown as new.")
	default:
		if _, err := projpolicy.Verify(p.Old, p.OldSig, ns, signers, "", c.s.now()); err != nil {
			lines = append(lines, "The old signature does not verify over the old file sent ("+galleyask.Clean(err.Error())+"), so the whole file is shown as new.")
		} else {
			old = string(p.Old)
		}
	}
	lines = append(lines, fmt.Sprintf("key %s (%s)", req.keyFP, galleyask.Clean(key.Comment)))
	level := "normal"
	if r.Cut || r.SessionRoot {
		level = "warning"
	}
	req.question = galleyask.Question{
		Title: "sign " + path, Text: strings.Join(lines, "\n"), Level: level,
		Chain: galleyask.Chain(r), Diff: &wire.Diff{Path: path, Old: old, New: string(p.New)},
	}
	v := c.ask(req)
	c.record(req, v)
	if !v.sign {
		return nil, errors.New("refused")
	}
	sig, err := signPolicy(key, ns, p.New)
	if err != nil {
		c.s.Log.Error("sign failed", "key", req.keyFP, "err", err.Error())
		return nil, err
	}
	return sig, nil
}
