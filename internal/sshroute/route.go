package sshroute

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/danielbodart/frisket/execrule"
	"github.com/danielbodart/frisket/policy"
)

// Route is one SSH route, checked: where it goes, who it logs in as and
// with what, the keys the machine must present, and the rules its commands
// are decided by. Compile is the only way to make one.
type Route struct {
	Name    string
	Address netip.AddrPort
	User    string

	hostKeys []ssh.PublicKey
	// algorithms are the host key algorithms the upstream is asked for:
	// those of the pinned keys and no others, so that a machine with a key
	// that is not pinned as well is asked for the one that is.
	algorithms []string
	agent      string
	keyFile    string
	identity   string
	rules      *execrule.Rules
}

// Decide is what the route's rules say about command.
func (r *Route) Decide(command string) Decision {
	return decision(r.rules.Decide(command))
}

// Reserved is what a session's SSH routes must stay clear of, which the
// session's document decides elsewhere.
type Reserved struct {
	// Addrs are addresses no route may name: frisket's service and dummy
	// addresses, and the Docker project's. Each is steered to frisket for
	// something else, and an SSH route there would take it.
	Addrs []netip.Addr
	// Hosts are the intercepted hosts, a name or "*.suffix", and the Docker
	// route's names: no route's name may be one, or fall under a wildcard.
	// The session answers those names with an address, and a route's name is
	// an ssh_config alias that must mean the route alone.
	Hosts []string
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)

// userRE is a login name, and no more: the user is written as it is into
// the sandbox's ssh_config, where a quote, a %, a # or a space is ssh's own
// syntax -- and ssh reads every line of the file whatever Host it is under,
// so one route's user could break every ssh in the sandbox.
var userRE = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._@-]*$`)

// fingerprintRE is ssh-keygen's SHA256 fingerprint: unpadded base64 of 32
// bytes.
var fingerprintRE = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// maxName bounds a route's name as DNS bounds a name.
const maxName = 253

// maxUser bounds a login name as Linux does, LOGIN_NAME_MAX less its NUL.
const maxUser = 255

// maxRoutes bounds a document's SSH routes. Each is a Host block in the
// sandbox's ssh_config and a destination in its relay, and Open answers with
// both in one control message: bounded here, with every name and user at its
// longest, they take about half of it, so a document's SSH routes cannot pass check
// and fail at launch for being too long to answer. A few dozen machines is
// more than a session runs commands on.
const maxRoutes = 32

// Compile checks a document's SSH routes, together and against what the
// rest of the document reserves, and prepares them. It opens nothing: the
// agent and the key file are read at login, so a document is checked where
// neither exists.
func Compile(routes []policy.SSHRoute, reserved Reserved) ([]*Route, error) {
	if len(routes) > maxRoutes {
		return nil, fmt.Errorf("ssh: %d routes, more than the %d a session may have", len(routes), maxRoutes)
	}
	out := make([]*Route, 0, len(routes))
	names := map[string]bool{}
	addrs := map[netip.AddrPort]string{}
	for _, pr := range routes {
		r, err := compile(pr, reserved)
		if err != nil {
			if pr.Name == "" {
				return nil, fmt.Errorf("ssh route: %w", err)
			}
			return nil, fmt.Errorf("ssh route %s: %w", pr.Name, err)
		}
		if names[r.Name] {
			return nil, fmt.Errorf("ssh route %s: the name is another route's", r.Name)
		}
		names[r.Name] = true
		if other, ok := addrs[r.Address]; ok {
			return nil, fmt.Errorf("ssh route %s: address %s is route %s's too", r.Name, r.Address, other)
		}
		addrs[r.Address] = r.Name
		out = append(out, r)
	}
	return out, nil
}

func compile(pr policy.SSHRoute, reserved Reserved) (*Route, error) {
	r := &Route{Name: pr.Name, User: pr.User}
	if err := checkName(pr.Name, reserved.Hosts); err != nil {
		return nil, err
	}
	ap, err := checkAddress(pr, reserved.Addrs)
	if err != nil {
		return nil, err
	}
	r.Address = ap
	if len(pr.User) > maxUser || !userRE.MatchString(pr.User) {
		return nil, fmt.Errorf("user %q: a login name of at most %d bytes, of letters, digits and . _ @ -, not starting with - or @", pr.User, maxUser)
	}
	if r.hostKeys, r.algorithms, err = hostKeys(pr.HostKeys); err != nil {
		return nil, err
	}
	switch {
	case pr.Agent != "" && pr.KeyFile != "":
		return nil, errors.New("agent and keyFile: frisket logs in with one of them")
	case pr.Agent != "":
		if err := checkPath(pr.Agent); err != nil {
			return nil, fmt.Errorf("agent %w", err)
		}
		r.agent = pr.Agent
	case pr.KeyFile != "":
		if err := checkPath(pr.KeyFile); err != nil {
			return nil, fmt.Errorf("keyFile %w", err)
		}
		r.keyFile = pr.KeyFile
	default:
		return nil, errors.New("no agent and no keyFile: frisket has nothing to log in with")
	}
	if pr.Identity != "" && !fingerprintRE.MatchString(pr.Identity) {
		return nil, fmt.Errorf("identity %q: a key's fingerprint, SHA256: and 43 characters of base64, as ssh-keygen -l prints it", pr.Identity)
	}
	r.identity = pr.Identity
	if r.rules, err = execrule.Compile(pr); err != nil {
		return nil, err
	}
	return r, nil
}

func checkName(name string, hosts []string) error {
	if len(name) > maxName || !nameRE.MatchString(name) {
		return fmt.Errorf("name %q: lower-case letters, digits, dots and hyphens, starting with a letter or digit", name)
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return fmt.Errorf("name %q is an address: a route's name is what the sandbox calls it, and its address is the address", name)
	}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		suffix, wild := strings.CutPrefix(h, "*.")
		if name == h || wild && strings.HasSuffix(name, "."+suffix) {
			return fmt.Errorf("name %s is %s's, or under it: the session answers it with an address, and a route's name means the route alone", name, h)
		}
	}
	return nil
}

// checkAddress reads the route's address and refuses one frisket must not
// reach for it. A private address is exactly what an SSH route is for --
// egress refuses it as raw TCP, and still does -- but not this host's own
// loopback, a link-local address and the metadata services on them, a
// multicast group, or an address that is steered to frisket for something
// else.
func checkAddress(pr policy.SSHRoute, reserved []netip.Addr) (netip.AddrPort, error) {
	ap, err := pr.AddrPort()
	if err != nil {
		return netip.AddrPort{}, err
	}
	a := ap.Addr()
	switch {
	case a.Zone() != "":
		return netip.AddrPort{}, fmt.Errorf("address %q has a zone: a route is a machine, not an interface", pr.Address)
	case a.Is4In6():
		return netip.AddrPort{}, fmt.Errorf("address %q: write an IPv4 address as IPv4", pr.Address)
	case a.IsUnspecified(), a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsInterfaceLocalMulticast(), a.IsMulticast(), a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return netip.AddrPort{}, fmt.Errorf("address %q: not unspecified, loopback, link-local, multicast or broadcast", pr.Address)
	case ap.Port() == 53:
		return netip.AddrPort{}, fmt.Errorf("address %q: port 53 is the session's DNS", pr.Address)
	}
	for _, r := range reserved {
		if r.Unmap().WithZone("") == a {
			return netip.AddrPort{}, fmt.Errorf("address %q is frisket's own, or the Docker project's", pr.Address)
		}
	}
	return ap, nil
}

// checkPath holds a credential's path to an absolute, clean one: the daemon
// has no working directory of the user's, and no SSH_AUTH_SOCK either.
func checkPath(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("%q: an absolute, clean path", p)
	}
	return nil
}

// hostKeys reads the pinned keys, one to an entry, and the host key
// algorithms that ask for them.
func hostKeys(lines []string) ([]ssh.PublicKey, []string, error) {
	if len(lines) == 0 {
		return nil, nil, errors.New("no hostKeys: the machine's own key is the only trust in it, and frisket never learns one on first use")
	}
	var keys []ssh.PublicKey
	var algos []string
	add := func(a ...string) {
		for _, x := range a {
			if !slices.Contains(algos, x) {
				algos = append(algos, x)
			}
		}
	}
	for i, l := range lines {
		if strings.ContainsAny(l, "\r\n") {
			return nil, nil, fmt.Errorf("hostKeys[%d]: one key, on one line", i)
		}
		k, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(l))
		switch {
		case err != nil:
			return nil, nil, fmt.Errorf("hostKeys[%d]: not a key as authorized_keys writes one: %w", i, err)
		case len(options) > 0 || len(bytes.TrimSpace(rest)) > 0:
			return nil, nil, fmt.Errorf("hostKeys[%d]: a key alone, \"ssh-ed25519 AAAA... [comment]\", with no host, marker or option before it", i)
		}
		if _, ok := k.(*ssh.Certificate); ok {
			return nil, nil, fmt.Errorf("hostKeys[%d] is a certificate: pin the machine's key itself", i)
		}
		switch k.Type() {
		case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
			add(k.Type())
		case ssh.KeyAlgoRSA:
			// The SHA-2 signatures first. ssh-rsa, SHA-1, last, for a host
			// too old for anything else: the key is pinned, so what SHA-1
			// weakens is only the signature over this one handshake.
			add(ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
		default:
			return nil, nil, fmt.Errorf("hostKeys[%d]: %s is not a host key type frisket asks for: ed25519, ECDSA or RSA", i, k.Type())
		}
		for _, p := range keys {
			if bytes.Equal(p.Marshal(), k.Marshal()) {
				return nil, nil, fmt.Errorf("hostKeys[%d] is listed twice", i)
			}
		}
		keys = append(keys, k)
	}
	for _, k := range keys {
		if k.Type() == ssh.KeyAlgoRSA {
			add(ssh.KeyAlgoRSA)
		}
	}
	return keys, algos, nil
}
