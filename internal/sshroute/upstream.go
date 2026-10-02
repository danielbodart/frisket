package sshroute

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// upstreamTimeout bounds the dial, the handshake and the login together. A
// variable only so a test can shrink it.
var upstreamTimeout = 10 * time.Second

// passwordCoolOff is how long a password a route's machine refused is not
// tried again, while the file still holds it: a workload that runs the same
// command in a loop would otherwise try a stale password once a connection,
// and a device that locks an account after so many tries locks the user out
// of their own machine. A variable only so a test can shrink it.
var passwordCoolOff = 5 * time.Minute

// maxKeyFile bounds a private key file: the largest OpenSSH writes, RSA
// 16384, is far under it.
const maxKeyFile = 64 << 10

// Dialer dials a route's upstream, at exactly that address and port.
type Dialer func(ctx context.Context, to netip.AddrPort) (net.Conn, error)

// pinnedDial is the default Dialer: a plain one, by literal address, never
// the egress dialer, whose classifier refuses the private addresses SSH
// routes are for, and never a name a resolver could answer differently.
func pinnedDial(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", to.String())
}

// HostKeyError is an upstream that presented a key the route does not pin:
// refused, never learnt, and never put to a person.
type HostKeyError struct {
	Type        string
	Fingerprint string
	Certificate bool
}

func (e *HostKeyError) Error() string {
	if e.Certificate {
		return fmt.Sprintf("host presented a certificate (%s), and the route pins keys", e.Type)
	}
	return fmt.Sprintf("host key %s %s is not one the route pins", e.Type, e.Fingerprint)
}

// checkHostKey is the route's known_hosts: the key must be one of those
// pinned, byte for byte.
func (r *Route) checkHostKey(_ string, _ net.Addr, key ssh.PublicKey) error {
	if c, ok := key.(*ssh.Certificate); ok {
		return &HostKeyError{Type: c.Type(), Fingerprint: ssh.FingerprintSHA256(c.Key), Certificate: true}
	}
	m := key.Marshal()
	for _, p := range r.hostKeys {
		if bytes.Equal(m, p.Marshal()) {
			return nil
		}
	}
	return &HostKeyError{Type: key.Type(), Fingerprint: ssh.FingerprintSHA256(key)}
}

// dialUpstream logs in to the route's machine: the dial, the handshake
// against the pinned keys, and the login with the route's credential, all
// within upstreamTimeout.
func (r *Route) dialUpstream(ctx context.Context, dial Dialer) (*ssh.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	auths, done, err := r.auth(ctx)
	if err != nil {
		return nil, err
	}
	var login error
	defer func() { done(login) }()
	nc, err := dial(ctx, r.Address)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	defer stop()
	cfg := &ssh.ClientConfig{
		User:              r.User,
		Auth:              auths,
		HostKeyCallback:   r.checkHostKey,
		HostKeyAlgorithms: r.algorithms,
	}
	c, chans, reqs, err := ssh.NewClientConn(nc, r.Address.String(), cfg)
	login = err
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	if !stop() {
		_ = c.Close()
		return nil, ctx.Err()
	}
	_ = nc.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// credentialError is a route's credential that could not be read: err in
// full, the file's or the socket's path with it, for the journal, and why
// alone for the sandbox, which is told nothing of where frisket keeps a
// route's credential.
type credentialError struct {
	why string
	err error
}

func (e *credentialError) Error() string { return e.err.Error() }
func (e *credentialError) Unwrap() error { return e.err }

// credential is err, as a credential that could not be read for why.
func credential(why string, err error) error {
	return &credentialError{why: why, err: err}
}

// sandboxError is err as the sandbox is told it: a credential's error
// without its path.
func sandboxError(err error) string {
	var ce *credentialError
	if errors.As(err, &ce) {
		return "the route's credential: " + ce.why
	}
	return err.Error()
}

// auth is the route's credential as login methods, and what to do once the
// login is over, given how it ended: close the agent's socket, which is
// dialled for each login and held no longer -- the user's agent is theirs,
// and frisket asks it for one signature -- or remember a password the
// machine refused.
func (r *Route) auth(ctx context.Context) ([]ssh.AuthMethod, func(error), error) {
	if r.passwordFile != "" {
		pw, err := readPasswordFile(r.passwordFile)
		if err != nil {
			return nil, nil, err
		}
		sum := sha256.Sum256([]byte(pw))
		if err := r.refusal.check(sum); err != nil {
			return nil, nil, err
		}
		tried := false
		return passwordAuth(pw, &tried), func(err error) { r.refusal.record(sum, tried, err) }, nil
	}
	if r.keyFile != "" {
		s, err := readKeyFile(r.keyFile)
		if err != nil {
			return nil, nil, err
		}
		if r.identity != "" && ssh.FingerprintSHA256(s.PublicKey()) != r.identity {
			return nil, nil, credential("the key file is not the route's identity",
				fmt.Errorf("key file %s is %s, not the identity %s", r.keyFile, ssh.FingerprintSHA256(s.PublicKey()), r.identity))
		}
		return []ssh.AuthMethod{ssh.PublicKeys(s)}, func(error) {}, nil
	}
	var d net.Dialer
	sock, err := d.DialContext(ctx, "unix", r.agent)
	if err != nil {
		return nil, nil, credential("the agent did not answer", fmt.Errorf("agent: %w", err))
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = sock.SetDeadline(dl)
	}
	ag := agent.NewClient(sock)
	signers := func() ([]ssh.Signer, error) {
		all, err := ag.Signers()
		if err != nil {
			return nil, fmt.Errorf("agent: %w", err)
		}
		if r.identity == "" {
			return all, nil
		}
		for _, s := range all {
			if ssh.FingerprintSHA256(s.PublicKey()) == r.identity {
				return []ssh.Signer{s}, nil
			}
		}
		return nil, fmt.Errorf("agent holds no key %s", r.identity)
	}
	return []ssh.AuthMethod{ssh.PublicKeysCallback(signers)}, func(error) { _ = sock.Close() }, nil
}

// refusal is the password a route's machine last refused, by its hash, and
// when: a password is never held past the login it is read for.
type refusal struct {
	mu  sync.Mutex
	sum [sha256.Size]byte
	at  time.Time
}

// check is an error where the password summed to sum was refused within
// passwordCoolOff: it is not tried again until the file holds another, or
// that has passed.
func (f *refusal) check(sum [sha256.Size]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.at.IsZero() || f.sum != sum {
		return nil
	}
	if ago := time.Since(f.at); ago < passwordCoolOff {
		why := fmt.Sprintf("the machine refused this password %s ago, and it is not tried again until the password file changes or %s has passed",
			ago.Round(time.Second), passwordCoolOff)
		return credential(why, errors.New("password file: "+why))
	}
	return nil
}

// record remembers how a login with the password summed to sum ended: one
// that failed once the password was given counts as refused -- a device
// that locks an account counts it so, whatever ended the login -- and one
// that succeeded forgets any refusal.
func (f *refusal) record(sum [sha256.Size]byte, tried bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case err == nil:
		f.at = time.Time{}
	case tried:
		f.sum, f.at = sum, time.Now()
	}
}

// maxPasswordFile bounds a password file: a password is a line, and a file
// far longer than one is not a password file.
const maxPasswordFile = 4 << 10

// maxInteractiveRounds bounds the rounds of keyboard-interactive a login
// answers: one that asks for the password, and those around it that ask
// nothing -- OpenSSH's PAM ends with an empty one.
const maxInteractiveRounds = 3

// passwordAuth logs in with pw by "password", or by "keyboard-interactive"
// where a server offers only that, as one with PAM behind it may: every
// prompt that hides what is typed is answered with the password, once. A
// prompt that echoes is asking for something other than a password -- a
// user name, a code to confirm -- and a second round that hides one is
// asking again, because the password was wrong or for a second factor: each
// ends the login rather than send the password where it was not asked for.
// The password is tried once in all: one refused by "password" is not
// offered again by "keyboard-interactive", since a device that locks an
// account counts each.
//
// tried is set once the password has been given.
func passwordAuth(pw string, tried *bool) []ssh.AuthMethod {
	password := ssh.PasswordCallback(func() (string, error) {
		*tried = true
		return pw, nil
	})
	rounds := 0
	interactive := ssh.KeyboardInteractive(func(_, _ string, questions []string, echos []bool) ([]string, error) {
		rounds++
		switch {
		case rounds > maxInteractiveRounds:
			return nil, fmt.Errorf("keyboard-interactive: more than %d rounds", maxInteractiveRounds)
		case len(questions) == 0:
			return nil, nil
		case *tried:
			return nil, errors.New("keyboard-interactive: asked for the password again, after it was given: it is wrong, or the server wants more than a password")
		}
		answers := make([]string, len(questions))
		for i := range questions {
			if echos[i] {
				return nil, errors.New("keyboard-interactive: a prompt that echoes, which asks for something other than a password")
			}
			answers[i] = pw
		}
		*tried = true
		return answers, nil
	})
	return []ssh.AuthMethod{password, interactive}
}

// readPasswordFile reads a password: the file's bytes, less one trailing
// newline. Its errors never quote what the file holds; they name its path,
// for the journal, and are credentialErrors, so the sandbox is not told it.
func readPasswordFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", credential("the password file could not be opened", fmt.Errorf("password file: %w", err))
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxPasswordFile+1))
	switch {
	case err != nil:
		return "", credential("the password file could not be read", fmt.Errorf("password file %s: %w", path, err))
	case len(b) > maxPasswordFile:
		return "", credential(fmt.Sprintf("the password file is over %d bytes", maxPasswordFile),
			fmt.Errorf("password file %s is over %d bytes", path, maxPasswordFile))
	}
	if n, ok := bytes.CutSuffix(b, []byte("\n")); ok {
		b, _ = bytes.CutSuffix(n, []byte("\r"))
	}
	if len(b) == 0 {
		return "", credential("the password file is empty", fmt.Errorf("password file %s is empty", path))
	}
	return string(b), nil
}

// readKeyFile reads an unencrypted private key. Its errors never quote
// what the file holds; they name its path, as readPasswordFile's do.
func readKeyFile(path string) (ssh.Signer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, credential("the key file could not be opened", fmt.Errorf("key file: %w", err))
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	switch {
	case err != nil:
		return nil, credential("the key file could not be read", fmt.Errorf("key file %s: %w", path, err))
	case len(b) > maxKeyFile:
		return nil, credential(fmt.Sprintf("the key file is over %d bytes", maxKeyFile),
			fmt.Errorf("key file %s is over %d bytes", path, maxKeyFile))
	}
	s, err := ssh.ParsePrivateKey(b)
	var pm *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &pm):
		return nil, credential("the key file is encrypted, and frisket has no passphrase for it: use an agent",
			fmt.Errorf("key file %s is encrypted, and frisket has no passphrase for it: use an agent", path))
	case err != nil:
		return nil, credential("the key file is not a private key ssh reads", fmt.Errorf("key file %s is not a private key ssh reads", path))
	}
	return s, nil
}

// hostKeyError is whether err is the upstream presenting a key the route
// does not pin.
func hostKeyError(err error) bool {
	var hk *HostKeyError
	return errors.As(err, &hk)
}
