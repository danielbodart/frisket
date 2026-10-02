package sshroute

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// upstreamTimeout bounds the dial, the handshake and the login together. A
// variable only so a test can shrink it.
var upstreamTimeout = 10 * time.Second

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
	auth, done, err := r.auth(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
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
		Auth:              []ssh.AuthMethod{auth},
		HostKeyCallback:   r.checkHostKey,
		HostKeyAlgorithms: r.algorithms,
	}
	c, chans, reqs, err := ssh.NewClientConn(nc, r.Address.String(), cfg)
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

// auth is the route's credential as a login method, and what to close once
// the login is over: the agent's socket, which is dialled for each login and
// held no longer -- the user's agent is theirs, and frisket asks it for one
// signature.
func (r *Route) auth(ctx context.Context) (ssh.AuthMethod, func(), error) {
	if r.keyFile != "" {
		s, err := readKeyFile(r.keyFile)
		if err != nil {
			return nil, nil, err
		}
		if r.identity != "" && ssh.FingerprintSHA256(s.PublicKey()) != r.identity {
			return nil, nil, fmt.Errorf("key file %s is %s, not the identity %s", r.keyFile, ssh.FingerprintSHA256(s.PublicKey()), r.identity)
		}
		return ssh.PublicKeys(s), func() {}, nil
	}
	var d net.Dialer
	sock, err := d.DialContext(ctx, "unix", r.agent)
	if err != nil {
		return nil, nil, fmt.Errorf("agent: %w", err)
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
	return ssh.PublicKeysCallback(signers), func() { _ = sock.Close() }, nil
}

// readKeyFile reads an unencrypted private key. Its errors never quote the
// file.
func readKeyFile(path string) (ssh.Signer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("key file %s: %w", path, err)
	case len(b) > maxKeyFile:
		return nil, fmt.Errorf("key file %s is over %d bytes", path, maxKeyFile)
	}
	s, err := ssh.ParsePrivateKey(b)
	var pm *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &pm):
		return nil, fmt.Errorf("key file %s is encrypted, and frisket has no passphrase for it: use an agent", path)
	case err != nil:
		return nil, fmt.Errorf("key file %s is not a private key ssh reads", path)
	}
	return s, nil
}

// hostKeyError is whether err is the upstream presenting a key the route
// does not pin.
func hostKeyError(err error) bool {
	var hk *HostKeyError
	return errors.As(err, &hk)
}
