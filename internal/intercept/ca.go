package intercept

import (
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// The CA's files, inside the directory LoadOrCreateCA is given.
const (
	CAKeyFile  = "ca.key"
	CACertFile = "ca.crt"
)

const (
	caLifetime = 10 * 365 * 24 * time.Hour
	// A leaf lives a week and is re-minted a day before it ends, so no
	// connection is ever handed a certificate about to expire under it.
	leafLifetime = 7 * 24 * time.Hour
	leafRenew    = 24 * time.Hour
	// Clients and the host disagree about the time by more than nothing, and a
	// certificate that is "not yet valid" to a sandbox is a refusal nobody can
	// explain from frisket's side.
	backdate = time.Hour
	// DefaultLeafCacheSize bounds the minted certificates held. Names are
	// already bounded by the routes, since an unknown name is refused before
	// anything is minted; the bound is here so that stays true if that ever
	// changes.
	DefaultLeafCacheSize = 256
)

// CA is the per-machine certificate authority sandboxes trust, and the leaf
// certificates minted from it.
//
// Whoever holds the key can impersonate any site TO A SANDBOX (PLAN.md,
// decision 4). That is the blast radius: it is generated here, never leaves
// this machine, and is trusted nowhere but inside sandboxes.
type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer

	// Now is the clock leaves are minted against; tests move it.
	Now func() time.Time

	mu    sync.Mutex
	max   int
	lru   *list.List // of *leaf, most recently used at the front
	byKey map[string]*list.Element
}

type leaf struct {
	name     string
	cert     *tls.Certificate
	notAfter time.Time
}

// LoadOrCreateCA loads the CA from dir, creating it the first time.
//
// It never regenerates a CA it cannot load. A CA that silently changed would
// break trust in every sandbox at once, and the most likely reason a load
// fails -- a key with permissions nobody set on purpose, one file of the two
// missing -- is one the operator needs to see rather than have papered over.
func LoadOrCreateCA(dir string) (*CA, error) {
	keyPath := filepath.Join(dir, CAKeyFile)
	certPath := filepath.Join(dir, CACertFile)

	_, keyErr := os.Lstat(keyPath)
	_, certErr := os.Lstat(certPath)
	switch {
	case keyErr == nil && certErr == nil:
		return loadCA(keyPath, certPath)
	case errors.Is(keyErr, fs.ErrNotExist) && errors.Is(certErr, fs.ErrNotExist):
		return createCA(dir, keyPath, certPath)
	case keyErr != nil && !errors.Is(keyErr, fs.ErrNotExist):
		return nil, fmt.Errorf("intercept: CA key: %w", keyErr)
	case certErr != nil && !errors.Is(certErr, fs.ErrNotExist):
		return nil, fmt.Errorf("intercept: CA certificate: %w", certErr)
	default:
		return nil, fmt.Errorf("intercept: %s has one of %s and %s but not the other; refusing to guess which to trust",
			dir, CAKeyFile, CACertFile)
	}
}

func createCA(dir, keyPath, certPath string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("intercept: CA directory: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			Organization: []string{"frisket"},
			CommonName:   "frisket sandbox CA " + host,
		},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		// It signs leaves and nothing else: no intermediate can be made under
		// it, so the key is the only thing that can mint for a sandbox.
		MaxPathLen:     0,
		MaxPathLenZero: true,
		KeyUsage:       x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	// The key first, created exclusively and 0600 from the start -- never
	// written and then chmodded, which leaves a window where it is readable.
	// If the certificate write then fails, the key is removed, so the next
	// start sees neither file rather than the half a CA refused above.
	if err := writeExclusive(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, fmt.Errorf("intercept: CA key: %w", err)
	}
	if err := writeExclusive(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		_ = os.Remove(keyPath)
		return nil, fmt.Errorf("intercept: CA certificate: %w", err)
	}
	return loadCA(keyPath, certPath)
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

func loadCA(keyPath, certPath string) (*CA, error) {
	// Refuse a key anyone else can read, as ssh does, rather than use it:
	// a readable CA key is every sandbox's trust handed to whoever read it.
	// Lstat, so a symlink to somewhere else is refused too rather than
	// followed to a file whose permissions were never checked.
	st, err := os.Lstat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("intercept: CA key: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("intercept: CA key %s is not a regular file", keyPath)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("intercept: CA key %s has mode %04o; it must not be readable or writable by group or others", keyPath, perm)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("intercept: CA key: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("intercept: CA key %s is not a PEM PKCS#8 private key", keyPath)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("intercept: CA key %s: %w", keyPath, err)
	}
	key, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("intercept: CA key %s cannot sign", keyPath)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("intercept: CA certificate: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("intercept: CA certificate %s is not a PEM certificate", certPath)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("intercept: CA certificate %s: %w", certPath, err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("intercept: CA certificate %s is not a CA", certPath)
	}
	// An expired CA would load and mint leaves that every sandbox refuses.
	// Replacing it is a decision -- every sandbox's trust changes -- so it is
	// refused here, where it can be seen, and not regenerated.
	if now := time.Now(); now.After(cert.NotAfter) {
		return nil, fmt.Errorf("intercept: CA certificate %s expired at %s; remove both files to generate a new CA, and redistribute it",
			certPath, cert.NotAfter.UTC().Format(time.RFC3339))
	}
	// The pair must be a pair. A certificate for some other key would load,
	// mint leaves no sandbox can verify, and fail every connection with an
	// error that points at the sandbox instead of here.
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, fmt.Errorf("intercept: %s is not the certificate for %s", certPath, keyPath)
	}

	return &CA{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		key:     key,
		Now:     time.Now,
		max:     DefaultLeafCacheSize,
		lru:     list.New(),
		byKey:   map[string]*list.Element{},
	}, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ae, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ae.Equal(b)
}

// CertPEM is the CA certificate, for distribution to sandboxes. It is the one
// thing a sandbox is told (PLAN.md): which authority to trust.
func (ca *CA) CertPEM() []byte { return append([]byte(nil), ca.certPEM...) }

// Certificate is the parsed CA certificate.
func (ca *CA) Certificate() *x509.Certificate { return ca.cert }

// SetCacheSize changes the bound on minted leaves held.
func (ca *CA) SetCacheSize(n int) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if n < 1 {
		n = 1
	}
	ca.max = n
	ca.evict()
}

// Leaf returns a certificate for name, minting one if none is cached or the
// cached one is near its end. The caller has already decided name is a route:
// this mints for whatever it is given.
func (ca *CA) Leaf(name string) (*tls.Certificate, error) {
	now := ca.Now()
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if el, ok := ca.byKey[name]; ok {
		l := el.Value.(*leaf)
		if now.Add(leafRenew).Before(l.notAfter) {
			ca.lru.MoveToFront(el)
			return l.cert, nil
		}
		ca.lru.Remove(el)
		delete(ca.byKey, name)
	}

	// Minting under the lock: a P-256 key and a signature are tens of
	// microseconds, and holding it means a burst of handshakes for one name
	// mints one certificate rather than one each.
	cert, notAfter, err := ca.mint(name, now)
	if err != nil {
		return nil, err
	}
	ca.byKey[name] = ca.lru.PushFront(&leaf{name: name, cert: cert, notAfter: notAfter})
	ca.evict()
	return cert, nil
}

func (ca *CA) evict() {
	for ca.lru.Len() > ca.max {
		el := ca.lru.Back()
		ca.lru.Remove(el)
		delete(ca.byKey, el.Value.(*leaf).name)
	}
}

// cached reports how many leaves are held, for tests of the bound.
func (ca *CA) cached() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.lru.Len()
}

func (ca *CA) mint(name string, now time.Time) (*tls.Certificate, time.Time, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, err
	}
	notAfter := now.Add(leafLifetime)
	if notAfter.After(ca.cert.NotAfter) {
		notAfter = ca.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             now.Add(-backdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		return nil, time.Time{}, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, notAfter, nil
}

// serial is 128 random bits, positive, as the baseline requirements ask.
func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		// crypto/rand does not fail on Linux; if it ever does, nothing that
		// follows is safe to do either.
		panic(err)
	}
	return n.Add(n, big.NewInt(1))
}
