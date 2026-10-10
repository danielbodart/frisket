// Package tpmkey holds SSH keys in the TPM, in stock ssh-tpm-agent's file
// format: ECDSA P-256, empty auth, under the transient H-2 ECC primary of the
// owner hierarchy. It is the only importer of go-tpm. It never touches a
// persistent handle.
package tpmkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"golang.org/x/crypto/ssh"
)

var (
	ErrCleared = errors.New("TPM cleared or a different chip")
	ErrLockout = errors.New("TPM is in dictionary-attack lockout; signing resumes when it decays")
)

type Key struct {
	Path    string
	Comment string
	Public  *ecdsa.PublicKey
	tk      *keyfile.TPMKey
}

// Load parses every *.tpm in dir without touching the TPM. A file that does
// not parse is skipped with one log line.
func Load(dir string, log *slog.Logger) ([]*Key, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.tpm"))
	if err != nil {
		return nil, err
	}
	var keys []*Key
	for _, path := range paths {
		k, err := loadFile(path)
		if err != nil {
			log.Warn("tpm key skipped", "file", path, "err", err)
			continue
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func loadFile(path string) (*Key, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tk, err := keyfile.Decode(b)
	if err != nil {
		return nil, err
	}
	if !tk.Keytype.Equal(keyfile.OIDLoadableKey) {
		return nil, errors.New("not a loadable key")
	}
	if !tk.EmptyAuth {
		return nil, errors.New("has a passphrase")
	}
	if tk.Parent != tpm2.TPMRHOwner {
		return nil, fmt.Errorf("parent is 0x%x, not the owner hierarchy", uint32(tk.Parent))
	}
	pub, err := tk.Pubkey.Contents()
	if err != nil {
		return nil, err
	}
	if pub.Type != tpm2.TPMAlgECC || !pub.ObjectAttributes.SignEncrypt {
		return nil, errors.New("not an ECDSA P-256 signing key")
	}
	pk, err := tpm2.Pub(*pub)
	if err != nil {
		return nil, err
	}
	ec, ok := pk.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("not an ECDSA P-256 signing key")
	}
	return &Key{Path: path, Comment: tk.Description, Public: ec, tk: tk}, nil
}

// TPM is one long-lived connection with the parent and every key used so far
// kept loaded on it.
type TPM struct {
	open   func() (transport.TPMCloser, error)
	mu     sync.Mutex
	tpm    transport.TPMCloser
	parent *tpm2.AuthHandle
	loaded map[*Key]tpm2.AuthHandle
}

func Device(path string) *TPM {
	return New(func() (transport.TPMCloser, error) { return linuxtpm.Open(path) })
}

func New(open func() (transport.TPMCloser, error)) *TPM {
	return &TPM{open: open, loaded: map[*Key]tpm2.AuthHandle{}}
}

func (k *Key) Signer(t *TPM) crypto.Signer { return signer{k, t} }

type signer struct {
	k *Key
	t *TPM
}

func (s signer) Public() crypto.PublicKey { return s.k.Public }

func (s signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("%v is not SHA-256", opts.HashFunc())
	}
	return s.t.sign(s.k, digest)
}

// sign retries once on a fresh connection, except on integrity or lockout.
func (t *TPM) sign(k *Key, digest []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	sig, err := t.trySign(k, digest)
	if err == nil || errors.Is(err, ErrCleared) || errors.Is(err, ErrLockout) {
		return sig, err
	}
	t.reset()
	return t.trySign(k, digest)
}

func (t *TPM) trySign(k *Key, digest []byte) ([]byte, error) {
	if err := t.connect(); err != nil {
		return nil, err
	}
	h, ok := t.loaded[k]
	if !ok {
		rsp, err := tpm2.Load{ParentHandle: *t.parent, InPrivate: k.tk.Privkey, InPublic: k.tk.Pubkey}.Execute(t.tpm)
		if err != nil {
			return nil, named(err)
		}
		h = tpm2.AuthHandle{Handle: rsp.ObjectHandle, Name: rsp.Name, Auth: tpm2.PasswordAuth(nil)}
		t.loaded[k] = h
	}
	rsp, err := tpm2.Sign{
		KeyHandle: h,
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
		},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(t.tpm)
	if err != nil {
		return nil, named(err)
	}
	return keyfile.EncodeSignatureASN1(&rsp.Signature)
}

func (t *TPM) connect() error {
	if t.tpm == nil {
		tpm, err := t.open()
		if err != nil {
			return err
		}
		t.tpm = tpm
	}
	if t.parent == nil {
		parent, _, err := keyfile.CreateSRK(keyfile.NewTPMSession(t.tpm), tpm2.TPMRHOwner, nil)
		if err != nil {
			return err
		}
		t.parent = parent
	}
	return nil
}

// reset closes the connection, which on /dev/tpmrm0 flushes everything loaded
// on it.
func (t *TPM) reset() {
	if t.tpm != nil {
		t.tpm.Close()
	}
	t.tpm = nil
	t.parent = nil
	clear(t.loaded)
}

func named(err error) error {
	switch {
	case errors.Is(err, tpm2.TPMRCIntegrity):
		return fmt.Errorf("%w: %v", ErrCleared, err)
	case errors.Is(err, tpm2.TPMRCLockout):
		return fmt.Errorf("%w: %v", ErrLockout, err)
	}
	return err
}

// Generate makes a key the way stock ssh-tpm-keygen does, DA protection on
// unless noDA, and writes dir/id_ecdsa.tpm and dir/id_ecdsa.pub in its format.
func Generate(t *TPM, dir, comment string, noDA bool) (*Key, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.connect(); err != nil {
		return nil, err
	}
	rsp, err := tpm2.Create{
		ParentHandle: *t.parent,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				NoDA:                noDA,
				SignEncrypt:         true,
				Decrypt:             true,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme:  tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
			}),
		}),
	}.Execute(t.tpm)
	if err != nil {
		return nil, named(err)
	}
	tk := keyfile.NewTPMKey(keyfile.OIDLoadableKey, rsp.OutPublic, rsp.OutPrivate, keyfile.WithDescription(comment))
	path := filepath.Join(dir, "id_ecdsa.tpm")
	if err := writeNew(path, tk.Bytes(), 0o600); err != nil {
		return nil, err
	}
	k, err := loadFile(path)
	if err != nil {
		return nil, err
	}
	pub, err := ssh.NewPublicKey(k.Public)
	if err != nil {
		return nil, err
	}
	line := fmt.Sprintf("%s %s\n", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), comment)
	if err := writeNew(filepath.Join(dir, "id_ecdsa.pub"), []byte(line), 0o644); err != nil {
		return nil, err
	}
	return k, nil
}

func writeNew(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
