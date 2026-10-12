package projpolicy

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHSIG, as OpenSSH's PROTOCOL.sshsig and sshsig.c define it.
const (
	sigMagic   = "SSHSIG"
	sigVersion = 1
	armorBegin = "-----BEGIN SSH SIGNATURE-----"
	armorEnd   = "-----END SSH SIGNATURE-----"
	armorWidth = 70 // sshbuf_dtob64's, so Sign's output is byte for byte ssh-keygen's shape
)

// Signature is one parsed SSHSIG blob.
type Signature struct {
	Key       ssh.PublicKey
	Namespace string
	HashAlg   string // sha256 or sha512
	Sig       *ssh.Signature
}

type sigBlob struct {
	Version   uint32
	PublicKey []byte
	Namespace string
	Reserved  []byte
	HashAlg   string
	Signature []byte
}

// ParseSignature reads an armoured SSHSIG, as ssh-keygen -Y sign writes it:
// anything around the armour lines is refused, as is a blob with trailing
// bytes, another version, a hash other than sha256 or sha512, or a
// certificate in place of a key.
func ParseSignature(armored []byte) (*Signature, error) {
	text := strings.ReplaceAll(string(armored), "\r\n", "\n")
	text = strings.TrimRight(text, "\n")
	body, ok := strings.CutPrefix(text, armorBegin+"\n")
	if !ok {
		return nil, errors.New("not an armoured SSH signature: no BEGIN SSH SIGNATURE line first")
	}
	body, ok = strings.CutSuffix(body, "\n"+armorEnd)
	if !ok {
		return nil, errors.New("not an armoured SSH signature: no END SSH SIGNATURE line last")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("the signature's base64: %w", err)
	}
	return parseBlob(raw)
}

func parseBlob(raw []byte) (*Signature, error) {
	rest, ok := bytes.CutPrefix(raw, []byte(sigMagic))
	if !ok {
		return nil, errors.New("not SSHSIG: no magic")
	}
	var b sigBlob
	if err := ssh.Unmarshal(rest, &b); err != nil {
		return nil, fmt.Errorf("SSHSIG blob: %w", err)
	}
	if b.Version != sigVersion {
		return nil, fmt.Errorf("SSHSIG version %d, not %d", b.Version, sigVersion)
	}
	if _, err := hasher(b.HashAlg); err != nil {
		return nil, err
	}
	key, err := ssh.ParsePublicKey(b.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("the signature's key: %w", err)
	}
	if _, isCert := key.(*ssh.Certificate); isCert {
		return nil, errors.New("the signature's key is a certificate, which a project policy is never signed by")
	}
	sig := new(ssh.Signature)
	if err := ssh.Unmarshal(b.Signature, sig); err != nil {
		return nil, fmt.Errorf("the signature: %w", err)
	}
	return &Signature{Key: key, Namespace: b.Namespace, HashAlg: b.HashAlg, Sig: sig}, nil
}

func hasher(alg string) (hash.Hash, error) {
	switch alg {
	case "sha512":
		return sha512.New(), nil
	case "sha256":
		return sha256.New(), nil
	}
	return nil, fmt.Errorf("SSHSIG hash %q is not sha256 or sha512", alg)
}

// signedData is what the key signs: the magic, the namespace, the empty
// reserved string, the hash's name and the message's hash.
func signedData(namespace, alg string, message []byte) ([]byte, error) {
	h, err := hasher(alg)
	if err != nil {
		return nil, err
	}
	h.Write(message)
	return append([]byte(sigMagic), ssh.Marshal(struct {
		Namespace string
		Reserved  []byte
		HashAlg   string
		Hash      []byte
	}{namespace, nil, alg, h.Sum(nil)})...), nil
}

// verify checks s over message alone: the namespace exactly, as ssh-keygen
// -Y verify strcmp's its -n, and the key's signature. Whose key it is, is
// the allowed signers' question.
func (s *Signature) verify(message []byte, namespace string) error {
	if s.Namespace != namespace {
		return fmt.Errorf("signed in namespace %q, not %q", s.Namespace, namespace)
	}
	if s.Key.Type() == ssh.KeyAlgoRSA && s.Sig.Format != ssh.KeyAlgoRSASHA256 && s.Sig.Format != ssh.KeyAlgoRSASHA512 {
		return fmt.Errorf("an RSA signature in %s, which OpenSSH refuses for SSHSIG", s.Sig.Format)
	}
	data, err := signedData(s.Namespace, s.HashAlg, message)
	if err != nil {
		return err
	}
	if err := s.Key.Verify(data, s.Sig); err != nil {
		return fmt.Errorf("the signature does not match the bytes: %w", err)
	}
	return nil
}

// Verify checks an armoured SSHSIG over message in namespace, by a key the
// allowed signers let sign there at now, and returns the principals of the
// lines that do: ssh-keygen -Y verify with -I any of them would succeed.
// principal, when not empty, must also be one a line's principals match,
// as -I is.
func Verify(message, armored []byte, namespace string, signers *AllowedSigners, principal string, now time.Time) ([]string, error) {
	s, err := ParseSignature(armored)
	if err != nil {
		return nil, err
	}
	if err := s.verify(message, namespace); err != nil {
		return nil, err
	}
	return signers.Allowed(s.Key, principal, namespace, now)
}

// Sign makes the armoured SSHSIG ssh-keygen -Y sign would, over message in
// namespace, hashed with sha512; an RSA key signs with rsa-sha2-512.
func Sign(rand io.Reader, signer ssh.Signer, namespace string, message []byte) ([]byte, error) {
	const alg = "sha512"
	data, err := signedData(namespace, alg, message)
	if err != nil {
		return nil, err
	}
	var sig *ssh.Signature
	if as, ok := signer.(ssh.AlgorithmSigner); ok && signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		sig, err = as.SignWithAlgorithm(rand, data, ssh.KeyAlgoRSASHA512)
	} else {
		sig, err = signer.Sign(rand, data)
	}
	if err != nil {
		return nil, err
	}
	blob := append([]byte(sigMagic), ssh.Marshal(sigBlob{
		Version: sigVersion, PublicKey: signer.PublicKey().Marshal(), Namespace: namespace,
		HashAlg: alg, Signature: ssh.Marshal(sig),
	})...)
	return armor(blob), nil
}

func armor(blob []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(blob)
	var b bytes.Buffer
	b.WriteString(armorBegin + "\n")
	for len(enc) > armorWidth {
		b.WriteString(enc[:armorWidth] + "\n")
		enc = enc[armorWidth:]
	}
	b.WriteString(enc + "\n" + armorEnd + "\n")
	return b.Bytes()
}
