// Package sudomsg is the message a remote sudo asks the forwarded agent to
// sign: built by frisket-sudo's gate and read by frisket-signer.
package sudomsg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

const (
	Magic     = "frisket-sudo-v1"
	NonceSize = 32
	// MaxSize is OpenSSH's agent message limit.
	MaxSize = 256 << 10
)

var prefix = string(binary.BigEndian.AppendUint32(nil, uint32(len(Magic)))) + Magic

type Message struct {
	Nonce    []byte
	HostKeys [][]byte
	User     string
	RunAs    string
	Cwd      string
	Argv     []string
	Level    string
	Reasons  []string
}

var (
	errMalformed = errors.New("not a well-formed frisket-sudo message")
	ErrTooLong   = fmt.Errorf("over the agent's limit of %d bytes", MaxSize)
)

// HasMagic is whether b starts with the length-prefixed magic, as no
// userauth request or SSHSIG blob does.
func HasMagic(b []byte) bool {
	return bytes.HasPrefix(b, []byte(prefix))
}

func validLevel(l string) bool {
	return l == "" || l == "warning" || l == "danger"
}

func (m *Message) Marshal() ([]byte, error) {
	if len(m.Nonce) != NonceSize {
		return nil, fmt.Errorf("a nonce of %d bytes", len(m.Nonce))
	}
	if len(m.HostKeys) == 0 {
		return nil, errors.New("no host keys")
	}
	if !validLevel(m.Level) {
		return nil, fmt.Errorf("level %q", m.Level)
	}
	b := []byte(prefix)
	b = appendString(b, m.Nonce)
	b = appendList(b, m.HostKeys)
	b = appendString(b, []byte(m.User))
	b = appendString(b, []byte(m.RunAs))
	b = appendString(b, []byte(m.Cwd))
	b = appendList(b, byteSlices(m.Argv))
	b = appendString(b, []byte(m.Level))
	b = appendList(b, byteSlices(m.Reasons))
	if len(b) > MaxSize {
		return nil, ErrTooLong
	}
	return b, nil
}

// Parse reads b strictly: every field present, a nonce of exactly NonceSize
// bytes, at least one host key and each a public key blob, a known level,
// nothing after the last field and no more than MaxSize in all.
func Parse(b []byte) (*Message, error) {
	if !HasMagic(b) || len(b) > MaxSize {
		return nil, errMalformed
	}
	r := &reader{b: b[len(prefix):]}
	m := &Message{Nonce: r.bytes()}
	m.HostKeys = r.list()
	m.User = string(r.bytes())
	m.RunAs = string(r.bytes())
	m.Cwd = string(r.bytes())
	m.Argv = r.strings()
	m.Level = string(r.bytes())
	m.Reasons = r.strings()
	if r.err != nil || len(r.b) != 0 {
		return nil, errMalformed
	}
	if len(m.Nonce) != NonceSize || len(m.HostKeys) == 0 || !validLevel(m.Level) {
		return nil, errMalformed
	}
	for _, k := range m.HostKeys {
		if _, err := ssh.ParsePublicKey(k); err != nil {
			return nil, fmt.Errorf("%w: a host key: %v", errMalformed, err)
		}
	}
	return m, nil
}

func byteSlices(ss []string) [][]byte {
	b := make([][]byte, len(ss))
	for i, s := range ss {
		b[i] = []byte(s)
	}
	return b
}

func appendString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func appendList(b []byte, l [][]byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(l)))
	for _, s := range l {
		b = appendString(b, s)
	}
	return b
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) uint32() uint32 {
	if r.err != nil || len(r.b) < 4 {
		r.err = errMalformed
		return 0
	}
	n := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return n
}

func (r *reader) bytes() []byte {
	n := r.uint32()
	if r.err != nil || uint64(n) > uint64(len(r.b)) {
		r.err = errMalformed
		return nil
	}
	s := r.b[:n:n]
	r.b = r.b[n:]
	return s
}

func (r *reader) list() [][]byte {
	n := r.uint32()
	var l [][]byte
	for i := uint32(0); i < n && r.err == nil; i++ {
		l = append(l, r.bytes())
	}
	return l
}

func (r *reader) strings() []string {
	var ss []string
	for _, b := range r.list() {
		ss = append(ss, string(b))
	}
	return ss
}
