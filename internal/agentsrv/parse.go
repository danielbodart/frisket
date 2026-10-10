package agentsrv

import (
	"bytes"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/ssh"
)

const (
	msgUserauthRequest = 50
	methodPublickey    = "publickey"
	methodHostbound    = "publickey-hostbound-v00@openssh.com"
	sshsigMagic        = "SSHSIG"
)

type userauth struct {
	sid     []byte
	key     []byte
	hostKey []byte
}

type sshsig struct {
	namespace string
}

type bind struct {
	hostKey ssh.PublicKey
	sid     []byte
	fwd     bool
}

var errMalformed = errors.New("malformed")

type reader struct {
	b   []byte
	err error
}

func (r *reader) bytes() []byte {
	if r.err != nil || len(r.b) < 4 {
		r.err = errMalformed
		return nil
	}
	n := binary.BigEndian.Uint32(r.b)
	if uint64(n) > uint64(len(r.b)-4) {
		r.err = errMalformed
		return nil
	}
	s := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return s
}

func (r *reader) byte() byte {
	if r.err != nil || len(r.b) < 1 {
		r.err = errMalformed
		return 0
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c
}

func (r *reader) end() error {
	if r.err == nil && len(r.b) != 0 {
		r.err = errMalformed
	}
	return r.err
}

func parseUserauth(data []byte) (*userauth, error) {
	r := &reader{b: data}
	u := &userauth{sid: r.bytes()}
	if r.byte() != msgUserauthRequest {
		return nil, errMalformed
	}
	r.bytes()
	r.bytes()
	method := string(r.bytes())
	if r.byte() != 1 {
		return nil, errMalformed
	}
	r.bytes()
	u.key = r.bytes()
	switch method {
	case methodPublickey:
	case methodHostbound:
		u.hostKey = r.bytes()
	default:
		return nil, errMalformed
	}
	if err := r.end(); err != nil {
		return nil, err
	}
	return u, nil
}

func parseSSHSIG(data []byte) (*sshsig, error) {
	rest, ok := bytes.CutPrefix(data, []byte(sshsigMagic))
	if !ok {
		return nil, errMalformed
	}
	r := &reader{b: rest}
	s := &sshsig{namespace: string(r.bytes())}
	r.bytes()
	r.bytes()
	r.bytes()
	if err := r.end(); err != nil {
		return nil, err
	}
	return s, nil
}

// parseBind reads session-bind@openssh.com and verifies the host key's
// signature over the session id.
func parseBind(contents []byte) (*bind, error) {
	r := &reader{b: contents}
	keyBlob, sid, sigBlob := r.bytes(), r.bytes(), r.bytes()
	fwd := r.byte()
	if err := r.end(); err != nil {
		return nil, err
	}
	if fwd > 1 {
		return nil, errMalformed
	}
	key, err := ssh.ParsePublicKey(keyBlob)
	if err != nil {
		return nil, err
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(sigBlob, &sig); err != nil {
		return nil, err
	}
	if err := key.Verify(sid, &sig); err != nil {
		return nil, err
	}
	return &bind{hostKey: key, sid: sid, fwd: fwd == 1}, nil
}
