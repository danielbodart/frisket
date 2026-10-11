package sudogate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/danielbodart/frisket/internal/peer"
	"golang.org/x/crypto/ssh"
)

const (
	magic       = "FSUD"
	version     = 2
	maxRequest  = 1 << 20
	maxLinks    = 16
	maxComm     = 64
	maxCmdline  = 4096
	maxMessage  = 512
	maxPassword = 1023
)

const (
	kindCheckIn  = 'C'
	kindParent   = 'G'
	kindApproval = 'A'
	kindVerify   = 'V'
	kindSign     = 'S'
)

const (
	replyYes      = 'Y'
	replyNo       = 'N'
	replyPassword = 'W'
	replyMessage  = 'M'
)

type request struct {
	kind      byte
	links     []peer.Link
	user      []string
	settings  []string
	command   []string
	argv      []string
	envp      []string
	verified  []byte
	truncated bool
	remote    bool

	pub    []byte
	sig    []byte
	failed *string
}

func readRequest(r io.Reader) (*request, error) {
	var h [10]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	if string(h[:4]) != magic {
		return nil, errors.New("not a frisket-sudo request")
	}
	if h[4] != version {
		return nil, fmt.Errorf("version %d", h[4])
	}
	req := &request{kind: h[5]}
	n := binary.BigEndian.Uint32(h[6:])
	if n > maxRequest-uint32(len(h)) {
		return nil, fmt.Errorf("a body of %d bytes", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	switch req.kind {
	case kindParent:
		if n != 0 {
			return nil, fmt.Errorf("%q with a body", req.kind)
		}
		return req, nil
	case kindCheckIn, kindApproval, kindVerify, kindSign:
	default:
		return nil, fmt.Errorf("kind %q", req.kind)
	}
	for len(body) > 0 {
		if len(body) < 5 {
			return nil, errors.New("a record cut short")
		}
		tag, size := body[0], binary.BigEndian.Uint32(body[1:5])
		body = body[5:]
		if uint64(size) > uint64(len(body)) {
			return nil, fmt.Errorf("record %q of %d bytes in %d", tag, size, len(body))
		}
		rec := body[:size]
		body = body[size:]
		if err := req.add(tag, rec); err != nil {
			return nil, err
		}
	}
	if req.kind == kindVerify && len(req.verified) != 1 {
		return nil, errors.New("'V' without one result")
	}
	if req.kind == kindSign && (req.failed == nil) == (req.pub == nil || req.sig == nil) {
		return nil, errors.New("'S' without either 'f' or both 'p' and 'g'")
	}
	return req, nil
}

func (req *request) add(tag byte, rec []byte) error {
	switch req.kind {
	case kindCheckIn:
		if tag != 'm' || len(rec) != 0 || req.remote {
			return fmt.Errorf("record %q in 'C'", tag)
		}
		req.remote = true
		return nil
	case kindSign:
		return req.addSign(tag, rec)
	case kindVerify:
		if tag != 'r' || len(rec) != 1 || rec[0] > 1 || req.verified != nil {
			return fmt.Errorf("record %q in 'V'", tag)
		}
		req.verified = rec
		return nil
	}
	switch tag {
	case 'k':
		if len(req.links) == maxLinks {
			return fmt.Errorf("more than %d links", maxLinks)
		}
		l, err := readLink(rec)
		if err != nil {
			return err
		}
		req.links = append(req.links, l)
	case 'u':
		req.user = append(req.user, string(rec))
	case 's':
		req.settings = append(req.settings, string(rec))
	case 'c':
		req.command = append(req.command, string(rec))
	case 'a':
		req.argv = append(req.argv, string(rec))
	case 'e':
		req.envp = append(req.envp, string(rec))
	case 't':
		req.truncated = true
	case 'm':
		if len(rec) != 0 || req.remote {
			return errors.New("'m' with a body or twice")
		}
		req.remote = true
	default:
		return fmt.Errorf("record %q in 'A'", tag)
	}
	return nil
}

func (req *request) addSign(tag byte, rec []byte) error {
	switch {
	case tag == 'p' && req.pub == nil && req.failed == nil:
		req.pub = rec
	case tag == 'g' && req.sig == nil && req.failed == nil:
		req.sig = rec
	case tag == 'f' && req.pub == nil && req.sig == nil && req.failed == nil && printable(rec):
		f := string(rec)
		req.failed = &f
	default:
		return fmt.Errorf("record %q in 'S'", tag)
	}
	return nil
}

func printable(b []byte) bool {
	if len(b) > maxMessage {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func readLink(b []byte) (peer.Link, error) {
	if len(b) < 26 {
		return peer.Link{}, errors.New("a link cut short")
	}
	be := binary.BigEndian
	l := peer.Link{
		Pid: int(be.Uint32(b)), PPid: int(be.Uint32(b[4:])), Start: be.Uint64(b[8:]),
		UID: int(be.Uint32(b[16:])), TTY: be.Uint32(b[20:]),
	}
	b = b[24:]
	comm, b, ok := cut16(b)
	if !ok {
		return peer.Link{}, errors.New("a link's comm cut short")
	}
	cmdline, b, ok := cut16(b)
	if !ok || len(b) != 0 {
		return peer.Link{}, errors.New("a link's cmdline cut short or followed by more")
	}
	if len(comm) > maxComm || len(cmdline) > maxCmdline {
		return peer.Link{}, fmt.Errorf("a comm of %d bytes or a cmdline of %d", len(comm), len(cmdline))
	}
	l.Comm = string(comm)
	if len(cmdline) > 0 {
		l.Cmdline = strings.Split(string(cmdline), "\x00")
	}
	return l, nil
}

func cut16(b []byte) (field, rest []byte, ok bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(b))
	if n > len(b)-2 {
		return nil, nil, false
	}
	return b[2 : 2+n], b[2+n:], true
}

func writeReply(w io.Writer, kind byte, msg []byte) error {
	b := make([]byte, 3+len(msg))
	b[0] = kind
	binary.BigEndian.PutUint16(b[1:], uint16(len(msg)))
	copy(b[3:], msg)
	_, err := w.Write(b)
	clear(b)
	return err
}

// writeMessage is the 'M' reply: the message to sign and the listed keys.
func writeMessage(w io.Writer, msg []byte, keys [][]byte) error {
	body := ssh.Marshal(struct {
		Msg []byte
		N   uint32
	}{msg, uint32(len(keys))})
	for _, k := range keys {
		body = append(body, ssh.Marshal(struct{ K []byte }{k})...)
	}
	if 5+len(body) > maxRequest {
		return errors.New("the 'M' reply is over its limit")
	}
	b := binary.BigEndian.AppendUint32([]byte{replyMessage}, uint32(len(body)))
	_, err := w.Write(append(b, body...))
	return err
}
