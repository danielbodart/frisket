package sudogate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/danielbodart/frisket/internal/peer"
)

const (
	magic       = "FSUD"
	version     = 1
	maxBody     = 1 << 20
	maxLinks    = 16
	maxCmdline  = 4096
	maxMessage  = 512
	maxPassword = 1023
)

const (
	kindCheckIn  = 'C'
	kindParent   = 'G'
	kindApproval = 'A'
	kindVerify   = 'V'
)

const (
	replyYes      = 'Y'
	replyNo       = 'N'
	replyPassword = 'W'
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
	if n > maxBody {
		return nil, fmt.Errorf("a body of %d bytes", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	switch req.kind {
	case kindCheckIn, kindParent:
		if n != 0 {
			return nil, fmt.Errorf("%q with a body", req.kind)
		}
		return req, nil
	case kindApproval, kindVerify:
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
	return req, nil
}

func (req *request) add(tag byte, rec []byte) error {
	if req.kind == kindVerify {
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
	default:
		return fmt.Errorf("record %q in 'A'", tag)
	}
	return nil
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
	if len(cmdline) > maxCmdline {
		return peer.Link{}, fmt.Errorf("a cmdline of %d bytes", len(cmdline))
	}
	l.Comm = string(comm)
	if s := strings.TrimSuffix(string(cmdline), "\x00"); s != "" {
		l.Cmdline = strings.Split(s, "\x00")
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
	b := make([]byte, 3, 3+len(msg))
	b[0] = kind
	binary.BigEndian.PutUint16(b[1:], uint16(len(msg)))
	_, err := w.Write(append(b, msg...))
	clear(b)
	return err
}
