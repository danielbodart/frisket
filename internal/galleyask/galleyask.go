// Package galleyask puts one question to the person through galley's
// services socket, and trusts the answer only from galley.service.
package galleyask

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/danielbodart/frisket/internal/peer"
	"github.com/danielbodart/galley/wire"
	"golang.org/x/sys/unix"
)

type Question struct {
	Title, Text, Level string
	Grantable          bool
	Password           bool
	// Allow labels a question's Allow button, "Allow once" when empty.
	Allow string
	// Chain is the process chain's rows, ChainRows, shown as a table under
	// the text; nil shows none.
	Chain *ChainTable
}

type Answer struct {
	Allowed bool
	For     time.Duration // 0 is once
	// Password is the dialog's only; the caller zeroes it.
	Password []byte
	Galley   struct {
		Pid    int
		Start  uint64
		Cgroup string
	}
}

var ErrNobody = errors.New("no one to ask")

const maxFor = 24 * time.Hour

var (
	socketDir = "/run/galley-ask"

	galleyCgroup = func(uid int) (uint64, error) {
		var st unix.Stat_t
		path := fmt.Sprintf("/sys/fs/cgroup/user.slice/user-%d.slice/user@%d.service/app.slice/galley.service", uid, uid)
		if err := unix.Stat(path, &st); err != nil {
			return 0, err
		}
		return st.Ino, nil
	}
)

func Ask(ctx context.Context, name string, q Question) (Answer, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return Answer{}, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return Answer{}, err
	}

	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", filepath.Join(socketDir, name+".sock"))
	if err != nil {
		if ctx.Err() != nil {
			return Answer{}, ctx.Err()
		}
		return Answer{}, fmt.Errorf("%w: %v", ErrNobody, err)
	}
	conn := c.(*net.UnixConn)
	defer conn.Close()
	defer context.AfterFunc(ctx, func() { conn.Close() })()

	l, err := checkPeer(conn, uid)
	if err != nil {
		return Answer{}, fmt.Errorf("%w: %v", ErrNobody, err)
	}
	var a Answer
	a.Galley.Pid, a.Galley.Start, a.Galley.Cgroup = l.Pid, l.Start, l.Cgroup

	it := item(name, q)
	line, err := json.Marshal(wire.Hello{Galley: wire.Needs(it), Item: it})
	if err != nil {
		return Answer{}, err
	}
	var w wire.Answer
	if _, err = conn.Write(append(line, '\n')); err == nil {
		err = json.NewDecoder(bufio.NewReader(conn)).Decode(&w)
	}
	if ctx.Err() != nil {
		return Answer{}, ctx.Err()
	}
	if err != nil {
		return Answer{}, fmt.Errorf("%w: %v", ErrNobody, err)
	}
	if w.Error != "" {
		return Answer{}, fmt.Errorf("%w: galley says %q", ErrNobody, w.Error)
	}
	return answer(q, w, a), nil
}

func checkPeer(c *net.UnixConn, uid int) (peer.Link, error) {
	r, err := peer.FromConn(c)
	if err != nil {
		return peer.Link{}, fmt.Errorf("galley peer: %w", err)
	}
	if r.PeerUID != uid {
		return peer.Link{}, fmt.Errorf("galley peer uid %d is not %d", r.PeerUID, uid)
	}
	if len(r.Chain) == 0 {
		return peer.Link{}, errors.New("galley peer cannot be read")
	}
	l := r.Chain[0]
	galley, err := galleyCgroup(uid)
	if err != nil {
		return peer.Link{}, fmt.Errorf("galley.service: %w", err)
	}
	if r.CgroupID != galley {
		return peer.Link{}, fmt.Errorf("galley peer pid %d is in %s, not galley.service", l.Pid, l.Cgroup)
	}
	return l, nil
}

func item(name string, q Question) *wire.Item {
	allow := q.Allow
	if allow == "" {
		allow = "Allow once"
	}
	it := &wire.Item{
		Kind: wire.KindQuestion, Level: q.Level, Title: q.Title, Text: q.Text,
		Buttons: []wire.Button{button(wire.AnswerCancel, "Refuse"), button(wire.AnswerExtra, allow)},
	}
	if q.Chain != nil {
		it.Table = &wire.Table{Columns: []string{"PID", "Process"}, Rows: q.Chain.Rows, Monospace: []int{1}, Summary: q.Chain.Summary}
	}
	units := wire.Field{Kind: wire.FieldCombo, Values: []string{"minutes", "hours"}}
	switch {
	case q.Password:
		it.Kind = wire.KindForms
		it.Buttons = []wire.Button{button(wire.AnswerCancel, "Cancel"), button(wire.AnswerOK, "Allow")}
		fields := []wire.Field{{Kind: wire.FieldPassword, Label: "Password for " + name}}
		if q.Grantable {
			fields = append(fields, wire.Field{Kind: wire.FieldEntry, Label: "Remember the password for this claude for", Text: "15"}, units)
		}
		it.Forms = &wire.Forms{Fields: fields}
	case q.Grantable:
		it.Kind = wire.KindForms
		it.Buttons = append(it.Buttons, button(wire.AnswerOK, "Allow for"))
		it.Forms = &wire.Forms{Fields: []wire.Field{{Kind: wire.FieldEntry, Label: "Allow for", Text: "15"}, units}}
	}
	it.Default = len(it.Buttons) - 1
	return it
}

func button(answer, label string) wire.Button {
	return wire.Button{Answer: answer, Label: label, Underline: -1}
}

func answer(q Question, w wire.Answer, a Answer) Answer {
	switch {
	case w.Answer == wire.AnswerExtra && w.Index == 0 && !q.Password:
		a.Allowed = true
	case w.Answer == wire.AnswerOK && (q.Password || q.Grantable):
		a.Allowed = true
		fields := w.Fields
		if q.Password {
			if p := text(fields, 0); p != "" {
				a.Password = []byte(p)
			}
			if len(fields) > 0 {
				fields = fields[1:]
			}
		}
		if q.Grantable {
			a.For = duration(text(fields, 0), text(fields, 1))
		}
	}
	return a
}

func text(fields []wire.FieldValue, i int) string {
	if i >= len(fields) || fields[i].Text == nil {
		return ""
	}
	return *fields[i].Text
}

func duration(number, unit string) time.Duration {
	per := map[string]time.Duration{"": time.Minute, "minutes": time.Minute, "hours": time.Hour}[unit]
	n, err := strconv.Atoi(number)
	if err != nil || n < 0 || per == 0 {
		slog.Warn("time not understood")
		return 0
	}
	if n > int(maxFor/per) {
		return maxFor
	}
	return time.Duration(n) * per
}
