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
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/danielbodart/galley/wire"
	"golang.org/x/sys/unix"
)

type Question struct {
	Title, Text, Level string
	Grantable          bool
	Password           bool
}

type Answer struct {
	Allowed bool
	For     time.Duration // 0 is once
	// Password is the dialog's only; the caller zeroes it.
	Password []byte
	Galley   struct {
		Pid   int
		Start uint64
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

	var a Answer
	if a.Galley.Pid, a.Galley.Start, err = checkPeer(conn, uid); err != nil {
		return Answer{}, fmt.Errorf("%w: %v", ErrNobody, err)
	}

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

func checkPeer(c *net.UnixConn, uid int) (int, uint64, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *unix.Ucred
	var credErr, pidfdErr error
	var pidfd int
	if err := rc.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		pidfd, pidfdErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	}); err != nil {
		return 0, 0, err
	}
	if pidfdErr != nil {
		return 0, 0, fmt.Errorf("SO_PEERPIDFD: %w", pidfdErr)
	}
	defer unix.Close(pidfd)
	if credErr != nil {
		return 0, 0, fmt.Errorf("SO_PEERCRED: %w", credErr)
	}
	if int(cred.Uid) != uid {
		return 0, 0, fmt.Errorf("galley peer uid %d is not %d", cred.Uid, uid)
	}

	want := uint64(unix.PIDFD_INFO_PID | unix.PIDFD_INFO_CGROUPID)
	info := unix.PidfdInfo{Mask: want}
	if err := unix.IoctlPidfdInfo(pidfd, &info); err != nil {
		return 0, 0, fmt.Errorf("galley peer: %w", err)
	}
	if info.Mask&want != want {
		return 0, 0, errors.New("galley peer has exited")
	}
	pid := int(info.Pid)
	galley, err := galleyCgroup(uid)
	if err != nil {
		return 0, 0, fmt.Errorf("galley.service: %w", err)
	}
	if info.Cgroupid != galley {
		return 0, 0, fmt.Errorf("galley peer pid %d is in %s, not galley.service", pid, cgroupOf(pid))
	}

	start, err := startTime(pid)
	if err != nil {
		return 0, 0, fmt.Errorf("galley peer pid %d: %w", pid, err)
	}
	fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	if n, err := unix.Poll(fds, 0); err != nil || n != 0 {
		return 0, 0, fmt.Errorf("galley peer pid %d has exited", pid)
	}
	return pid, start, nil
}

func startTime(pid int) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return 0, errors.New("stat has no comm")
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return 0, errors.New("stat is short")
	}
	return strconv.ParseUint(f[19], 10, 64)
}

func cgroupOf(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "an unreadable cgroup"
	}
	return strings.TrimPrefix(strings.TrimSpace(string(b)), "0::")
}

func item(name string, q Question) *wire.Item {
	it := &wire.Item{
		Kind: wire.KindQuestion, Level: q.Level, Title: q.Title, Text: q.Text,
		Buttons: []wire.Button{button(wire.AnswerCancel, "Refuse"), button(wire.AnswerExtra, "Allow once")},
		Default: -1,
	}
	units := wire.Field{Kind: wire.FieldCombo, Values: []string{"minutes", "hours"}}
	switch {
	case q.Password:
		it.Kind = wire.KindForms
		it.Buttons = []wire.Button{button(wire.AnswerCancel, "Cancel"), button(wire.AnswerOK, "Allow")}
		it.Default = 1
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
