package sshroute

import (
	"context"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/steer"
)

// maxLoggedCommand bounds the command in a log line, as a request's path is
// bounded.
const maxLoggedCommand = 1024

// maxLoggedUser bounds the user name the sandbox's client gave. It is the
// workload's to choose, any bytes up to a packet's size, and goes on every
// line of the connection; a name worth reading is far shorter.
const maxLoggedUser = 64

// loggedCommand is a command as the log shows it: bounded, and with every
// control byte, backslash and byte that is not UTF-8 written as an escape,
// so that a line holds exactly one command and says plainly what it was.
// The command is logged, unlike a query string: it is what a route
// authorises, as a path is, and a line without it says nothing of what ran.
func loggedCommand(cmd string) string { return escaped(cmd, maxLoggedCommand) }

// loggedUser is the client's user name as the log shows it, bounded and
// escaped as a command is: no less the workload's own text.
func loggedUser(user string) string { return escaped(user, maxLoggedUser) }

// escaped is s cut to limit bytes, with "..." saying it was cut, and its
// control bytes, backslashes and bytes that are not UTF-8 written as escapes.
func escaped(s string, limit int) string {
	cut := len(s) > limit
	if cut {
		s = s[:limit]
	}
	var b strings.Builder
	const hex = "0123456789abcdef"
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n <= 1, r < ' ', r == 0x7f:
			b.WriteString(`\x`)
			b.WriteByte(hex[s[i]>>4])
			b.WriteByte(hex[s[i]&0xf])
			n = 1
		case r == '\\':
			b.WriteString(`\\`)
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	if cut {
		b.WriteString("...")
	}
	return b.String()
}

// log writes a command's one line.
func (c *channel) log(l *execLine, start time.Time) {
	s := c.s
	s.lines.Add(1)
	attrs := []any{
		"session", s.c.Session,
		"conn", s.c.ID,
		"channel", c.n,
		"dst", s.c.Orig.String(),
		"route", s.route.Name,
		"user", s.route.User,
		"client_user", s.clientUser,
		"command", loggedCommand(l.command),
		"decision", l.decision,
	}
	if l.rule != "" {
		attrs = append(attrs, "rule", l.rule)
	}
	if l.operation != "" {
		attrs = append(attrs, "operation", l.operation)
	}
	if l.asked {
		attrs = append(attrs, "asked", true)
	}
	if l.reason != "" {
		attrs = append(attrs, "reason", l.reason)
	}
	if l.exitStatus != nil {
		attrs = append(attrs, "exit_status", *l.exitStatus)
	}
	if l.exitSignal != "" {
		attrs = append(attrs, "exit_signal", l.exitSignal)
	}
	attrs = append(attrs,
		"stdin_bytes", l.stdin.Load(),
		"stdout_bytes", l.stdout.Load(),
		"stderr_bytes", l.stderr.Load(),
		"duration_ms", time.Since(start).Milliseconds(),
	)
	if l.err != nil {
		attrs = append(attrs, "error", l.err.Error())
	}
	level := slog.LevelInfo
	if l.decision == intercept.DecisionRefused {
		level = slog.LevelWarn
	}
	s.h.log.Log(context.Background(), level, "ssh", attrs...)
}

// logChannelRefused writes the line of a channel that was not a session: a
// forward, an agent, X11. Each is refused where it is asked for, and said.
func (s *conn) logChannelRefused(n uint64, kind string) {
	s.lines.Add(1)
	s.h.log.Warn("ssh",
		"session", s.c.Session,
		"conn", s.c.ID,
		"channel", n,
		"dst", s.c.Orig.String(),
		"route", s.route.Name,
		"client_user", s.clientUser,
		"channel_type", kind,
		"decision", intercept.DecisionRefused,
		"reason", ReasonChannelType,
	)
}

// connLine is a connection's line, where it ran no command.
type connLine struct {
	conn       *steer.Conn
	route      string
	clientUser string
	decision   string
	reason     string
	channels   uint64
	err        error
}

func (h *Handler) logConn(l connLine, start time.Time) {
	attrs := []any{
		"session", l.conn.Session,
		"conn", l.conn.ID,
		"dst", l.conn.Orig.String(),
	}
	if l.route != "" {
		attrs = append(attrs, "route", l.route)
	}
	if l.clientUser != "" {
		attrs = append(attrs, "client_user", l.clientUser)
	}
	attrs = append(attrs, "decision", l.decision)
	if l.reason != "" {
		attrs = append(attrs, "reason", l.reason)
	}
	attrs = append(attrs,
		"channels", l.channels,
		"duration_ms", time.Since(start).Milliseconds(),
	)
	if l.err != nil {
		attrs = append(attrs, "error", l.err.Error())
	}
	level := slog.LevelInfo
	if l.decision == intercept.DecisionRefused {
		level = slog.LevelWarn
	}
	h.log.Log(context.Background(), level, "ssh", attrs...)
}
