package galleyask

import (
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Width is the characters a command is laid out to before it is broken
// across lines.
const Width = 64

// indent is what a shell script's lines, and a broken line's continuations,
// start with.
const indent = "    "

// Command lays out argv for reading, each argument cleaned. One that fits in
// width is a line, the arguments joined by spaces as before. A longer one
// first puts a shell's script, the argument a -c names, on lines of its
// own, split at the script's control operators that no quote, $( ), ( ),
// { }, backquote or comment holds: &&, || and | start the line after them,
// ; ends the line before it, a newline is a line break. A segment that is
// eval of one single-quoted script, as Claude Code's Bash tool runs each
// command, is laid out the same way inside its quotes. Any line still wider
// than width is then broken at spaces, quotes kept whole where they can be,
// each line but the last ending with a backslash; a word longer than a
// line is left whole.
func Command(argv []string, width int) []string {
	if len(argv) == 0 {
		return nil
	}
	cleaned := make([]string, len(argv))
	for i, a := range argv {
		cleaned[i] = Clean(a)
	}
	whole := strings.Join(cleaned, " ")
	if utf8.RuneCountInString(whole) <= width {
		return []string{whole}
	}
	var lines []string
	w := wrapped(argv)
	if s := scriptArg(argv[w:]); s > 0 {
		s += w
		lines = append(lines, strings.Join(cleaned[:s], " "))
		lines = append(lines, scriptLines(argv[s], indent, width)...)
		if s+1 < len(cleaned) {
			lines = append(lines, indent+strings.Join(cleaned[s+1:], " "))
		}
	} else {
		lines = []string{whole}
	}
	var out []string
	for _, l := range lines {
		out = append(out, Wrap(l, width)...)
	}
	return out
}

// scriptLines is script's segments, each a line starting with ind, an eval
// too long for its line opened onto lines of its own.
func scriptLines(script, ind string, width int) []string {
	var lines []string
	for _, seg := range split(script) {
		line := ind + Clean(seg)
		if utf8.RuneCountInString(line) > width {
			if lead, body, rest, ok := evalScript(seg); ok {
				lines = append(lines, ind+Clean(strings.TrimSpace(lead+" eval '")))
				lines = append(lines, scriptLines(body, ind+indent, width)...)
				lines = append(lines, ind+Clean(strings.TrimSpace("'"+rest)))
				continue
			}
		}
		lines = append(lines, line)
	}
	return lines
}

// evalScript reads seg as [operator] eval WORD [rest], where WORD is one
// shell word of quoted and escaped pieces, as Claude Code writes it, whose
// value is the script.
func evalScript(seg string) (lead, body, rest string, ok bool) {
	for _, op := range []string{"&&", "||", "|&", "|"} {
		if strings.HasPrefix(seg, op+" ") {
			lead, seg = op, strings.TrimLeft(seg[len(op):], " ")
			break
		}
	}
	if !strings.HasPrefix(seg, "eval '") {
		return "", "", "", false
	}
	body, rest, ok = shellWord(seg[len("eval "):])
	if !ok {
		return "", "", "", false
	}
	return lead, body, rest, true
}

// shellWord reads the shell word s starts with: single-quoted pieces, double-
// quoted pieces with nothing in them to expand, and backslash escapes,
// joined, up to a blank or the end. A word with anything to expand is not
// read.
func shellWord(s string) (value, rest string, ok bool) {
	var b strings.Builder
	i := 0
	for i < len(s) && s[i] != ' ' && s[i] != '\t' {
		switch s[i] {
		case '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return "", "", false
			}
			b.WriteString(s[i+1 : i+1+end])
			i += end + 2
		case '"':
			end := strings.IndexByte(s[i+1:], '"')
			if end < 0 || strings.ContainsAny(s[i+1:i+1+end], "$`\\") {
				return "", "", false
			}
			b.WriteString(s[i+1 : i+1+end])
			i += end + 2
		case '\\':
			if i+1 >= len(s) {
				return "", "", false
			}
			b.WriteByte(s[i+1])
			i += 2
		default:
			if strings.IndexByte("$`;&|<>(){}*?[~", s[i]) >= 0 {
				return "", "", false
			}
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String(), s[i:], true
}

// wrappers are programs that run the rest of their arguments as a command.
var wrappers = map[string]bool{"timeout": true, "nice": true, "nohup": true, "setsid": true, "env": true, "stdbuf": true, "ionice": true}

// wrapped is the index in argv of the command its wrappers run, 0 when
// argv[0] is no wrapper.
func wrapped(argv []string) int {
	i := 0
	for i < len(argv) && wrappers[filepath.Base(argv[i])] {
		name := filepath.Base(argv[i])
		i++
	options:
		for i < len(argv) && strings.HasPrefix(argv[i], "-") && argv[i] != "-" {
			switch argv[i] {
			case "--":
				i++
				break options
			case "-s", "-k", "-n", "-u", "-C", "-i", "-o", "-e", "-c", "-p":
				i++
			}
			i++
		}
		switch name {
		case "timeout":
			i++
		case "env":
			for i < len(argv) && strings.Contains(argv[i], "=") {
				i++
			}
		}
	}
	if i >= len(argv) {
		return 0
	}
	return i
}

// scriptArg is the index in argv of a shell's script: for a shell, the
// first argument after its options when one of them holds c; for script(1),
// the argument after -c or --command. 0 is none.
func scriptArg(argv []string) int {
	name := filepath.Base(argv[0])
	if name == "script" {
		for i := 1; i+1 < len(argv); i++ {
			a := argv[i]
			if a == "--command" || (len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.HasSuffix(a, "c")) {
				return i + 1
			}
		}
		return 0
	}
	if !Shell(name) {
		return 0
	}
	c := false
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			if c && i+1 < len(argv) {
				return i + 1
			}
			return 0
		case strings.HasPrefix(a, "--"):
		case len(a) > 1 && (a[0] == '-' || a[0] == '+'):
			if a[0] == '-' && strings.ContainsRune(a[1:], 'c') {
				c = true
			}
			// -o and +o take an option's name.
			if a[1:] == "o" || a[1:] == "O" {
				i++
			}
		default:
			if c {
				return i
			}
			return 0
		}
	}
	return 0
}

// Split is a shell script's lines at its top-level control operators, each
// cleaned and trimmed, empty ones dropped. && || and | (and |&) lead the
// segment after them; ; ends the one before it; a newline only breaks.
// Operators inside quotes, $( ), ( ), ` ` and comments stay where they are,
// as does the | of a >| redirection.
func Split(script string) []string {
	segs := split(script)
	for i, s := range segs {
		segs[i] = Clean(s)
	}
	return segs
}

func split(script string) []string {
	var segs []string
	var cur strings.Builder
	lead := ""
	flush := func(tail string) {
		seg := strings.TrimSpace(cur.String())
		cur.Reset()
		if seg != "" || tail != "" {
			seg = strings.TrimSpace(lead + " " + seg)
			segs = append(segs, seg+tail)
			lead = ""
		}
	}
	var quote byte // '\'', '"' or '`'
	depth := 0     // ( and $( not yet closed
	comment := false
	for i := 0; i < len(script); i++ {
		ch := script[i]
		switch {
		case comment:
			if ch == '\n' {
				comment = false
				flush("")
				continue
			}
		case quote == '\'':
			if ch == '\'' {
				quote = 0
			}
		case ch == '\\' && i+1 < len(script):
			if script[i+1] == '\n' {
				// A line continuation joins the lines.
				i++
				cur.WriteByte(' ')
				continue
			}
			cur.WriteByte(ch)
			i++
			ch = script[i]
		case quote == '"':
			if ch == '"' {
				quote = 0
			}
		case quote == '`':
			if ch == '`' {
				quote = 0
			}
		case ch == '\'' || ch == '"' || ch == '`':
			quote = ch
		case ch == '(':
			depth++
		case ch == ')':
			if depth > 0 {
				depth--
			}
		case ch == '{' && word(script, i):
			depth++
		case ch == '}' && word(script, i) && depth > 0:
			depth--
		case depth > 0:
		case ch == '#' && (cur.Len() == 0 || isSpace(lastByte(&cur))):
			comment = true
		case ch == '\n':
			flush("")
			continue
		case ch == ';' && i+1 < len(script) && script[i+1] == ';':
			// A case arm's end, not a list's.
			cur.WriteString(";;")
			i++
			continue
		case ch == ';':
			flush(";")
			continue
		case ch == '&' && i+1 < len(script) && script[i+1] == '&':
			flush("")
			lead = "&&"
			i++
			continue
		case ch == '|' && i+1 < len(script) && script[i+1] == '|':
			flush("")
			lead = "||"
			i++
			continue
		case ch == '|' && (cur.Len() == 0 || lastByte(&cur) != '>'):
			flush("")
			lead = "|"
			if i+1 < len(script) && script[i+1] == '&' {
				lead = "|&"
				i++
			}
			continue
		}
		cur.WriteByte(ch)
	}
	flush("")
	if lead != "" {
		// A script ending in an operator keeps it.
		segs = append(segs, lead)
	}
	return segs
}

// word is whether script[i] is a word of its own, as a group's { and }
// must be.
func word(script string, i int) bool {
	before := i == 0 || strings.IndexByte(" \t\n;&|", script[i-1]) >= 0
	after := i+1 == len(script) || strings.IndexByte(" \t\n;&|)<>", script[i+1]) >= 0
	return before && after
}

func lastByte(b *strings.Builder) byte {
	s := b.String()
	return s[len(s)-1]
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' }

// Wrap breaks line at spaces into lines of at most width characters, each
// but the last ending " \", the continuations indented. It breaks first at
// spaces outside quotes, then at any space, and leaves a word longer than
// a line whole.
func Wrap(line string, width int) []string {
	if utf8.RuneCountInString(line) <= width {
		return []string{line}
	}
	lead := line[:len(line)-len(strings.TrimLeft(line, " "))]
	cont := lead + indent
	var out []string
	rest := strings.TrimLeft(line, " ")
	prefix := lead
	for {
		room := width - utf8.RuneCountInString(prefix)
		if utf8.RuneCountInString(rest) <= room {
			out = append(out, prefix+rest)
			return out
		}
		// Room for the " \" that ends the line.
		at := breakAt(rest, room-2)
		if at == len(rest) {
			out = append(out, prefix+rest)
			return out
		}
		out = append(out, prefix+strings.TrimRight(rest[:at], " ")+" \\")
		rest = strings.TrimLeft(rest[at:], " ")
		prefix = cont
	}
}

// breakAt is the byte index in s to break at so that s[:at] is at most n
// characters: the last space outside quotes, else the last space, else,
// for a word longer than that, the first space after it, or the end.
func breakAt(s string, n int) int {
	if n < 1 {
		n = 1
	}
	limit, count := len(s), 0
	for i := range s {
		if count == n {
			limit = i
			break
		}
		count++
	}
	outside, any := -1, -1
	var quote byte
	for i := 0; i < len(s) && i <= limit; i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ' ' && i > 0:
			outside = i
		}
		if c == ' ' && i > 0 {
			any = i
		}
	}
	switch {
	case outside > 0:
		return outside
	case any > 0:
		return any
	}
	if at := strings.IndexByte(s[limit:], ' '); at >= 0 {
		return limit + at
	}
	return len(s)
}
