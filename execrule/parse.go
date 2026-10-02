package execrule

import (
	"slices"
	"strings"
)

// A command is decided by its words, and only a command a shell reads as
// exactly its words has any. sshd hands the command to the login shell as one
// string, so that is a real difference, not a theoretical one: `ls $(rm x)`
// is not two words to bash. So frisket reads a small grammar every login
// shell of the POSIX family, fish and csh reads alike -- simple commands of
// plain, single-quoted or double-quoted words, joined by && || ; and |, and
// ending, if they like, >/dev/null or </dev/null -- and a command with
// anything else in it is unreadable, which no rule decides. Windows' cmd.exe
// is not of them, and no grammar could be: ' is no quote to it and ; no
// separator, while " is its only quote, so `echo 'a & b'` is two commands to
// cmd.exe and one to bash. A route to a machine whose login shell is cmd.exe,
// or PowerShell, is decided by words that machine does not run.

// plainByte is a byte a word may hold unquoted: one no POSIX-family shell,
// fish or csh gives a meaning of its own anywhere in a word -- but %, which
// fish reads at a word's start: `%self` is its PID there, and nowhere else,
// so a plain word may not begin with one (see lex). cmd.exe expands %VAR%,
// which is one more reason a route assumes none of it.
func plainByte(b byte) bool {
	switch {
	case 'a' <= b && b <= 'z', 'A' <= b && b <= 'Z', '0' <= b && b <= '9':
		return true
	}
	return strings.IndexByte("_@%+=:,./-", b) >= 0
}

// quotedByte is a byte a single-quoted word may hold: printable ASCII, but
// not the quote itself -- there is no escaping one in bash -- nor a
// backslash, which escapes a quote inside single quotes in fish, nor a !,
// which csh expands there. Each of those is read differently by some login
// shell frisket allows for, and it does not know which one the machine has.
func quotedByte(b byte) bool {
	return ' ' <= b && b <= '~' && b != '\'' && b != '\\' && b != '!'
}

// doubleQuotedByte is a byte a double-quoted word may hold: what a
// single-quoted one may, but $ and the backtick, which every shell expands
// inside double quotes, and the quote itself. A backslash escapes there,
// and csh expands a ! there too, so neither is a quotedByte to begin with.
// Every other printable byte is itself inside double quotes to sh, bash,
// zsh, ksh, fish and csh alike: none of them globs, splits or comments
// there.
func doubleQuotedByte(b byte) bool {
	return quotedByte(b) && b != '$' && b != '`' && b != '"'
}

// maxCommand bounds a command, as every input frisket matches is bounded:
// a longer one is unreadable, so deciding it is never more work than this
// much. Nothing worth a rule is 8 KiB long, and a question shows a person
// far less of one.
const maxCommand = 8 << 10

// devNull is the one file a redirection may name: `>/dev/null` and
// `</dev/null`, each a word of its own at a simple command's end.
const devNull = "/dev/null"

// reserved are the words a shell reads as its own syntax in a command's
// first place -- bash's, zsh's and fish's -- and so never as the command
// they look like: `then rm x` runs rm, `not rm x` runs rm in fish, and zsh's
// `-`, a plain word, runs the word after it as the command: `ls; - rm x`
// runs rm. A rule for `then **` would admit them all, so a command with one
// first is unreadable, and a pattern starting with one is refused. time is
// one too, but a command may begin with it: what runs is the command after
// it, which is what is decided (see strip).
var reserved = []string{
	"-", "and", "begin", "case", "coproc", "do", "done", "elif", "else", "end", "esac",
	"fi", "for", "foreach", "function", "if", "in", "nocorrect", "noglob", "not",
	"or", "repeat", "select", "switch", "then", "time", "until", "while",
}

// precommands are the shells' builtins that run the command after them:
// `exec rm x`, `command rm x` and `builtin cd x` run rm and cd, so a rule
// for `command **` would admit anything. A simple command may begin with
// one, and what runs is decided (see strip); anywhere else it is
// unreadable, and a pattern starting with one is refused.
var precommands = []string{"builtin", "command", "exec"}

// unreadableFirst is why a command's first word makes it unreadable, or "".
// One holding = that strip did not take as an assignment -- a name not
// listed, a quoted one, or one after time -- may be an assignment to a shell
// -- `PATH=/tmp/x ls` runs some other ls, `LD_PRELOAD=x ls` runs ls with x in
// it -- and the word after it is the command, so neither word's rule may
// decide it. Quoted, the word is a command's name to bash and an assignment
// to nothing, but a command named with = is nothing worth a rule, and one
// reading is simpler than two.
func unreadableFirst(w string) string {
	switch {
	case strings.Contains(w, "="):
		return "holds =, which a shell reads as an assignment"
	case slices.Contains(reserved, w):
		return "is a shell's reserved word"
	case slices.Contains(precommands, w):
		return "is a shell's builtin that runs the command after it"
	}
	return ""
}

// word is one word as the grammar reads it, and whether it was quoted: an
// assignment is a plain word, and the same bytes quoted are a command's name.
type word struct {
	s      string
	quoted bool
}

// lex reads command as frisket's grammar, into its simple commands' words,
// or reports it unreadable. A simple command is words separated by spaces,
// and simple commands are joined by &&, ||, ; or |, with or without spaces.
// A word is plain bytes, not beginning % or =, or a single- or double-quoted
// string whose content is the word; one that is both, `a'b'`, is
// unreadable, since zsh with RC_QUOTES reads two single-quoted strings run
// together as one, with a quote between them. After its words a simple
// command may redirect its output to /dev/null, its input from it, or both,
// each once and a word of its own; the redirections are no words of it.
// Unreadable too: any other byte, an operator first or last, two operators
// together, a single &, and a command longer than maxCommand.
func lex(command string) ([][]word, bool) {
	if len(command) > maxCommand {
		return nil, false
	}
	var (
		cmds [][]word
		cur  []word
		// in and out are whether the simple command being read has
		// redirected its input or its output, and piped whether a pipe
		// feeds it.
		in, out, piped bool
	)
	// ends is whether a word may end at i: at the end, a space or an
	// operator, and not straight into another word.
	ends := func(i int) bool {
		return i == len(command) || strings.IndexByte(" ;|&", command[i]) >= 0
	}
	// quoted reads a quoted word starting at i, of bytes ok allows up to
	// the closing quote, and returns its content and where it ends.
	quoted := func(i int, ok func(byte) bool) (string, int, bool) {
		q := command[i]
		j := i + 1
		for j < len(command) && command[j] != q {
			if !ok(command[j]) {
				return "", 0, false
			}
			j++
		}
		if j == len(command) || !ends(j+1) {
			return "", 0, false
		}
		return command[i+1 : j], j + 1, true
	}
	for i := 0; i < len(command); {
		b := command[i]
		if in || out {
			// Only a redirection, or the end of the simple command, may
			// follow one: `>/dev/null pa x` is no command to fish, and
			// what is after one is no word of the command to the rest.
			switch b {
			case ' ', ';', '|', '&', '<', '>':
			default:
				return nil, false
			}
		}
		switch {
		case b == ' ':
			i++
		case b == '\'' || b == '"':
			ok := quotedByte
			if b == '"' {
				ok = doubleQuotedByte
			}
			s, j, read := quoted(i, ok)
			if !read {
				return nil, false
			}
			cur = append(cur, word{s, true})
			i = j
		case b == '=', b == '%':
			// zsh, by its EQUALS option, on unless a profile turns it off,
			// reads an unquoted word beginning = as a command's path:
			// `cat =deploy` is cat of whatever deploy on PATH is, a word
			// no rule was asked about. fish reads `%self` as its PID. No
			// argument worth a rule is spelt either way, and quoted, each
			// is itself to every shell.
			return nil, false
		case plainByte(b):
			j := i
			for j < len(command) && plainByte(command[j]) {
				j++
			}
			if !ends(j) {
				return nil, false
			}
			cur = append(cur, word{command[i:j], false})
			i = j
		case b == '<' || b == '>':
			// `>/dev/null` or `</dev/null`, after a space and before the
			// end of the word, and each once: csh calls a second
			// redirection of either ambiguous and runs nothing, and the
			// same of output redirected into a pipe, or input from a file
			// beside one -- which zsh, by MULTIOS, would also read as
			// both.
			j := i + 1 + len(devNull)
			if len(cur) == 0 || command[i-1] != ' ' || !strings.HasPrefix(command[i+1:], devNull) || !ends(j) ||
				b == '<' && (in || piped) || b == '>' && out {
				return nil, false
			}
			if b == '<' {
				in = true
			} else {
				out = true
			}
			i = j
		case b == ';', b == '|', b == '&':
			n := 1
			if b != ';' && i+1 < len(command) && command[i+1] == b {
				n = 2
			}
			if b == '&' && n == 1 || len(cur) == 0 || b == '|' && n == 1 && out {
				// A single & runs what is before it unwaited for, an
				// operator with no command before it is no command, and
				// output to /dev/null is no output to a pipe.
				return nil, false
			}
			piped = b == '|' && n == 1
			cmds, cur, in, out = append(cmds, cur), nil, false, false
			i += n
		default:
			return nil, false
		}
	}
	if len(cur) == 0 {
		return nil, false
	}
	return append(cmds, cur), true
}

// Simple is one simple command as the rules see it. Words are what runs,
// its name first: whatever came before it that only sets how it runs --
// a precommand, time, an assignment of a listed name, env -- taken off, and
// any redirection to or from /dev/null after it too. Assignments are
// the NAME=value words taken off with it, the shell's and env's, in order:
// no command rule sees them, and every arg rule does.
type Simple struct {
	Words       []string
	Assignments []string
}

// strip takes off a simple command's prefixes, and reports it unreadable
// where one is not what strip can say runs after it. They are:
//
//   - exec, command or builtin, plain, first and only first: each runs the
//     command after it -- exec in place of the shell, command by PATH and
//     not as a function, builtin as the shell's own -- and where a shell has
//     no such builtin, csh's command and builtin or dash's builtin, it runs
//     the program of that name, POSIX's wrapper of the builtin where there
//     is one, or nothing. Quoted, it is that program to csh, so it is
//     unreadable. Any option -- `command -v`, `exec -a`, `--` -- is
//     unreadable, as is one with no command after it. After one, an assignment is a command's
//     name and another precommand a program to some shells and a builtin to
//     others, so both are unreadable; env and time are the programs, as
//     after env. Anywhere else a precommand is unreadable: after an
//     assignment it is no builtin to csh, and after env or time the program
//     of that name.
//   - NAME=value, a plain word, at the start or after another: the shell's
//     assignment, for the command after it alone. Its name must be listed,
//     and its value one assignment allows (see assignment). Alone, with no
//     command after it, it sets the shell's own variable for whatever comes
//     next, and is unreadable.
//   - env, then NAME=value words, plain and listed: env with no option, which
//     runs the word after them as the command, by PATH. With no command after
//     it, env is the command, and is decided as `env`; so is env with only
//     options that run nothing -- `env -0`, `env -u NAME` -- before any
//     assignment (see printsAll), which print the environment as env does.
//     Any other option, or one with a command after it -- `env -i ls`,
//     `-u NAME ls`, `-S`, `--` -- is unreadable: they change what runs, or
//     how.
//   - time: the shell's reserved word in bash, zsh and ksh, and
//     /usr/bin/time in dash or after env; either runs the command after it.
//     After env it is only ever the program, and takes -p, POSIX's one
//     option. Anywhere else -p is unreadable, as the shells disagree what it
//     is: bash's option only unquoted, and to zsh, whose time has none, the
//     command to run, so `time -p ls` there runs whatever -p is on PATH. Any
//     other option is unreadable, and so is time with no command after it.
//
// The shells disagree where time and a shell assignment meet, so both
// orders are unreadable: `time LANG=C ls` is ls to bash and zsh, but to
// dash, whose time is /usr/bin/time, LANG=C is the command to run, and
// `LANG=C time ls` is the keyword or not as the shell's grammar has it.
// `time env LANG=C ls` and `env LANG=C time ls` mean one thing everywhere,
// and are read.
//
// csh has no assignment before a command at all: `LANG=C ls` runs a
// command named LANG=C there, which is not there to run. A route to a
// machine whose login shell is csh should list no names.
func (r *Rules) strip(ws []word) (Simple, bool) {
	var s Simple
	// shell is whether a plain NAME=value here is the shell's assignment:
	// at the start, or after another. After time it is a command to dash,
	// and after env, env's.
	shell := true
	// assigned is whether the word before this one was the shell's
	// assignment.
	assigned := false
	// byEnv is whether env or a precommand came before this word, so that
	// time here is the program and no shell's reserved word.
	byEnv := false
	if len(ws) > 0 && !ws[0].quoted && slices.Contains(precommands, ws[0].s) {
		ws = ws[1:]
		if len(ws) == 0 || strings.HasPrefix(ws[0].s, "-") {
			return Simple{}, false
		}
		shell, byEnv = false, true
	}
	for {
		if len(ws) == 0 {
			// Prefixes and no command: assignments alone, or time alone.
			return Simple{}, false
		}
		w := ws[0]
		switch {
		case w.s == "time":
			if assigned {
				return Simple{}, false
			}
			ws = ws[1:]
			if byEnv && len(ws) > 0 && ws[0].s == "-p" {
				ws = ws[1:]
			}
			if len(ws) > 0 && strings.HasPrefix(ws[0].s, "-") {
				return Simple{}, false
			}
			shell, assigned = false, false
		case w.s == "env":
			ws = ws[1:]
			before := len(s.Assignments)
			for len(ws) > 0 && !ws[0].quoted && strings.Contains(ws[0].s, "=") {
				if !r.assignment(ws[0].s) {
					return Simple{}, false
				}
				s.Assignments = append(s.Assignments, ws[0].s)
				ws = ws[1:]
			}
			if len(ws) == 0 || len(s.Assignments) == before && printsAll(ws) {
				s.Words = []string{"env"}
				return s, true
			}
			if strings.HasPrefix(ws[0].s, "-") {
				return Simple{}, false
			}
			shell, assigned, byEnv = false, false, true
		case shell && !w.quoted && strings.Contains(w.s, "="):
			if !r.assignment(w.s) {
				return Simple{}, false
			}
			s.Assignments = append(s.Assignments, w.s)
			ws = ws[1:]
			assigned = true
		default:
			if unreadableFirst(w.s) != "" {
				return Simple{}, false
			}
			s.Words = make([]string, len(ws))
			for i, w := range ws {
				s.Words[i] = w.s
			}
			return s, true
		}
	}
}

// envOptions are env's options that run nothing and print the environment
// or nothing: -0 ends each variable with a NUL, -i and - clear the
// environment, and -v and --debug only say what env does.
var envOptions = []string{"-0", "--null", "-i", "--ignore-environment", "-", "-v", "--debug"}

// printsAll is whether ws, the words after env, are only options that leave
// env with no command to run, so that env prints its environment as env
// alone does: those of envOptions, and -u NAME, -uNAME, --unset NAME and
// --unset=NAME, each of a name. Each is env's in GNU's, BSD's and
// busybox's, or an error there, which runs nothing either. Any other option
// may run a command -- -S splits its argument into one, and its argument
// may be in the same word, `-Sls` -- and so is no such word.
func printsAll(ws []word) bool {
	for i := 0; i < len(ws); i++ {
		w := ws[i].s
		switch {
		case slices.Contains(envOptions, w):
		case w == "-u" || w == "--unset":
			if i++; i == len(ws) || !identifier(ws[i].s) {
				return false
			}
		case strings.HasPrefix(w, "-u") && identifier(w[2:]),
			strings.HasPrefix(w, "--unset=") && identifier(w[len("--unset="):]):
		default:
			return false
		}
	}
	return true
}

// assignment is whether w, a plain word holding =, is NAME=value of a name
// the route lists, with a value no shell reads as more than its bytes and
// no program as a file it chooses.
//
// The value may not begin = or hold :=, where zsh may expand a command's
// path, as for a word beginning = (see lex). Nor may it begin /, . or :,
// or hold .. or %: a name a route lists is read by every program the
// command runs, and LANG, LC_* and TZ, the names a route most often lists,
// are names of files too. glibc loads a locale named /dir from that
// directory, and musl a zone named /f, ./f or .f from that file, and TZ=:f
// is f; a zone holding .. leaves the zone directory it is joined to; and %
// is expanded in NLSPATH and its kin, as sudo refuses it. Locale and zone
// data is trusted by the library that reads it -- glibc ignores such names
// in a setuid program for that reason -- so one the session wrote would be
// parsed inside whatever program a rule admitted, which is then no longer
// what was decided. What is left names only the system's own data: C,
// C.UTF-8, en_GB.UTF-8, UTC, Europe/London.
func (r *Rules) assignment(w string) bool {
	name, value, _ := strings.Cut(w, "=")
	return identifier(name) && r.listed(name) &&
		!strings.HasPrefix(value, "=") && !strings.Contains(value, ":=") &&
		!strings.HasPrefix(value, "/") && !strings.HasPrefix(value, ".") && !strings.HasPrefix(value, ":") &&
		!strings.Contains(value, "..") && !strings.Contains(value, "%")
}

// identifier is whether s is a name every shell assigns: a letter or _,
// then letters, digits and _. `PATH+=x` appends in bash and `a-b=1` is a
// command, so neither is one.
func identifier(s string) bool {
	if s == "" || '0' <= s[0] && s[0] <= '9' {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !('a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9' || b == '_') {
			return false
		}
	}
	return true
}

// listed is whether the route's env names name: exactly, or by a prefix
// written with a trailing *.
func (r *Rules) listed(name string) bool {
	for _, e := range r.env {
		if p, ok := strings.CutSuffix(e, "*"); ok && strings.HasPrefix(name, p) || e == name {
			return true
		}
	}
	return false
}

// Parse reads command as these rules' grammar: its simple commands, each
// with what strip took off it, or false where it is unreadable. Which
// assignments are read depends on the route's env names; with none, every
// assignment is unreadable.
func (r *Rules) Parse(command string) ([]Simple, bool) {
	cmds, ok := lex(command)
	if !ok {
		return nil, false
	}
	out := make([]Simple, len(cmds))
	for i, c := range cmds {
		if out[i], ok = r.strip(c); !ok {
			return nil, false
		}
	}
	return out, true
}

// Readable is whether any rule of these could decide command at all. Any
// other command is never matched by any rule, admitting or refusing, and goes
// to the route's unmatched: a refuse rule is a convenience on readable
// commands, and only unmatched "refuse" is a boundary.
func (r *Rules) Readable(command string) bool {
	_, ok := r.Parse(command)
	return ok
}

// Readable is whether a route that lists no env names could decide command
// at all: Rules.Readable for one with none.
func Readable(command string) bool {
	return (&Rules{}).Readable(command)
}
