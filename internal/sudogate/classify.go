package sudogate

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/danielbodart/frisket/execrule"
	"github.com/danielbodart/frisket/internal/galleyask"
)

var envAllowed = map[string]bool{
	"HOME": true, "LOGNAME": true, "USER": true, "SHELL": true, "MAIL": true, "TERM": true,
	"TERMINFO": true, "TERMINFO_DIRS": true, "LANG": true, "PATH": true, "DISPLAY": true,
	"XAUTHORITY": true, "COLORTERM": true, "SUDO_USER": true, "SUDO_UID": true, "SUDO_GID": true,
	"SUDO_COMMAND": true, "SUDO_HOME": true,
}

const unreadable = "a shell command frisket cannot read"

// rootOwned is whether program is absolute, clean and directly in one of the
// root-owned directories.
func rootOwned(program, user string) bool {
	if !filepath.IsAbs(program) || filepath.Clean(program) != program {
		return false
	}
	switch filepath.Dir(program) {
	case "/run/current-system/sw/bin", "/run/wrappers/bin", "/etc/profiles/per-user/" + user + "/bin":
		return true
	}
	return false
}

// dangers are the catalogue's reasons for words, a shell's -c string and
// env's command classified by every simple command in them. shell says
// words run a shell whatever its name, as sudo -s and -i do. A shell run
// any other way than exactly <shell> -c STRING cannot be read.
func dangers(rules *execrule.Rules, words []string, shell bool) []string {
	words = slices.Clone(words)
	words[0] = filepath.Base(words[0])
	switch {
	case shell || galleyask.Shell(words[0]):
		if len(words) != 3 || words[1] != "-c" || strings.HasPrefix(words[2], "-") || strings.HasPrefix(words[2], "+") {
			return []string{unreadable}
		}
		cmds, ok := rules.Parse(words[2])
		if !ok {
			return []string{unreadable}
		}
		var reasons []string
		for _, c := range cmds {
			reasons = append(reasons, dangers(rules, c.Words, false)...)
		}
		return reasons
	case words[0] == "env" && len(words) > 1:
		if strings.HasPrefix(words[1], "-") || strings.Contains(words[1], "=") {
			return []string{unreadable}
		}
		return dangers(rules, words[1:], false)
	}
	if d := rules.DecideWords(words); d.Outcome == execrule.Ask && d.Rule != execrule.RuleUnmatched && d.Operation != nil {
		return []string{d.Operation.Summary}
	}
	return nil
}

// unescape undoes sudo's escaping of a -s or -i command: a backslash before
// every byte but letters, digits, _, - and $.
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// envLines are the variables outside the allowlist, each cut.
func envLines(envp []string) []string {
	var lines []string
	for _, e := range envp {
		name, _, _ := strings.Cut(e, "=")
		if !envAllowed[name] && !strings.HasPrefix(name, "LC_") {
			lines = append(lines, galleyask.Clean(e))
		}
	}
	return lines
}

func outsideLine(program string) string {
	return fmt.Sprintf("runs %s, outside the root-owned directories", galleyask.Clean(program))
}
