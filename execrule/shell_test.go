package execrule

import (
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/danielbodart/frisket/policy"
)

func shellRules(t testing.TB, unmatched string, specs ...string) *Rules {
	t.Helper()
	route := policy.SSHRoute{Unmatched: unmatched, Shell: true}
	for _, s := range specs {
		route.Exec = append(route.Exec, spec(s))
	}
	r, err := Compile(route)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A Shell route reads one simple command of plain words, and nothing more:
// the device's shell is no grammar frisket knows.
func TestAShellRouteReadsOneSimpleCommandOfPlainWords(t *testing.T) {
	r := shellRules(t, "ask")
	for _, tc := range []struct {
		name    string
		command string
		want    []string // nil: unreadable
	}{
		{"one word", "uptime", []string{"uptime"}},
		{"words", "xdslctl info --show", []string{"xdslctl", "info", "--show"}},
		{"runs of spaces", "  xdslctl   info  ", []string{"xdslctl", "info"}},
		{"the plain alphabet", "cfg a/b,c@d%e+f:g ./h_i --x=1", []string{"cfg", "a/b,c@d%e+f:g", "./h_i", "--x=1"}},
		{"env is a word like any other", "env LANG=C ls", []string{"env", "LANG=C", "ls"}},
		{"so is a precommand", "exec ls", []string{"exec", "ls"}},
		{"so is time", "time ls", []string{"time", "ls"}},
		{"and an assignment first", "A=1 ls", []string{"A=1", "ls"}},
		{"a reserved word", "if x", []string{"if", "x"}},

		{"empty", "", nil},
		{"spaces alone", "   ", nil},
		{"then", "uptime; reboot", nil},
		{"and", "uptime && reboot", nil},
		{"or", "uptime || reboot", nil},
		{"a pipe", "uptime | reboot", nil},
		{"a background", "uptime & reboot", nil},
		{"a redirection to /dev/null", "uptime >/dev/null", nil},
		{"input from /dev/null", "uptime </dev/null", nil},
		{"a single-quoted word", "echo 'a b'", nil},
		{"a double-quoted word", `echo "a"`, nil},
		{"a carriage return", "uptime\rreboot", nil},
		{"a newline", "uptime\nreboot", nil},
		{"a tab, which completes", "upt\time", nil},
		{"a question mark, which asks for help", "show ?", nil},
		{"a control byte", "uptime\x03", nil},
		{"a backslash", `echo a\b`, nil},
		{"a dollar", "echo $HOME", nil},
		{"not ASCII", "echo é", nil},
		{"a word beginning %", "echo %self", nil},
		{"a word beginning =", "cat =deploy", nil},
		{"as long as a typed line may be", strings.Repeat("a", maxShellCommand), []string{strings.Repeat("a", maxShellCommand)}},
		{"longer", strings.Repeat("a", maxShellCommand+1), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := r.Parse(tc.command)
			if tc.want == nil {
				if ok {
					t.Fatalf("%q read as %v", tc.command, got)
				}
				return
			}
			if !ok || len(got) != 1 || !slices.Equal(got[0].Words, tc.want) || got[0].Assignments != nil {
				t.Fatalf("%q read as %v, %v; want %q", tc.command, got, ok, tc.want)
			}
		})
	}
}

// What a Shell route cannot read is refused even where unmatched is "ask":
// it would be typed byte for byte into a line editor, which may read it as
// more than one line, or cut it short, and a person asked about it could
// not tell.
func TestAShellRouteRefusesWhatItCannotReadEvenWhereUnmatchedAsks(t *testing.T) {
	r := shellRules(t, "ask", "xdslctl **")
	for _, command := range []string{
		"xdslctl info --show\rreboot",
		"xdslctl info --show" + strings.Repeat(" ", 1000) + "\rreboot",
		"reboot\x15xdslctl info --show",
		"xdslctl info --show\nreboot",
		"xdslctl\tinfo",
		"xdslctl info ?",
		"xdslctl info; reboot",
		"xdslctl " + strings.Repeat("a", maxShellCommand),
	} {
		if d := r.Decide(command); d.Outcome != Refuse || d.Rule != RuleUnmatched {
			t.Errorf("%q: %v by %q, want refused as unmatched", command, d.Outcome, d.Rule)
		}
	}
	if d := r.Decide("reboot now"); d.Outcome != Ask {
		t.Errorf("a readable command no rule names: %v, want asked", d.Outcome)
	}
}

// What a Shell route cannot read is unmatched, as on any route, and never
// admitted by a rule that would admit its words on another route.
func TestAShellRouteDecidesWhatItCannotReadAsUnmatched(t *testing.T) {
	r := shellRules(t, "refuse", "xdslctl **", "ls **", "refuse:reboot **", "refuse:[arg .ssh]")
	for command, want := range map[string]Outcome{
		"xdslctl info --show":          Allow,
		"xdslctl info; reboot":         Refuse,
		"ls >/dev/null":                Refuse,
		"LANG=C ls":                    Refuse,
		"ls /root/.ssh":                Refuse,
		"reboot now":                   Refuse,
		"xdslctl info --show && ls -l": Refuse,
	} {
		if got := r.Decide(command); got.Outcome != want {
			t.Errorf("%q: %v, want %v", command, got.Outcome, want)
		}
	}
	if d := r.Decide("ls; ls"); d.Rule != RuleUnmatched {
		t.Errorf("an unreadable command was decided by %q", d.Rule)
	}
}

func TestAShellRouteListsNoEnvNames(t *testing.T) {
	_, err := Compile(policy.SSHRoute{Shell: true, Env: []string{"LANG"}, Exec: []policy.ExecRule{{Command: "ls"}}})
	if err == nil || !strings.Contains(err.Error(), "shell route") {
		t.Fatalf("env on a shell route: %v", err)
	}
}

// Every command a Shell route reads is one line of plain bytes: nothing a
// line editor could end early, complete or read as more than itself.
func TestAShellRouteReadsOnlyALineOfPlainBytes(t *testing.T) {
	r := shellRules(t, "ask")
	rapid.Check(t, func(t *rapid.T) {
		b := rapid.SliceOfN(rapid.OneOf(rapid.Byte(), rapid.SampledFrom([]byte(" xy-./=%;|&<>'\"\r\n\t?\\$"))), 0, 64).Draw(t, "command")
		command := string(b)
		cmds, ok := r.Parse(command)
		if !ok {
			return
		}
		if len(cmds) != 1 || len(command) > maxShellCommand {
			t.Fatalf("%q read as %v", command, cmds)
		}
		for i := 0; i < len(command); i++ {
			if b := command[i]; b != ' ' && !plainByte(b) {
				t.Fatalf("%q read, with %q in it", command, b)
			}
		}
		if got := strings.Join(cmds[0].Words, " "); got != strings.Join(strings.Fields(command), " ") {
			t.Fatalf("%q read as %q", command, got)
		}
	})
}
