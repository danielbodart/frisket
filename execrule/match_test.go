package execrule

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/danielbodart/frisket/policy"
)

func TestACommandIsReadAsSimpleCommandsOfPlainOrQuotedWords(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		want    [][]string // nil: unreadable
	}{
		{"one word", "ls", [][]string{{"ls"}}},
		{"words", "systemctl status nginx.service", [][]string{{"systemctl", "status", "nginx.service"}}},
		{"runs of spaces", "  apt   update  ", [][]string{{"apt", "update"}}},
		{"the plain alphabet", "cp a/b,c@d%e+f:g ./h_i --since=2026-01-01", [][]string{{"cp", "a/b,c@d%e+f:g", "./h_i", "--since=2026-01-01"}}},
		{"a quoted word", "echo 'a b'", [][]string{{"echo", "a b"}}},
		{"a quoted word holding what a shell would read", "grep '$HOME; `id` | * \" ~ # (x) {y} <z>' f", [][]string{{"grep", "$HOME; `id` | * \" ~ # (x) {y} <z>", "f"}}},
		{"an empty quoted word", "ls ''", [][]string{{"ls", ""}}},
		{"a quoted command", "'sudo' reboot", [][]string{{"sudo", "reboot"}}},
		{"and", "cd /etc && ls", [][]string{{"cd", "/etc"}, {"ls"}}},
		{"or", "test -f x || touch x", [][]string{{"test", "-f", "x"}, {"touch", "x"}}},
		{"then", "uptime; df -h", [][]string{{"uptime"}, {"df", "-h"}}},
		{"a pipe", "ps aux | grep nginx", [][]string{{"ps", "aux"}, {"grep", "nginx"}}},
		{"operators without spaces", "cd /etc&&ls|wc -l;pwd||id", [][]string{{"cd", "/etc"}, {"ls"}, {"wc", "-l"}, {"pwd"}, {"id"}}},
		{"a quoted word against an operator", "echo 'a'&&echo 'b'", [][]string{{"echo", "a"}, {"echo", "b"}}},
		{"= past the first word", "journalctl --since=today", [][]string{{"journalctl", "--since=today"}}},
		{"a reserved word past the first", "echo if then fi", [][]string{{"echo", "if", "then", "fi"}}},
		{"a quoted word beginning =", "cat '=deploy'", [][]string{{"cat", "=deploy"}}},
		{"a % past a word's start", "date +%Y-%m-%d x%self", [][]string{{"date", "+%Y-%m-%d", "x%self"}}},
		{"a quoted word beginning %", "echo '%self'", [][]string{{"echo", "%self"}}},
		{"a double-quoted word", `echo "a b"`, [][]string{{"echo", "a b"}}},
		{"a double-quoted word holding what a shell would read outside them", `grep "; | * ~ # (x) {y} <z> [a] ? & %self =x ^" f`, [][]string{{"grep", "; | * ~ # (x) {y} <z> [a] ? & %self =x ^", "f"}}},
		{"an empty double-quoted word", `ls ""`, [][]string{{"ls", ""}}},
		{"a double-quoted command", `"sudo" reboot`, [][]string{{"sudo", "reboot"}}},
		{"a double-quoted word against an operator", `echo "a"&&echo "b"`, [][]string{{"echo", "a"}, {"echo", "b"}}},
		{"output to /dev/null", "ls -l >/dev/null", [][]string{{"ls", "-l"}}},
		{"input from /dev/null", "ls </dev/null", [][]string{{"ls"}}},
		{"both, either way round", "ls >/dev/null </dev/null; ls </dev/null >/dev/null", [][]string{{"ls"}, {"ls"}}},
		{"a redirection before an operator", "ls >/dev/null&&pwd </dev/null;id >/dev/null||pwd", [][]string{{"ls"}, {"pwd"}, {"id"}, {"pwd"}}},
		{"input from /dev/null into a pipe", "ls </dev/null | wc -l", [][]string{{"ls"}, {"wc", "-l"}}},
		{"output to /dev/null out of a pipe", "ls | wc -l >/dev/null", [][]string{{"ls"}, {"wc", "-l"}}},
		{"a quoted redirection is a word", "echo '>/dev/null' \">/dev/null\"", [][]string{{"echo", ">/dev/null", ">/dev/null"}}},
		{"exec", "exec ls -l", [][]string{{"ls", "-l"}}},
		{"command", "command ls", [][]string{{"ls"}}},
		{"builtin", "builtin cd /", [][]string{{"cd", "/"}}},
		{"a precommand past the first word", "echo exec command builtin", [][]string{{"echo", "exec", "command", "builtin"}}},
		{"a command as long as may be", "echo " + strings.Repeat("a", maxCommand-len("echo ")), [][]string{{"echo", strings.Repeat("a", maxCommand-len("echo "))}}},

		{"nothing", "", nil},
		{"spaces", "   ", nil},
		{"a leading operator", "; ls", nil},
		{"a leading pipe", "| ls", nil},
		{"a trailing operator", "ls ;", nil},
		{"a trailing and", "ls &&", nil},
		{"a trailing pipe", "ls |", nil},
		{"an empty simple command", "ls ; ; pwd", nil},
		{"two operators together", "ls;;pwd", nil},
		{"three pipes", "ls ||| pwd", nil},
		{"three ampersands", "ls &&& pwd", nil},
		{"a single ampersand", "sleep 1 & ls", nil},
		{"a trailing ampersand", "sleep 1 &", nil},
		{"a pipe of stderr", "ls |& cat", nil},
		{"an assignment", "PATH=/tmp ls", nil},
		{"an assignment alone", "X=1", nil},
		{"an assignment after an operator", "ls && LD_PRELOAD=/tmp/x.so ls", nil},
		{"a quoted assignment", "'X=1' ls", nil},
		{"zsh's =command past the first word", "cat =deploy", nil},
		{"a lone = past the first word", "echo =", nil},
		{"zsh's =command after an operator", "ls && cat =deploy", nil},
		{"time", "time rm x", [][]string{{"rm", "x"}}},
		{"if", "if true; then rm x; fi", nil},
		{"then after an operator", "ls; then", nil},
		{"while", "while ls; do rm x; done", nil},
		{"fish's not", "not rm x", nil},
		{"zsh's -", "ls; - rm x", nil},
		{"a quoted zsh -", "ls && '-' rm x", nil},
		{"fish's begin", "begin; rm x; end", nil},
		{"quoted and plain together", "a'b'", nil},
		{"plain after quoted", "'a'b", nil},
		{"two quoted together", "'a''b'", nil},
		{"an unterminated quote", "echo 'a", nil},
		{"a backslash in quotes", `echo 'a\'`, nil},
		{"a ! in quotes", "echo 'a!b'", nil},
		{"a tab in quotes", "echo 'a\tb'", nil},
		{"a newline in quotes", "echo 'a\nb'", nil},
		{"non-ASCII in quotes", "echo 'é'", nil},
		{"a dollar", "echo $HOME", nil},
		{"a substitution", "echo $(id)", nil},
		{"a backtick", "echo `id`", nil},
		{"a dollar in double quotes", `echo "$HOME"`, nil},
		{"a backtick in double quotes", "echo \"`id`\"", nil},
		{"an escaped double quote", `echo "a\"b"`, nil},
		{"a backslash in double quotes", `echo "a\b"`, nil},
		{"a ! in double quotes", `echo "a!b"`, nil},
		{"a single quote in double quotes", `echo "it's"`, nil},
		{"a tab in double quotes", "echo \"a\tb\"", nil},
		{"non-ASCII in double quotes", `echo "é"`, nil},
		{"an unterminated double quote", `echo "a`, nil},
		{"double-quoted and plain together", `a"b"`, nil},
		{"double- and single-quoted together", `"a"'b'`, nil},
		{"two double-quoted together", `"a""b"`, nil},
		{"fish's %self", "kill %self", nil},
		{"a word beginning %", "ls %1", nil},
		{"a % alone", "echo %", nil},
		{"a command beginning %", "%self", nil},
		{"a command longer than may be", "echo " + strings.Repeat("a", maxCommand-len("echo ")+1), nil},
		{"exec alone", "exec", nil},
		{"command alone", "command", nil},
		{"exec's option", "exec -a sshd ls", nil},
		{"command -v", "command -v ls", nil},
		{"command -p", "command -p ls", nil},
		{"command --", "command -- ls", nil},
		{"builtin --", "builtin -- cd", nil},
		{"a quoted option", "command '-v' ls", nil},
		{"a quoted precommand, which csh runs as a program", "'exec' ls", nil},
		{"a double-quoted precommand", `"command" ls`, nil},
		{"a precommand twice", "command command ls", nil},
		{"exec then command, which zsh runs and bash execs", "exec command ls", nil},
		{"a precommand after time", "time command ls", nil},
		{"a precommand then a reserved word", "command if", nil},
		{"a precommand then zsh's -", "exec - ls", nil},
		{"a backslash", `echo a\ b`, nil},
		{"a tab", "ls\tx", nil},
		{"a newline", "ls\nrm", nil},
		{"a carriage return", "ls\rrm", nil},
		{"a glob", "ls *", nil},
		{"a question mark", "ls ?", nil},
		{"a bracket", "ls [a]", nil},
		{"a tilde", "ls ~", nil},
		{"braces", "ls {a,b}", nil},
		{"a redirection in", "cat <x", nil},
		{"a redirection out", "ls >x", nil},
		{"a redirection of stderr", "ls 2>/dev/null", nil},
		{"a redirection with a space", "ls > /dev/null", nil},
		{"a redirection appending", "ls >>/dev/null", nil},
		{"a redirection of both", "ls &>/dev/null", nil},
		{"a redirection against a word", "ls x>/dev/null", nil},
		{"a redirection against another", "ls >/dev/null</dev/null", nil},
		{"a redirection to more than /dev/null", "ls >/dev/nullx", nil},
		{"a redirection to less", "ls >/dev/nul", nil},
		{"a redirection first, which fish refuses", ">/dev/null ls", nil},
		{"a redirection before a word", "ls >/dev/null -l", nil},
		{"a redirection alone", "ls; >/dev/null", nil},
		{"output twice, which csh calls ambiguous", "ls >/dev/null >/dev/null", nil},
		{"input twice", "ls </dev/null </dev/null", nil},
		{"output into a pipe, which csh calls ambiguous", "ls >/dev/null | wc", nil},
		{"input beside a pipe, which csh calls ambiguous", "ls | wc </dev/null", nil},
		{"a redirection after a single &", "ls >/dev/null & ls", nil},
		{"a subshell", "(id)", nil},
		{"a comment", "ls #", nil},
		{"a bang", "! ls", nil},
		{"non-ASCII", "ls é", nil},
		{"a NUL", "ls \x00", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parse(tc.command)
			if tc.want == nil {
				if ok {
					t.Errorf("%q read as %q", tc.command, got)
				}
				return
			}
			if !ok || !slices.EqualFunc(got, tc.want, slices.Equal[[]string]) {
				t.Errorf("%q: got %q %v, want %q", tc.command, got, ok, tc.want)
			}
		})
	}
}

// spec is a rule written shortly: "ask:" or "refuse:" first, then the
// command pattern, then " [arg glob]".
func spec(s string) policy.ExecRule {
	var e policy.ExecRule
	switch {
	case strings.HasPrefix(s, "ask:"):
		e.Ask, s = true, strings.TrimPrefix(s, "ask:")
	case strings.HasPrefix(s, "refuse:"):
		e.Refuse, s = true, strings.TrimPrefix(s, "refuse:")
	}
	if i := strings.Index(s, "[arg "); i >= 0 {
		e.Arg = strings.TrimSuffix(s[i+len("[arg "):], "]")
		s = strings.TrimSuffix(s[:i], " ")
	}
	e.Command = s
	return e
}

func mustRules(t testing.TB, specs ...string) []rule {
	t.Helper()
	var out []rule
	for _, s := range specs {
		r, err := compileRule(spec(s))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestTheMostLiteralRuleDecidesAndATieGoesToTheStricter(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rules     []string
		unmatched Outcome
		command   string
		outcome   Outcome
		rule      string
	}{
		{"an exact rule admits its command", []string{"apt update"}, Refuse, "apt update", Allow, "apt update"},
		{"runs of spaces are one separator", []string{"apt update"}, Refuse, "  apt   update ", Allow, "apt update"},
		{"an exact rule does not admit more words", []string{"apt update"}, Refuse, "apt update x", Refuse, RuleUnmatched},
		{"a star is exactly one word", []string{"systemctl status *"}, Ask, "systemctl status a b", Ask, RuleUnmatched},
		{"a star is not no word", []string{"systemctl status *"}, Ask, "systemctl status", Ask, RuleUnmatched},
		{"a star matches one", []string{"systemctl status *"}, Refuse, "systemctl status nginx", Allow, "systemctl status *"},
		{"a star matches a quoted word whatever it holds", []string{"echo *"}, Refuse, "echo 'a; rm -rf /'", Allow, "echo *"},
		{"a literal matches a quoted word", []string{"refuse:sudo **"}, Ask, "'sudo' reboot", Refuse, "sudo **"},
		{"a trailing double star matches none", []string{"uptime **"}, Refuse, "uptime", Allow, "uptime **"},
		{"a trailing double star matches many", []string{"journalctl **"}, Refuse, "journalctl -u x -n 5", Allow, "journalctl **"},
		{"words are matched whole, never as prefixes", []string{"cat /etc/hosts"}, Refuse, "cat /etc/hostsx", Refuse, RuleUnmatched},
		{"words are matched with their case", []string{"ls"}, Refuse, "LS", Refuse, RuleUnmatched},
		{"more literal words beat fewer", []string{"refuse:systemctl **", "systemctl status *"}, Refuse, "systemctl status nginx", Allow, "systemctl status *"},
		{"more literal words beat fewer when stricter", []string{"systemctl **", "refuse:systemctl stop *"}, Ask, "systemctl stop nginx", Refuse, "systemctl stop *"},
		{"a tie goes to refusing", []string{"sudo *", "refuse:sudo **"}, Ask, "sudo reboot", Refuse, "sudo **"},
		{"a tie goes to asking over admitting", []string{"ask:apt *", "apt **"}, Refuse, "apt upgrade", Ask, "apt *"},
		{"a bare double star is the least literal", []string{"**", "refuse:rm **"}, Refuse, "rm -rf x", Refuse, "rm **"},
		{"no match under ask is asked", nil, Ask, "ls", Ask, RuleUnmatched},
		{"an unreadable command is never admitted", []string{"**"}, Ask, "ls; rm -rf $HOME", Ask, RuleUnmatched},
		{"nor refused by a rule", []string{"refuse:rm **"}, Ask, `rm -rf "$HOME"`, Ask, RuleUnmatched},
		{"a double-quoted word is matched as its content", []string{"refuse:rm **", "echo *"}, Ask, `rm -rf "/" ; echo "a b"`, Refuse, "rm **"},
		{"a precommand is decided as what it runs", []string{"refuse:sudo **", "**"}, Ask, "command sudo reboot", Refuse, "sudo **"},
		{"redirections are no words of a command", []string{"ls"}, Refuse, "ls >/dev/null </dev/null", Allow, "ls"},
		{"nor by an arg rule", []string{"**", "refuse:[arg .ssh]"}, Ask, "cat ~/.ssh/id_rsa", Ask, RuleUnmatched},
		{"and unmatched refuse refuses it", []string{"**"}, Refuse, "echo $(id)", Refuse, RuleUnmatched},
		{"an empty command is unmatched", []string{"**"}, Refuse, "", Refuse, RuleUnmatched},
		{"an assignment is unmatched whatever the rules", []string{"ls", "**"}, Ask, "PATH=/tmp ls", Ask, RuleUnmatched},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := decide(mustRules(t, tc.rules...), tc.unmatched, tc.command)
			if d.Outcome != tc.outcome || d.Rule != tc.rule {
				t.Errorf("%q: got %v by %q, want %v by %q", tc.command, d.Outcome, d.Rule, tc.outcome, tc.rule)
			}
		})
	}
}

func TestEachSimpleCommandIsDecidedAndTheStrictestDecidesTheWhole(t *testing.T) {
	rules := []string{"cd *", "ls **", "cat *", "ask:systemctl restart *", "refuse:rm **", "wc **", "grep **"}
	for _, tc := range []struct {
		name      string
		unmatched Outcome
		command   string
		outcome   Outcome
		rule      string
	}{
		{"every part admitted", Refuse, "cd /etc && ls -l", Allow, "cd *"},
		{"a pipe of admitted parts", Refuse, "cat /etc/hosts | grep local | wc -l", Allow, "cat *"},
		{"one asked", Refuse, "ls; systemctl restart nginx", Ask, "systemctl restart *"},
		{"one refused after an or", Ask, "ls x || rm -rf x", Refuse, "rm **"},
		{"refusing beats asking, wherever it is", Ask, "rm x; systemctl restart nginx", Refuse, "rm **"},
		{"a part no rule matches is unmatched", Ask, "ls | sh", Ask, RuleUnmatched},
		{"and refused under refuse", Refuse, "cat x | sh", Refuse, RuleUnmatched},
		{"a part a rule matches less than whole", Refuse, "cd /etc /tmp && ls", Refuse, RuleUnmatched},
		{"between equals the first", Refuse, "cd / ; ls", Allow, "cd *"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := decide(mustRules(t, rules...), tc.unmatched, tc.command)
			if d.Outcome != tc.outcome || d.Rule != tc.rule {
				t.Errorf("%q: got %v by %q, want %v by %q", tc.command, d.Outcome, d.Rule, tc.outcome, tc.rule)
			}
		})
	}
}

func TestArgRulesOnlyTighten(t *testing.T) {
	rules := []string{
		"cat **", "ls **", "cd *", "grep **", "less **", "ask:cp **",
		"refuse:[arg .ssh]", "refuse:[arg id_*]", "refuse:[arg *.pem]", "refuse:[arg shadow]",
		"ask:less ** [arg +*]", "refuse:cp ** [arg /etc/*]", "refuse:rm **",
	}
	for _, tc := range []struct {
		name      string
		unmatched Outcome
		command   string
		outcome   Outcome
		rule      string
	}{
		{"a word that matches no glob", Refuse, "cat /etc/hosts", Allow, "cat **"},
		{"a component", Refuse, "cat /root/.ssh/config", Refuse, "[arg .ssh]"},
		{"a whole word", Refuse, "cd .ssh", Refuse, "[arg .ssh]"},
		{"a star within a component", Refuse, "cat /home/u/id_ed25519", Refuse, "[arg id_*]"},
		{"a suffix", Refuse, "cat /etc/ssl/private/site.pem", Refuse, "[arg *.pem]"},
		{"after an =", Refuse, "grep --file=id_rsa x", Refuse, "[arg id_*]"},
		{"a path after an =", Refuse, "grep --file=/etc/shadow x", Refuse, "[arg shadow]"},
		{"a quoted word", Refuse, "cat '/etc/shadow'", Refuse, "[arg shadow]"},
		{"anywhere in the command", Refuse, "ls /etc && cat /etc/shadow", Refuse, "[arg shadow]"},
		{"in a part no rule matches", Ask, "xxd /etc/shadow", Refuse, "[arg shadow]"},
		{"a glob matches a component whole", Refuse, "cat /x/xid_rsa", Allow, "cat **"},
		{"a glob with a / matches whole words", Refuse, "cp /etc/hosts /tmp", Refuse, "cp ** [arg /etc/*]"},
		{"and never across one", Refuse, "cp /etc/ssl/x /tmp", Ask, "cp **"},
		{"the command's own name is not an argument", Ask, "shadow -l", Ask, RuleUnmatched},
		{"a part of a component is not a component", Refuse, "cat /etc/shadows", Allow, "cat **"},
		{"an arg rule with a command applies to it", Refuse, "less +F log", Ask, "less ** [arg +*]"},
		{"and to nothing else", Refuse, "ls +F", Allow, "ls **"},
		{"an asking arg rule leaves a refusal", Refuse, "less +F x | sh", Refuse, RuleUnmatched},
		{"an asking arg rule under a stricter one", Refuse, "less +F /etc/shadow", Refuse, "[arg shadow]"},
		{"one as strict as unmatched is credited", Refuse, "xxd /etc/shadow", Refuse, "[arg shadow]"},
		{"one as strict as a command rule is credited", Refuse, "rm /etc/shadow", Refuse, "[arg shadow]"},
		{"the first of several as strict", Refuse, "cat /root/.ssh/id_rsa", Refuse, "[arg .ssh]"},
		{"a tilde is unreadable, so no arg rule sees it", Ask, "cp ~/.ssh/id_rsa /tmp", Ask, RuleUnmatched},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := decide(mustRules(t, rules...), tc.unmatched, tc.command)
			if d.Outcome != tc.outcome || d.Rule != tc.rule {
				t.Errorf("%q: got %v by %q, want %v by %q", tc.command, d.Outcome, d.Rule, tc.outcome, tc.rule)
			}
		})
	}
}

// The decision carries the deciding rule's operation, and every operation
// the parts were decided by where there are more than one.
func TestADecisionCarriesItsOperations(t *testing.T) {
	op := func(id string) *policy.Operation { return &policy.Operation{ID: id, Summary: id} }
	var rules []rule
	for _, e := range []policy.ExecRule{
		{Command: "ls **", Operation: op("list")},
		{Command: "cd *", Operation: op("cd")},
		{Command: "rm **", Refuse: true, Operation: op("remove")},
		{Command: "pwd"},
		{Arg: "shadow", Refuse: true, Operation: op("secret")},
		{Command: "systemctl status *", Operation: op("status")},
		{Command: "systemctl status", Operation: op("status")},
		{Command: "cp **", Ask: true, Operation: op("copy")},
		{Arg: "id_*", Ask: true, Operation: op("key")},
	} {
		r, err := compileRule(e)
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, r)
	}
	ids := func(ops []*policy.Operation) []string {
		var out []string
		for _, o := range ops {
			out = append(out, o.ID)
		}
		return out
	}
	for _, tc := range []struct {
		command    string
		operation  string
		operations []string
	}{
		{"ls", "list", nil},
		{"pwd", "", nil},
		{"ls; ls -l", "list", nil},
		{"cd / && ls", "cd", []string{"cd", "list"}},
		{"ls && rm x && cd /", "remove", []string{"list", "remove", "cd"}},
		{"ls /etc/shadow", "secret", nil},
		{"pwd | sh", "", nil},
		{"systemctl status nginx; systemctl status", "status", nil},
		{"systemctl status nginx && ls", "status", []string{"status", "list"}},
		{"xxd /etc/shadow", "secret", nil},
		{"cp id_rsa /tmp", "key", nil},
		{"cp /root/.ssh/id_rsa /tmp", "key", nil},
		{"cp ~/.ssh/id_rsa /tmp", "", nil},
		{"cp x /tmp && cp id_rsa /tmp", "copy", []string{"copy", "key"}},
	} {
		d := decide(rules, Refuse, tc.command)
		got := ""
		if d.Operation != nil {
			got = d.Operation.ID
		}
		if got != tc.operation || !slices.Equal(ids(d.Operations), tc.operations) {
			t.Errorf("%q: got %q %v, want %q %v", tc.command, got, ids(d.Operations), tc.operation, tc.operations)
		}
	}
}

func TestARuleIsRefusedUnlessItHasOneSpellingAndOneMeaning(t *testing.T) {
	for _, tc := range []struct {
		rule policy.ExecRule
		want string
	}{
		{policy.ExecRule{}, "no command and no arg"},
		{policy.ExecRule{Command: " ls"}, "one space"},
		{policy.ExecRule{Command: "ls "}, "one space"},
		{policy.ExecRule{Command: "ls  -l"}, "one space"},
		{policy.ExecRule{Command: "** ls"}, "only the last word"},
		{policy.ExecRule{Command: "ls ***"}, "not"},
		{policy.ExecRule{Command: "ls a*"}, "not"},
		{policy.ExecRule{Command: "ls $x"}, "not"},
		{policy.ExecRule{Command: "ls\t-l"}, "not"},
		{policy.ExecRule{Command: "ls; rm"}, "not"},
		{policy.ExecRule{Command: "PATH=/tmp **"}, "assignment"},
		{policy.ExecRule{Command: "cat =deploy"}, "begins ="},
		{policy.ExecRule{Command: "time **"}, "reserved word"},
		{policy.ExecRule{Command: "- **"}, "reserved word"},
		{policy.ExecRule{Command: "exec **"}, "runs the command after it"},
		{policy.ExecRule{Command: "command *"}, "runs the command after it"},
		{policy.ExecRule{Command: "builtin"}, "runs the command after it"},
		{policy.ExecRule{Command: "kill %self"}, "begins %"},
		{policy.ExecRule{Command: "%1"}, "begins %"},
		{policy.ExecRule{Command: "ls", Ask: true, Refuse: true}, "both asks and refuses"},
		{policy.ExecRule{Arg: ".ssh"}, "only asks or refuses"},
		{policy.ExecRule{Command: "cat **", Arg: ".ssh"}, "only asks or refuses"},
		{policy.ExecRule{Arg: "*", Refuse: true}, "every word"},
		{policy.ExecRule{Arg: "***", Refuse: true}, "**"},
		{policy.ExecRule{Arg: "a**b", Refuse: true}, "never crosses"},
		{policy.ExecRule{Arg: "a\\b", Refuse: true}, "printable"},
		{policy.ExecRule{Arg: "it's", Refuse: true}, "printable"},
		{policy.ExecRule{Arg: "a\tb", Refuse: true}, "printable"},
		{policy.ExecRule{Arg: "é", Refuse: true}, "printable"},
		{policy.ExecRule{Command: "ls *x", Arg: ".ssh", Refuse: true}, "not"},
		{policy.ExecRule{Command: "ls", Operation: &policy.Operation{ID: "ls"}}, "id and a summary"},
		{policy.ExecRule{Command: "ls", Operation: &policy.Operation{ID: "ls", Summary: "List", Class: "safe"}}, "read, write or guarded"},
	} {
		_, err := compileRule(tc.rule)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: got %v, want an error saying %q", tc.rule, err, tc.want)
		}
	}
}

// The alphabet commands are drawn from: plain bytes and space, weighted to
// make words, and every kind of byte that is not.
var (
	plainChars    = []byte("abcz09_@%+=:,./- ")
	nonPlainChars = []byte("'\"$`;|&<>(){}*?[]~!#\\\t\n\r\x00\x7f\xc3\xa9\xff")
)

// stringOf draws strings of min to max bytes from chars.
func stringOf(chars []byte, min, max int) *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		return string(rapid.SliceOfN(rapid.SampledFrom(chars), min, max).Draw(t, "bytes"))
	})
}

// word draws a word a pattern may hold.
var patternWord = rapid.OneOf(
	rapid.SampledFrom([]string{"*", "ls", "rm", "sudo", "cat", "a", "-rf", "/", "x=1", "time", "exec", "command"}),
	stringOf(plainChars[:len(plainChars)-1], 1, 4),
)

// drawRules draws rules frisket can read, admitting ones above all, and
// arg rules among them.
func drawRules(t *rapid.T) []rule {
	n := rapid.IntRange(0, 6).Draw(t, "rules")
	var rules []rule
	for len(rules) < n {
		var e policy.ExecRule
		if rapid.IntRange(0, 3).Draw(t, "kind") > 0 {
			ws := rapid.SliceOfN(patternWord, 0, 4).Draw(t, "words")
			if len(ws) == 0 || rapid.Bool().Draw(t, "tail") {
				ws = append(ws, "**")
			}
			e.Command = strings.Join(ws, " ")
		}
		outcome := rapid.SampledFrom([]Outcome{Allow, Allow, Ask, Refuse}).Draw(t, "outcome")
		if e.Command == "" || rapid.IntRange(0, 4).Draw(t, "arg") == 0 {
			e.Arg = rapid.SampledFrom([]string{"a", "*a", "b*", ".ssh", "id_*", "*.pem", "/etc/shadow"}).Draw(t, "glob")
			if outcome == Allow {
				outcome = Refuse
			}
		}
		e.Ask, e.Refuse = outcome == Ask, outcome == Refuse
		r, err := compileRule(e)
		if err != nil {
			// A first word that is an assignment or reserved: refused, as
			// it should be, and not a rule to draw.
			continue
		}
		rules = append(rules, r)
	}
	return rules
}

// drawCommand draws commands, mostly readable ones.
func drawCommand(t *rapid.T) string {
	simple := rapid.Custom(func(t *rapid.T) string {
		ws := rapid.SliceOfN(rapid.OneOf(
			patternWord,
			rapid.SampledFrom([]string{"''", "'a b'", "'*'", "'$x'", `""`, `"a b"`, `"*"`, `"ls"`, `"$x"`, "%self", ">/dev/null", "</dev/null", "/root/.ssh/x", "id_rsa", "k.pem", "--f=/etc/shadow"}),
			stringOf(plainChars, 0, 6),
		), 0, 4).Draw(t, "words")
		return strings.Join(ws, rapid.SampledFrom([]string{" ", "  "}).Draw(t, "sep"))
	})
	parts := rapid.SliceOfN(simple, 1, 4).Draw(t, "parts")
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteString(rapid.SampledFrom([]string{"&&", " && ", "||", " | ", ";", "; ", "&", "|||", ";;"}).Draw(t, "op"))
		}
		b.WriteString(p)
	}
	return b.String()
}

// noUnreadableCommandIsAdmitted: whatever the rules, a command with one byte
// outside the grammar is never admitted. A shell would read it as something
// other than its words, so no rule can say what it is.
func noUnreadableCommandIsAdmitted(t *rapid.T) {
	rules := drawRules(t)
	unmatched := rapid.SampledFrom([]Outcome{Ask, Refuse}).Draw(t, "unmatched")

	command := rapid.OneOf(
		rapid.Custom(func(t *rapid.T) string {
			before := stringOf(plainChars, 0, 20).Draw(t, "before")
			bad := rapid.SampledFrom(nonPlainChars).Draw(t, "bad")
			after := stringOf(append(append([]byte(nil), plainChars...), nonPlainChars...), 0, 20).Draw(t, "after")
			return before + string([]byte{bad}) + after
		}),
		rapid.Custom(drawCommand),
	).Draw(t, "command")

	if d := decide(rules, unmatched, command); d.Outcome == Allow && !Readable(command) {
		t.Fatalf("%q, unreadable, admitted by %q", command, d.Rule)
	}
}

func TestNoUnreadableCommandIsAdmitted(t *testing.T) { rapid.Check(t, noUnreadableCommandIsAdmitted) }

func FuzzNoUnreadableCommandIsAdmitted(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(noUnreadableCommandIsAdmitted))
}

// Whatever a readable command reads as, each of its simple commands is one
// a shell runs with exactly those words: rejoined, quoted, and read again,
// it is the same -- single-quoted, or double-quoted where its bytes allow.
func TestAReadableCommandReadsTheSameRequoted(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		command := drawCommand(t)
		cmds, ok := parse(command)
		if !ok {
			t.Skip("unreadable")
		}
		var parts []string
		for _, c := range cmds {
			q := make([]string, len(c))
			for i, w := range c {
				q[i] = "'" + w + "'"
				if !strings.ContainsFunc(w, func(r rune) bool { return r > '~' || !doubleQuotedByte(byte(r)) }) &&
					rapid.Bool().Draw(t, "double") {
					q[i] = `"` + w + `"`
				}
			}
			parts = append(parts, strings.Join(q, " "))
		}
		again, ok := parse(strings.Join(parts, " ; "))
		if !ok || !slices.EqualFunc(cmds, again, slices.Equal[[]string]) {
			t.Fatalf("%q read as %q, and requoted as %q %v", command, cmds, again, ok)
		}
	})
}

// Redirecting a simple command's input from /dev/null, or its output to
// it, changes nothing about what runs, and so nothing about how it is
// decided.
func TestARedirectionToDevNullDecidesNothing(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rules := drawRules(t)
		unmatched := rapid.SampledFrom([]Outcome{Ask, Refuse}).Draw(t, "unmatched")
		command := drawCommand(t)
		cmds, ok := lex(command)
		if !ok {
			t.Skip("unreadable")
		}
		redirect := rapid.SampledFrom([]string{">/dev/null", "</dev/null", ">/dev/null </dev/null", "</dev/null >/dev/null"}).Draw(t, "redirect")
		at := rapid.IntRange(0, len(cmds)-1).Draw(t, "part")
		parts := make([]string, len(cmds))
		for i, c := range cmds {
			parts[i] = requote(c)
			if i == at {
				parts[i] += " " + redirect
			}
		}
		joined := strings.Join(parts, rapid.SampledFrom([]string{" && ", "||", "; "}).Draw(t, "op"))
		before, after := decide(rules, unmatched, command), decide(rules, unmatched, joined)
		if after.Outcome != before.Outcome || after.Rule != before.Rule {
			t.Fatalf("%q is %v by %q, but %q is %v by %q", command, before.Outcome, before.Rule, joined, after.Outcome, after.Rule)
		}
	})
}

// Joining readable simple commands to a command never makes its decision
// less strict, whatever the operator and on either side: every part of a
// command may run. (Joining an unreadable one can: the whole is then
// unmatched, asked about where a rule would have refused -- which is why
// only unmatched "refuse" is a boundary. So can a pipe between two readable
// ones that redirect to or from /dev/null across it, which csh refuses to
// run: `ls >/dev/null | wc` is unreadable.)
func TestAddingASimpleCommandNeverLoosens(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rules := drawRules(t)
		unmatched := rapid.SampledFrom([]Outcome{Ask, Refuse}).Draw(t, "unmatched")
		command := drawCommand(t)
		extra := drawCommand(t)
		if !Readable(extra) {
			t.Skip("unreadable")
		}
		op := rapid.SampledFrom([]string{" && ", "||", " | ", "; "}).Draw(t, "op")
		before := decide(rules, unmatched, command)
		for _, joined := range []string{command + op + extra, extra + op + command} {
			if !Readable(joined) && Readable(command) {
				if op != " | " {
					t.Fatalf("%q and %q are readable, but %q is not", command, extra, joined)
				}
				continue
			}
			if after := decide(rules, unmatched, joined); strictness(after.Outcome) < strictness(before.Outcome) {
				t.Fatalf("%q is %v by %q, but %q is %v by %q", command, before.Outcome, before.Rule, joined, after.Outcome, after.Rule)
			}
		}
	})
}

// A word an arg rule refuses, anywhere in a readable command -- in any part,
// in any place but a command's name -- refuses the command, whatever else
// admits it.
func TestAnArgRefusedWordAnywhereRefuses(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		secrets, err := compileRule(policy.ExecRule{Arg: ".ssh", Refuse: true})
		if err != nil {
			t.Fatal(err)
		}
		rules := append(drawRules(t), secrets)
		unmatched := rapid.SampledFrom([]Outcome{Ask, Refuse}).Draw(t, "unmatched")
		command := drawCommand(t)
		cmds, ok := parse(command)
		if !ok {
			t.Skip("unreadable")
		}
		secret := rapid.SampledFrom([]string{".ssh", "/root/.ssh", "/home/u/.ssh/id_ed25519", "'.ssh'", "--key=.ssh/x"}).Draw(t, "secret")
		at := rapid.IntRange(0, len(cmds)-1).Draw(t, "part")
		var parts []string
		for i, c := range cmds {
			q := make([]string, len(c))
			for j, w := range c {
				q[j] = "'" + w + "'"
			}
			if i == at {
				k := rapid.IntRange(1, len(q)).Draw(t, "place")
				q = slices.Insert(q, k, secret)
			}
			parts = append(parts, strings.Join(q, " "))
		}
		joined := strings.Join(parts, " && ")
		if d := decide(rules, unmatched, joined); d.Outcome != Refuse {
			t.Fatalf("%q is %v by %q", joined, d.Outcome, d.Rule)
		}
	})
}

// A readable command is decided by the rule a reading of the words alone
// would pick: one matching rule with no other as literal decides it exactly.
func TestAReadableCommandIsDecidedByItsOnlyMatchingRule(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// A first word a shell reads as its own -- zsh's - -- is no rule,
		// and nor is a word fish reads as a process.
		ws := rapid.SliceOfN(stringOf([]byte("abcz09_@%+:,./-"), 1, 6), 1, 5).
			Filter(func(ws []string) bool {
				return unreadableFirst(ws[0]) == "" && !slices.ContainsFunc(ws, func(w string) bool { return w[0] == '%' })
			}).Draw(t, "words")
		outcome := rapid.SampledFrom([]Outcome{Allow, Ask, Refuse}).Draw(t, "outcome")
		pattern := strings.Join(ws, " ")
		r, err := compileRule(policy.ExecRule{Command: pattern, Ask: outcome == Ask, Refuse: outcome == Refuse})
		if err != nil {
			t.Fatal(err)
		}
		pad := stringOf([]byte(" "), 0, 3).Draw(t, "pad")
		command := pad + strings.Join(ws, pad+" ") + pad
		if d := decide([]rule{r}, Refuse, command); d.Outcome != outcome || d.Rule != pattern {
			t.Fatalf("%q under %q: got %v by %q", command, pattern, d.Outcome, d.Rule)
		}
	})
}

// glob is what a regular expression for it says: each * any run of bytes
// but /, and every other byte itself.
func TestAGlobsStarIsAnyRunButASlash(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		g := stringOf([]byte("ab/*."), 1, 8).Draw(t, "glob")
		s := stringOf([]byte("ab/."), 0, 10).Draw(t, "s")
		parts := strings.Split(g, "*")
		for i, p := range parts {
			parts[i] = regexp.QuoteMeta(p)
		}
		re := regexp.MustCompile("^" + strings.Join(parts, "[^/]*") + "$")
		if got, want := glob(g, s), re.MatchString(s); got != want {
			t.Fatalf("glob(%q, %q) = %v, want %v", g, s, got, want)
		}
	})
}
