package execrule

import (
	"fmt"
	"path"
	"slices"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/danielbodart/frisket/policy"
)

// mustCompile compiles a route of rules written as spec writes them, with
// env names, under unmatched.
func mustCompile(t testing.TB, unmatched string, env []string, specs ...string) *Rules {
	t.Helper()
	route := policy.SSHRoute{Unmatched: unmatched, Env: env}
	for _, s := range specs {
		route.Exec = append(route.Exec, spec(s))
	}
	r, err := Compile(route)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAPrecommandAListedAssignmentTimeAndEnvAreTakenOffWhatRuns(t *testing.T) {
	r := mustCompile(t, "ask", []string{"LANG", "LC_*", "TZ"})
	for _, tc := range []struct {
		name    string
		command string
		want    []Simple // nil: unreadable
	}{
		{"an assignment", "LANG=C ls", []Simple{{[]string{"ls"}, []string{"LANG=C"}}}},
		{"several, one by a prefix", "LANG=C LC_ALL=C.UTF-8 ls -l", []Simple{{[]string{"ls", "-l"}, []string{"LANG=C", "LC_ALL=C.UTF-8"}}}},
		{"an empty value", "TZ= date", []Simple{{[]string{"date"}, []string{"TZ="}}}},
		{"a value holding =", "LANG=a=b ls", []Simple{{[]string{"ls"}, []string{"LANG=a=b"}}}},
		{"env and an assignment", "env LANG=C ls", []Simple{{[]string{"ls"}, []string{"LANG=C"}}}},
		{"env alone is env", "env", []Simple{{[]string{"env"}, nil}}},
		{"env with only assignments is env", "env LANG=C", []Simple{{[]string{"env"}, []string{"LANG=C"}}}},
		{"an assignment to env alone", "LANG=C env", []Simple{{[]string{"env"}, []string{"LANG=C"}}}},
		{"env with an option that runs nothing is env", "env -0", []Simple{{[]string{"env"}, nil}}},
		{"env with options that run nothing is env", "env -i --null -u LANG -uTZ --unset=LC_ALL --unset LC_X -", []Simple{{[]string{"env"}, nil}}},
		{"a precommand and env -0", "exec env -0", []Simple{{[]string{"env"}, nil}}},
		{"an assignment to env -i", "LANG=C env -i", []Simple{{[]string{"env"}, []string{"LANG=C"}}}},
		{"a quoted env", "'env' ls", []Simple{{[]string{"ls"}, nil}}},
		{"time", "time ls", []Simple{{[]string{"ls"}, nil}}},
		{"env's time -p", "env time -p ls -l", []Simple{{[]string{"ls", "-l"}, nil}}},
		{"env's time and a quoted -p", "env time '-p' ls", []Simple{{[]string{"ls"}, nil}}},
		{"a zone by area and city", "TZ=Europe/London date", []Simple{{[]string{"date"}, []string{"TZ=Europe/London"}}}},
		{"a zone as a POSIX rule", "TZ=EST5EDT date", []Simple{{[]string{"date"}, []string{"TZ=EST5EDT"}}}},
		{"a locale with a codeset", "LC_ALL=en_GB.UTF-8 ls", []Simple{{[]string{"ls"}, []string{"LC_ALL=en_GB.UTF-8"}}}},
		{"time twice", "time time ls", []Simple{{[]string{"ls"}, nil}}},
		{"time then env", "time env LANG=C ls", []Simple{{[]string{"ls"}, []string{"LANG=C"}}}},
		{"env then time", "env LANG=C time -p ls", []Simple{{[]string{"ls"}, []string{"LANG=C"}}}},
		{"an assignment then env then an assignment", "TZ=UTC env LANG=C date", []Simple{{[]string{"date"}, []string{"TZ=UTC", "LANG=C"}}}},
		{"each simple command its own", "cd /etc && LANG=C ls | time wc -l", []Simple{{[]string{"cd", "/etc"}, nil}, {[]string{"ls"}, []string{"LANG=C"}}, {[]string{"wc", "-l"}, nil}}},
		{"past the first word, an argument", "ls LANG=C time", []Simple{{[]string{"ls", "LANG=C", "time"}, nil}}},
		{"exec", "exec ls", []Simple{{[]string{"ls"}, nil}}},
		{"command then env", "command env LANG=C ls", []Simple{{[]string{"ls"}, []string{"LANG=C"}}}},
		{"exec then the program time, which takes -p", "exec time -p ls", []Simple{{[]string{"ls"}, nil}}},
		{"builtin then time", "builtin time ls", []Simple{{[]string{"ls"}, nil}}},
		{"command then env alone", "command env", []Simple{{[]string{"env"}, nil}}},
		{"redirections after what strip takes off", "env LANG=C time ls >/dev/null", []Simple{{[]string{"ls"}, []string{"LANG=C"}}}},

		{"a name not listed", "LD_PRELOAD=x ls", nil},
		{"PATH", "PATH=/tmp ls", nil},
		{"a name a listed one begins", "LANGUAGE=en ls", nil},
		{"a prefix's start without its _", "LC=x ls", nil},
		{"one not listed among listed", "LANG=C LD_PRELOAD=x ls", nil},
		{"a name that is no identifier", "1LANG=C ls", nil},
		{"bash's append", "LANG+=x ls", nil},
		{"an assignment alone", "LANG=C", nil},
		{"an assignment alone before another", "LANG=C && ls", nil},
		{"a quoted assignment", "'LANG=C' ls", nil},
		{"a value beginning =", "LANG==ls ls", nil},
		{"a value holding :=", "LANG=a:=ls ls", nil},
		{"env with a name not listed", "env LD_PRELOAD=x ls", nil},
		{"env with a quoted assignment", "env 'LANG=C' ls", nil},
		{"env -i", "env -i ls", nil},
		{"env -", "env - ls", nil},
		{"env --", "env -- ls", nil},
		{"env -u", "env -u LANG ls", nil},
		{"env -S", "env -S 'ls -l'", nil},
		{"env -S in one word", "env -Sls", nil},
		{"env -0 and a command", "env -0 ls", nil},
		{"env -u with no name", "env -u", nil},
		{"env -u and a word no name", "env -u a-b", nil},
		{"env -C", "env -C /tmp", nil},
		{"env with an option that runs nothing after an assignment", "env LANG=C -0", nil},
		{"env with an option after an assignment", "env LANG=C -i ls", nil},
		{"time alone", "time", nil},
		{"time -p alone", "time -p", nil},
		{"the shell's time -p, which zsh runs as a command named -p", "time -p ls", nil},
		{"the shell's time and a quoted -p, which bash runs as a command named -p", "time '-p' ls", nil},
		{"time -p after time", "time time -p ls", nil},
		{"time -p after an assignment's env", "LANG=C time -p ls", nil},
		{"a locale by its directory", "LC_ALL=/tmp/l ls", nil},
		{"env and a locale by its directory", "env LC_ALL=/tmp/l ls", nil},
		{"a zone by its file", "TZ=/tmp/z date", nil},
		{"a zone by its file after :", "TZ=:/tmp/z date", nil},
		{"a zone by : alone", "TZ=:UTC date", nil},
		{"a zone relative to the directory", "TZ=./z date", nil},
		{"a zone musl opens as a file", "TZ=.z date", nil},
		{"a zone out of its directory", "TZ=../../../tmp/z date", nil},
		{"a zone out of its directory partway", "TZ=Europe/../../tmp/z date", nil},
		{"a value holding %", "LANG=a%Lb ls", nil},
		{"another time option", "time -v ls", nil},
		{"time --", "time -- ls", nil},
		{"time -p and another", "time -p -o x ls", nil},
		{"time before an assignment", "time LANG=C ls", nil},
		{"an assignment before time", "LANG=C time ls", nil},
		{"env's time before an assignment", "env time LANG=C ls", nil},
		{"time before a reserved word", "time then", nil},
		{"env before a reserved word", "env if", nil},
		{"an assignment before a precommand, which csh runs as a command", "LANG=C command ls", nil},
		{"a precommand before an assignment, a command's name to it", "command LANG=C ls", nil},
		{"env before a precommand, the program of its name", "env command ls", nil},
		{"time before a precommand, the program of its name to dash", "time exec ls", nil},
		{"a precommand before time and an assignment", "exec time LANG=C ls", nil},
		{"a precommand before env's option", "command env -i ls", nil},
		{"a precommand before time alone", "exec time", nil},
		{"a precommand before redirections alone", "exec >/dev/null", nil},
		{"time before redirections alone", "time </dev/null", nil},
		{"an assignment before redirections alone", "LANG=C >/dev/null", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := r.Parse(tc.command)
			if tc.want == nil {
				if ok {
					t.Errorf("%q read as %q", tc.command, got)
				}
				return
			}
			if !ok || !slices.EqualFunc(got, tc.want, func(a, b Simple) bool {
				return slices.Equal(a.Words, b.Words) && slices.Equal(a.Assignments, b.Assignments)
			}) {
				t.Errorf("%q: got %q %v, want %q", tc.command, got, ok, tc.want)
			}
		})
	}
}

func TestWithNoNamesListedEveryAssignmentIsUnreadable(t *testing.T) {
	for _, c := range []string{"LANG=C ls", "env LANG=C ls", "env LANG=C"} {
		if Readable(c) {
			t.Errorf("%q is readable", c)
		}
	}
	for _, c := range []string{"env", "env ls", "time ls", "env time -p ls"} {
		if !Readable(c) {
			t.Errorf("%q is unreadable", c)
		}
	}
}

func TestACommandIsDecidedAsWhatRunsAndItsAssignmentsByArgRules(t *testing.T) {
	r := mustCompile(t, "ask", []string{"LANG", "KUBECONFIG"},
		"ls **", "env", "refuse:sudo **", "refuse:[arg .kube]", "refuse:[arg .ssh]")
	for _, tc := range []struct {
		command string
		outcome Outcome
		rule    string
	}{
		{"LANG=C ls /etc", Allow, "ls **"},
		{"env LANG=C ls", Allow, "ls **"},
		{"env time -p ls", Allow, "ls **"},
		{"time -p ls", Ask, RuleUnmatched},
		{"env", Allow, "env"},
		{"env LANG=C", Allow, "env"},
		{"env sudo reboot", Refuse, "sudo **"},
		{"LANG=C sudo reboot", Refuse, "sudo **"},
		{"KUBECONFIG=root/.kube/config ls", Refuse, "[arg .kube]"},
		{"env KUBECONFIG=root/.ssh/x", Refuse, "[arg .ssh]"},
		{"KUBECONFIG=/root/.kube/config ls", Ask, RuleUnmatched},
		{"LD_PRELOAD=/tmp/x.so ls", Ask, RuleUnmatched},
		{"time LANG=C ls", Ask, RuleUnmatched},
		{"env -i ls", Ask, RuleUnmatched},
		{"env -0", Allow, "env"},
		{"env -u LANG", Allow, "env"},
	} {
		if d := r.Decide(tc.command); d.Outcome != tc.outcome || d.Rule != tc.rule {
			t.Errorf("%q: got %v by %q, want %v by %q", tc.command, d.Outcome, d.Rule, tc.outcome, tc.rule)
		}
	}
}

func TestEnvNamesAreNamesOrAPrefixAndNoneThatChangesWhatRuns(t *testing.T) {
	for _, ok := range [][]string{
		nil, {"LANG"}, {"LC_*", "TZ", "COLUMNS"}, {"L_*"}, {"LD"}, {"LDX"}, {"PATHS"}, {"ENVIRONMENT"}, {"_X"}, {"A*"},
	} {
		if _, err := Compile(policy.SSHRoute{Env: ok}); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	tooMany := make([]string, maxEnv+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("V%d", i)
	}
	for _, tc := range []struct {
		env  []string
		want string
	}{
		{[]string{""}, `env[0] ""`},
		{[]string{"*"}, `env[0] "*"`},
		{[]string{"LANG", "1A"}, `env[1] "1A"`},
		{[]string{"A-B"}, "letters, digits and _"},
		{[]string{"LANG**"}, "letters, digits and _"},
		{[]string{"LA*NG"}, "letters, digits and _"},
		{[]string{"LANG="}, "letters, digits and _"},
		{[]string{"LANG", "LANG"}, `env[1] "LANG" is listed twice`},
		{[]string{"PATH"}, "names PATH"},
		{[]string{"LD_PRELOAD"}, "names LD_*"},
		{[]string{"LD_LIBRARY_PATH"}, "names LD_*"},
		{[]string{"LD_*"}, "names LD_*"},
		{[]string{"LD_X*"}, "names LD_*"},
		{[]string{"LD*"}, "names LD_*"},
		{[]string{"L*"}, "names LD_*"},
		{[]string{"P*"}, "names PATH"},
		{[]string{"DYLD_INSERT_LIBRARIES"}, "names DYLD_*"},
		{[]string{"GCONV_PATH"}, "names GCONV_PATH"},
		{[]string{"BASH_ENV"}, "names BASH_ENV"},
		{[]string{"BASH*"}, "names BASH_ENV"},
		{[]string{"ENV"}, "names ENV"},
		{[]string{"IFS"}, "names IFS"},
		{[]string{"SHELLOPTS"}, "names SHELLOPTS"},
		{[]string{"BASHOPTS"}, "names BASHOPTS"},
		{[]string{"LOCPATH"}, "names LOCPATH"},
		{[]string{"LO*"}, "names LOCPATH"},
		{[]string{"NLSPATH"}, "names NLSPATH"},
		{[]string{"NLS*"}, "names NLSPATH"},
		{[]string{"N*"}, "names NLSPATH"},
		{[]string{"GLIBC_TUNABLES"}, "names GLIBC_TUNABLES"},
		{[]string{"GLIBC_*"}, "names GLIBC_TUNABLES"},
		{tooMany, "more than 64"},
	} {
		_, err := Compile(policy.SSHRoute{Env: tc.env})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: got %v, want an error saying %q", tc.env, err, tc.want)
		}
	}
}

// What strip takes off is never itself what a rule is written for, so
// neither env with more words nor time first is a pattern.
func TestEnvIsOnlyAPatternAlone(t *testing.T) {
	if _, err := compileRule(policy.ExecRule{Command: "env"}); err != nil {
		t.Error(err)
	}
	for _, p := range []string{"env ls", "env **", "env *", "env -i **"} {
		if _, err := compileRule(policy.ExecRule{Command: p}); err == nil || !strings.Contains(err.Error(), "only ever alone") {
			t.Errorf("%q: got %v", p, err)
		}
	}
}

// The names a property's routes may list, and those they never do: none of
// these is LANG, LC_* or TZ.
var (
	listedNames   = []string{"LANG", "LC_ALL", "LC_TIME", "TZ"}
	unlistedNames = []string{"LD_PRELOAD", "PATH", "LANGUAGE", "LC", "BASH_ENV", "X", "TZX"}
)

// drawEnv draws a route's env names: some of LANG, LC_* and TZ.
func drawEnv(t *rapid.T) []string {
	var env []string
	for _, n := range []string{"LANG", "LC_*", "TZ"} {
		if rapid.Bool().Draw(t, "list "+n) {
			env = append(env, n)
		}
	}
	return env
}

// requote is a simple command lex read, written again: each quoted word
// single-quoted, and each plain one as it was, since quoting a plain word
// may change what it is -- an assignment, or a precommand.
func requote(ws []word) string {
	q := make([]string, len(ws))
	for i, w := range ws {
		q[i] = w.s
		if w.quoted {
			q[i] = "'" + w.s + "'"
		}
	}
	return strings.Join(q, " ")
}

// prefixOne puts prefix before the simple command at of command, which
// lex read as cmds, each word requoted: the same command, with prefix
// before that part alone.
func prefixOne(cmds [][]word, at int, prefix string) string {
	parts := make([]string, len(cmds))
	for i, c := range cmds {
		parts[i] = requote(c)
		if i == at {
			parts[i] = prefix + " " + parts[i]
		}
	}
	return strings.Join(parts, " && ")
}

// anUnlistedAssignmentNeverAdmits: whatever the rules and the names
// listed, a simple command that assigns a name not listed, before it or by
// env, is unreadable, so no rule admits the command it is in.
func anUnlistedAssignmentNeverAdmits(t *rapid.T) {
	env := drawEnv(t)
	unmatched := rapid.SampledFrom([]Outcome{Ask, Refuse}).Draw(t, "unmatched")
	r := &Rules{rules: drawRules(t), unmatched: unmatched, env: env}
	cmds, ok := lex(drawCommand(t))
	if !ok {
		t.Skip("unreadable")
	}
	name := rapid.SampledFrom(unlistedNames).Draw(t, "name")
	value := rapid.SampledFrom([]string{"", "C", "/tmp/x.so", "x"}).Draw(t, "value")
	var ws []string
	for _, n := range rapid.SliceOfN(rapid.SampledFrom(listedNames), 0, 2).Draw(t, "listed") {
		if r.listed(n) {
			ws = append(ws, n+"=C")
		}
	}
	ws = slices.Insert(ws, rapid.IntRange(0, len(ws)).Draw(t, "place"), name+"="+value)
	prefix := strings.Join(ws, " ")
	if rapid.Bool().Draw(t, "by env") {
		prefix = "env " + prefix
	}
	command := prefixOne(cmds, rapid.IntRange(0, len(cmds)-1).Draw(t, "part"), prefix)
	if d := r.Decide(command); d.Outcome == Allow || d.Rule != RuleUnmatched {
		t.Fatalf("%q under env %q is %v by %q", command, env, d.Outcome, d.Rule)
	}
}

func TestAnUnlistedAssignmentNeverAdmits(t *testing.T) {
	rapid.Check(t, anUnlistedAssignmentNeverAdmits)
}

func FuzzAnUnlistedAssignmentNeverAdmits(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(anUnlistedAssignmentNeverAdmits))
}

// aValueNamesNoFileOfItsOwn: whatever a listed name is assigned, before a
// command or by env, an assignment that is read names nothing but the
// system's own data -- a locale or zone a library looks up in its own
// directory -- and never a file the session chose: not one by itself, as
// glibc reads LC_ALL=/dir and musl TZ=/f, ./f and .f, nor TZ=:f, nor one
// that joined to a directory leaves it, nor a % that NLSPATH expands.
func aValueNamesNoFileOfItsOwn(t *rapid.T) {
	r := &Rules{rules: []rule{}, unmatched: Ask, env: []string{"LANG", "LC_*", "TZ"}}
	name := rapid.SampledFrom(listedNames).Draw(t, "name")
	value := stringOf([]byte("aZ09_-./:%=@"), 0, 10).Draw(t, "value")
	prefix := ""
	if rapid.Bool().Draw(t, "by env") {
		prefix = "env "
	}
	command := prefix + name + "=" + value + " ls"
	if !r.Readable(command) {
		return
	}
	const dir = "/usr/share/zoneinfo"
	switch {
	case value != "" && strings.ContainsRune("/.:", rune(value[0])):
		t.Fatalf("%q is read, and %q names a file by itself", command, value)
	case !strings.HasPrefix(path.Join(dir, value)+"/", dir+"/"):
		t.Fatalf("%q is read, and %q leaves the directory it is joined to", command, value)
	case strings.Contains(value, ".."):
		t.Fatalf("%q is read, and %q climbs a directory", command, value)
	case strings.Contains(value, "%"):
		t.Fatalf("%q is read, and %q holds a %% that NLSPATH expands", command, value)
	}
}

func TestAValueNamesNoFileOfItsOwn(t *testing.T) {
	rapid.Check(t, aValueNamesNoFileOfItsOwn)
}

func FuzzAValueNamesNoFileOfItsOwn(f *testing.F) {
	f.Fuzz(rapid.MakeFuzz(aValueNamesNoFileOfItsOwn))
}

// Taking off what strip takes off never decides a command more loosely
// than the command without it: with listed assignments, env, time and a
// precommand before any of its simple commands, a readable command is decided exactly
// as it was, when the values name nothing an arg rule refuses, and at least
// as strictly when they might. One strip cannot read is unmatched, as any
// unreadable command is: `time -rf` is no command a rule for `-rf` decides.
func TestStrippingNeverLoosens(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		env := drawEnv(t)
		unmatched := rapid.SampledFrom([]Outcome{Ask, Refuse}).Draw(t, "unmatched")
		r := &Rules{rules: drawRules(t), unmatched: unmatched, env: env}
		command := drawCommand(t)
		cmds, ok := lex(command)
		if !ok || !r.Readable(command) {
			t.Skip("unreadable")
		}
		before := r.Decide(command)
		inert := rapid.Bool().Draw(t, "inert")
		values := []string{"C", "UTC", "C.UTF-8"}
		if !inert {
			values = append(values, "/root/.ssh/x", "root/.ssh/x", "id_rsa", "k.pem", "/etc/shadow", "a")
		}
		var assigns []string
		for _, n := range rapid.SliceOfN(rapid.SampledFrom(listedNames), 0, 2).Draw(t, "names") {
			if r.listed(n) {
				assigns = append(assigns, n+"="+rapid.SampledFrom(values).Draw(t, "value"))
			}
		}
		a := strings.Join(assigns, " ")
		prefix := strings.TrimSpace(rapid.SampledFrom([]string{
			a, "env " + a, "time", "time -p", "time '-p'", "time env " + a, "env " + a + " time", "env " + a + " time -p", "env " + a + " time '-p'", "time time",
			"exec", "command", "builtin", "'command'", "exec env " + a, "command time -p", "exec " + a, "command exec", "time command", "env " + a + " exec", "command -v",
		}).Draw(t, "prefix"))
		if prefix == "" {
			t.Skip("no prefix")
		}
		joined := prefixOne(cmds, rapid.IntRange(0, len(cmds)-1).Draw(t, "part"), prefix)
		after := r.Decide(joined)
		switch {
		case !r.Readable(joined):
			if after.Outcome != unmatched || after.Rule != RuleUnmatched {
				t.Fatalf("%q, unreadable, is %v by %q", joined, after.Outcome, after.Rule)
			}
		case strictness(after.Outcome) < strictness(before.Outcome),
			inert && (after.Outcome != before.Outcome || after.Rule != before.Rule):
			t.Fatalf("%q is %v by %q, but %q is %v by %q", command, before.Outcome, before.Rule, joined, after.Outcome, after.Rule)
		}
	})
}
