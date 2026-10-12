package galleyask

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/danielbodart/frisket/internal/peer"
	"github.com/danielbodart/galley/wire"
)

func TestSplitPutsEachTopLevelSegmentOnALineOfItsOwn(t *testing.T) {
	for _, c := range []struct {
		script string
		want   []string
	}{
		{"a && b || c | d; e", []string{"a", "&& b", "|| c", "| d;", "e"}},
		{"a\nb\n\nc", []string{"a", "b", "c"}},
		{"make 2>&1 |& tee log", []string{"make 2>&1", "|& tee log"}},
		{"pwd -P >| /tmp/cwd && x", []string{"pwd -P >| /tmp/cwd", "&& x"}},
		{"case x in a) y;; esac", []string{"case x in a) y;; esac"}},
		{"a &&", []string{"a", "&&"}},
		{"a &&\n  b", []string{"a", "&& b"}},
		{"a \\\n  && b", []string{"a", "&& b"}},
	} {
		if got := Split(c.script); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %q", c.script, got)
		}
	}
}

func TestSplitLeavesOperatorsInsideQuotesSubshellsAndComments(t *testing.T) {
	for _, c := range []struct {
		script string
		want   []string
	}{
		{`echo 'a && b; c | d' && e`, []string{`echo 'a && b; c | d'`, "&& e"}},
		{`echo "a && \"b || c\"" ; e`, []string{`echo "a && \"b || c\"";`, "e"}},
		{`echo a\&\&b && c`, []string{`echo a\&\&b`, "&& c"}},
		{"x=$(a && b | c) && d", []string{"x=$(a && b | c)", "&& d"}},
		{"(cd a; make) || e", []string{"(cd a; make)", "|| e"}},
		{"x=`a && b` ; d", []string{"x=`a && b`;", "d"}},
		{"a # b && c\nd", []string{"a # b && c", "d"}},
		{"grep -c a#b && c", []string{"grep -c a#b", "&& c"}},
	} {
		if got := Split(c.script); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %q", c.script, got)
		}
	}
}

func TestSplitCleansEachSegmentAndKeepsAQuotedNewline(t *testing.T) {
	got := Split("git commit -m 'one\ntwo' && echo \x1b[2J")
	want := []string{`git commit -m 'one\u000atwo'`, `&& echo \u001b[2J`}
	if !slices.Equal(got, want) {
		t.Errorf("got %q", got)
	}
}

func TestACommandThatFitsIsOneLineAsBefore(t *testing.T) {
	got := Command([]string{"bash", "-c", "cd x && make"}, Width)
	if !slices.Equal(got, []string{"bash -c cd x && make"}) {
		t.Errorf("got %q", got)
	}
}

func TestALongShellCommandPutsItsScriptsSegmentsOnLines(t *testing.T) {
	script := "source /home/dan/.claude/shell-snapshots/snapshot-bash-1760.sh 2>/dev/null || true && " +
		"eval 'cd /home/dan/Projects/frisket && go test ./...' < /dev/null && pwd -P >| /tmp/claude-ab12-cwd"
	got := Command([]string{"/bin/bash", "-c", "-l", script}, 72)
	want := []string{
		"/bin/bash -c -l",
		"    source /home/dan/.claude/shell-snapshots/snapshot-bash-1760.sh \\",
		"        2>/dev/null",
		"    || true",
		"    && eval 'cd /home/dan/Projects/frisket && go test ./...' < /dev/null",
		"    && pwd -P >| /tmp/claude-ab12-cwd",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s", strings.Join(got, "\n"))
	}
}

func TestTheScriptIsFoundAfterTheShellsOptions(t *testing.T) {
	for _, c := range []struct {
		argv []string
		want int
	}{
		{[]string{"bash", "-c", "x"}, 2},
		{[]string{"bash", "-c", "-l", "x"}, 3},
		{[]string{"/bin/sh", "-ec", "x", "name"}, 2},
		{[]string{"bash", "-o", "pipefail", "-c", "x"}, 4},
		{[]string{"bash", "--norc", "-c", "--", "x"}, 4},
		{[]string{"bash", "script.sh", "-c"}, 0},
		{[]string{"bash", "-l"}, 0},
		{[]string{"script", "-qefc", "x", "/dev/null"}, 2},
		{[]string{"script", "--command", "x"}, 2},
		{[]string{"nix", "develop", "-c", "x"}, 0},
	} {
		if got := scriptArg(c.argv); got != c.want {
			t.Errorf("%q: got %d", c.argv, got)
		}
	}
}

func TestALongCommandWithNoScriptIsWrappedWithBackslashes(t *testing.T) {
	argv := []string{"git", "commit", "-m", "Lay out a long command for reading, a segment a line, before wrapping it"}
	got := Command(argv, 40)
	want := []string{
		"git commit -m Lay out a long command \\",
		"    for reading, a segment a line, \\",
		"    before wrapping it",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s", strings.Join(got, "\n"))
	}
}

func TestWrapKeepsQuotesWholeWhereItCanAndAWordTooLongForALineWhole(t *testing.T) {
	got := Wrap(`eval 'cd /a && make' < /dev/null`, 23)
	want := []string{`eval 'cd /a && make' \`, `    < /dev/null`}
	if !slices.Equal(got, want) {
		t.Errorf("got %q", got)
	}
	long := "/home/dan/.claude/shell-snapshots/snapshot-bash-1760253112345-k3j9xq.sh"
	got = Wrap("source "+long+" 2>/dev/null", 40)
	want = []string{"source \\", "    " + long + " \\", "    2>/dev/null"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q", got)
	}
}

func TestAWrappersCommandIsLaidOutAsItsOwn(t *testing.T) {
	for _, c := range []struct {
		argv []string
		want int
	}{
		{[]string{"timeout", "1800", "script", "-qefc", "x"}, 2},
		{[]string{"timeout", "-k", "5", "--foreground", "60", "bash", "-c", "x"}, 5},
		{[]string{"nice", "-n", "10", "env", "-u", "X", "A=1", "B=2", "sh", "-c", "x"}, 8},
		{[]string{"nohup", "--", "bash"}, 2},
		{[]string{"timeout", "60"}, 0},
		{[]string{"bash", "-c", "x"}, 0},
	} {
		if got := wrapped(c.argv); got != c.want {
			t.Errorf("%q: got %d", c.argv, got)
		}
	}
	script := "cd /home/dan/Projects/frisket && go test ./internal/... 2>&1 | tail -40"
	got := Command([]string{"timeout", "600", "bash", "-c", script}, 40)
	want := []string{"timeout 600 bash -c", "    cd /home/dan/Projects/frisket", "    && go test ./internal/... 2>&1", "    | tail -40"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q", got)
	}
}

func TestClaudeCodesEvalIsLaidOutInsideItsQuotes(t *testing.T) {
	cmd := `cd /home/dan/Projects/nix-config && git commit -m '\''one && two'\'' | tail -5`
	script := "source /tmp/snapshot.sh 2>/dev/null || true && eval '" + cmd + "' \\< /dev/null && pwd -P >| /tmp/cwd"
	got := Command([]string{"/bin/bash", "-c", "-l", script}, 60)
	want := []string{
		"/bin/bash -c -l",
		"    source /tmp/snapshot.sh 2>/dev/null",
		"    || true",
		"    && eval '",
		"        cd /home/dan/Projects/nix-config",
		"        && git commit -m 'one && two'",
		"        | tail -5",
		`    ' \< /dev/null`,
		"    && pwd -P >| /tmp/cwd",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s", strings.Join(got, "\n"))
	}
	for _, seg := range []string{"eval 'a'$b", `eval 'a'"$b"`, "eval 'a", "eval 'a'`b`"} {
		if _, _, _, ok := evalScript(seg); ok {
			t.Errorf("%s is read as one script", seg)
		}
	}
	// Claude Code quotes a quote as '"'"'.
	_, body, rest, ok := evalScript(`eval 'echo '"'"'a && b'"'"' && c' < /dev/null`)
	if !ok || body != "echo 'a && b' && c" || rest != " < /dev/null" {
		t.Errorf("got %q %q %v", body, rest, ok)
	}
}

func TestSplitLeavesABraceGroupWhole(t *testing.T) {
	got := Split("a || true && { shopt -u extglob || setopt X; } 2>/dev/null || true")
	want := []string{"a", "|| true", "&& { shopt -u extglob || setopt X; } 2>/dev/null", "|| true"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q", got)
	}
	if got := Split("echo {a,b} && x"); !slices.Equal(got, []string{"echo {a,b}", "&& x"}) {
		t.Errorf("got %q", got)
	}
}

func TestEveryLineFitsTheWidth(t *testing.T) {
	script := strings.Repeat("echo 'a quoted string that runs on && on' && ", 6) + "true"
	for _, l := range Command([]string{"sh", "-c", script}, 50) {
		if utf8.RuneCountInString(l) > 50 {
			t.Errorf("%q is wider than 50", l)
		}
	}
}

func chainFixture(t *testing.T, name string) *peer.Requester {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "chains", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var links []peer.Link
	if err := json.Unmarshal(b, &links); err != nil {
		t.Fatal(err)
	}
	return peer.FromLinks(links)
}

// The fixtures are chains read from /proc under Claude Code: each stand-in
// (sudo, ssh, ssh-keygen) was a script that slept, run from the directory
// the fixtures leave out of the text; a sudo's chain starts at its parent.

func TestAWrappersRowFoldsTheCommandItRunsIntoTheRowBelow(t *testing.T) {
	c := Chain(chainFixture(t, "sudo-deep"))
	var procs []string
	for _, r := range c.Rows {
		procs = append(procs, r[1])
	}
	if len(procs) != 4 || procs[0] != "claude" || procs[1] != "timeout 1800" || procs[2] != "script -qefc … /dev/null" ||
		!strings.HasPrefix(procs[3], "bash -c\n    set -euo pipefail;\n    zig build") {
		t.Errorf("got\n%s", strings.Join(procs, "\n--\n"))
	}
	if n := strings.Count(strings.Join(procs, "\n"), "zig build"); n != 1 {
		t.Errorf("the script is shown %d times", n)
	}
	if !strings.HasPrefix(c.Summary, "claude ← set -euo pipefail; zig build") {
		t.Errorf("summary %q", c.Summary)
	}
}

func TestClaudeCodesBashToolShowsItsCommandInsideItsEval(t *testing.T) {
	c := Chain(chainFixture(t, "sudo-direct"))
	if len(c.Rows) != 2 || !strings.Contains(c.Rows[1][1], "\n    && eval '\n        git status --short >/dev/null\n"+
		"        && sudo nixos-rebuild switch --flake .#dan-desktop 2>&1\n        | tail -30\n    ' < /dev/null\n") {
		t.Errorf("got %q", c.Rows)
	}
	if c.Summary != "claude ← git status --short >/dev/null && sudo nixos-rebuild switch --flake .#dan-desktop 2>&1 | tail -30" {
		t.Errorf("summary %q", c.Summary)
	}
}

func TestASignersChainIsItsLinksAndItsSummaryTheLeaf(t *testing.T) {
	c := Chain(chainFixture(t, "signer-push"))
	want := [][]string{{"2953050", "claude"}, {"3037399", "git push origin trunk"}, {"3037401", "ssh git@github.com git-receive-pack 'danielbodart/galley.git'"}}
	if !reflect.DeepEqual(c.Rows, want) || c.Summary != "claude ← ssh git@github.com git-receive-pack 'danielbodart/galley.git'" {
		t.Errorf("got %q %q", c.Rows, c.Summary)
	}
	r := chainFixture(t, "signer-commit")
	c = Chain(r)
	want = [][]string{{"2953050", "claude"}, {"3037369", "git commit -S -m Show the process chain as a table under the \\\n    text"},
		{"3037370", "ssh-keygen -Y sign -n git -f /home/dan/.ssh/id_ecdsa.pub \\\n    /tmp/.git_signing_buffer_tmpyGAU8k"}}
	if !reflect.DeepEqual(c.Rows, want) || c.Summary != "claude ← git commit -S -m Show the process chain as a table under the text" {
		t.Errorf("got %q %q", c.Rows, c.Summary)
	}
	if r.Anchor.Comm != "ssh-keygen" || r.SessionRoot || r.Cut {
		t.Errorf("the decision's anchor is %s, session root %v, cut %v", r.Anchor.Comm, r.SessionRoot, r.Cut)
	}
	it := item("dan", Question{Title: "t", Chain: c})
	if it.Table == nil || it.Table.Summary != c.Summary || len(it.Table.Rows) != 3 || wire.Needs(it) != 4 {
		t.Errorf("item table %+v", it.Table)
	}
}

func TestFoldMatchesExactly(t *testing.T) {
	script := "make && sudo make install"
	for _, c := range []struct {
		argv, next, want []string
	}{
		{[]string{"timeout", "60", "script", "-qc", script, "/dev/null"}, []string{"script", "-qc", script, "/dev/null"}, []string{"timeout", "60"}},
		{[]string{"script", "-qc", script, "/dev/null"}, []string{"bash", "-c", script}, []string{"script", "-qc", "…", "/dev/null"}},
		{[]string{"env", "A=1", "make", "x", "--", "y"}, []string{"make", "x"}, []string{"env", "A=1", "…", "--", "y"}},
		{[]string{"script", "-qc", script + " ", "/dev/null"}, []string{"bash", "-c", script}, []string{"script", "-qc", script + " ", "/dev/null"}},
		{[]string{"timeout", "60", "make"}, []string{"/usr/bin/make"}, []string{"timeout", "60", "make"}},
		// A shell forked for a pipeline or a subshell shows its script once.
		{[]string{"bash", "-c", script}, []string{"bash", "-c", script}, []string{"bash", "-c", "…"}},
		{[]string{"bash", "-c", script}, []string{"bash", "-c", script + ";"}, []string{"bash", "-c", script}},
	} {
		if got := fold(c.argv, c.next); !slices.Equal(got, c.want) {
			t.Errorf("fold(%q, %q) = %q", c.argv, c.next, got)
		}
	}
}
