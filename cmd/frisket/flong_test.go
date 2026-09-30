package main

import (
	"strings"
	"testing"
)

func TestExpandPolicy(t *testing.T) {
	for _, c := range []struct {
		template, name, want string
	}{
		{"/run/user/1000/chase/{machine}/policy.json", "agent-strict-0a1b", "/run/user/1000/chase/agent-strict-0a1b/policy.json"},
		{"/srv/policies/{machine}.json", "m1", "/srv/policies/m1.json"},
		// No {machine}: the path itself, whatever the name.
		{"/etc/frisket/policies/strict.json", "m1", "/etc/frisket/policies/strict.json"},
	} {
		got, err := expandPolicy(c.template, c.name)
		if err != nil || got != c.want {
			t.Errorf("expandPolicy(%q, %q) = %q, %v; want %q", c.template, c.name, got, err, c.want)
		}
	}
}

func TestExpandPolicyRefuses(t *testing.T) {
	for _, c := range []struct {
		template, name, why string
	}{
		{"policies/{machine}.json", "m1", "absolute"},
		{"/p/{machine}/{machine}.json", "m1", "at most once"},
		{"/p/{workspace}.json", "m1", "brace"},
		{"/p/{machine}/{.json", "m1", "brace"},
		{"/p/}{machine}.json", "m1", "brace"},
		{"/p/{Machine}.json", "m1", "brace"},
		// The name must be a session's, so it is never a way out of the
		// directory the template names.
		{"/p/{machine}/policy.json", "../etc", "name"},
		{"/p/{machine}/policy.json", "a/b", "name"},
		{"/p/{machine}/policy.json", "", "name"},
		// And the result the clean, absolute path the daemon asks for.
		{"/p/../{machine}.json", "m1", "clean"},
		{"/p//{machine}.json", "m1", "clean"},
	} {
		got, err := expandPolicy(c.template, c.name)
		if err == nil {
			t.Errorf("expandPolicy(%q, %q) = %q; want a refusal", c.template, c.name, got)
			continue
		}
		if !strings.Contains(err.Error(), c.why) {
			t.Errorf("expandPolicy(%q, %q): %v; want it to say %q", c.template, c.name, err, c.why)
		}
	}
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestFlongEnvNamesEveryMissingVariable(t *testing.T) {
	_, err := flongEnv(env(map[string]string{"machine": "m1", "userns": ""}), flongSteer)
	if err == nil {
		t.Fatal("an environment with only $machine was taken")
	}
	for _, want := range []string{"$netns", "$userns", "$leader", "$workspace"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%v: does not name %s", err, want)
		}
	}
	if strings.Contains(err.Error(), "$machine") {
		t.Errorf("%v: names $machine, which is set", err)
	}
}

func TestFlongEnvReadsWhatItIsAsked(t *testing.T) {
	got, err := flongEnv(env(map[string]string{"machine": "m1", "netns": "/proc/self/fd/5", "other": "x"}), []string{"machine", "netns"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["machine"] != "m1" || got["netns"] != "/proc/self/fd/5" {
		t.Errorf("got %v", got)
	}
}

// setFlong gives the test flong's postStart environment.
func setFlong(t *testing.T) {
	t.Helper()
	t.Setenv("machine", "m1")
	t.Setenv("netns", "/proc/self/fd/5")
	t.Setenv("userns", "/proc/self/fd/6")
	t.Setenv("leader", "1234")
	t.Setenv("workspace", "/srv/work")
}

func wantErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("got %v; want an error saying %q", err, want)
	}
}

// Past every check -flong makes, steer and connect reach the steering file,
// which here does not exist: the error is that, and nothing before it.
func TestFlongReachesTheSteeringFile(t *testing.T) {
	setFlong(t)
	missing := t.TempDir() + "/steering.json"
	common := []string{"-flong", "-nsenter", "/bin/nsenter", "-steering", missing}
	// The launcher's arguments, after --, are never read as flags.
	launcher := []string{"--", "-x", "--help", "anything"}
	steer := append(append(append([]string{}, common...), "-roots", "/etc/ssl/certs/ca-bundle.crt",
		"-policy", "/run/user/1000/chase/{machine}/policy.json"), launcher...)
	wantErr(t, runSteer(steer), missing)
	wantErr(t, runConnect(append(append([]string{}, common...), launcher...)), missing)
}

// What each step does with flong's environment: every variable where it
// belongs, so two swapped would fail here rather than only in a VM.
func TestFlongPutsTheEnvironmentWhereItBelongs(t *testing.T) {
	flongEnv := env(map[string]string{
		"machine": "agent-strict-0a1b", "netns": "/proc/self/fd/5", "userns": "/proc/self/fd/6",
		"leader": "1234", "workspace": "/srv/work",
	})
	launcher := []string{"--", "agent-strict", "-x"}

	st, err := parseSteer(append([]string{"-flong", "-control", "/c", "-nsenter", "/bin/nsenter", "-nft", "/bin/nft",
		"-roots", "/r", "-steering", "/s", "-policy", "/run/user/1000/chase/{machine}/policy.json", "-param", "k=v"}, launcher...), flongEnv)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{
		{st.session.Name, "agent-strict-0a1b"},
		{st.session.Policy, "/run/user/1000/chase/agent-strict-0a1b/policy.json"},
		{st.netns, "/proc/self/fd/5"},
		{st.s.Helper.Userns, "/proc/self/fd/6"},
		{st.session.Mntns, "/proc/1234/ns/mnt"},
		{st.session.Params["workspace"], "/srv/work"},
		{st.session.Params["k"], "v"},
		{st.session.Roots, "/r"},
		{st.file, "/s"},
		{st.s.Control, "/c"},
		{st.s.Nft, "/bin/nft"},
		{st.s.Helper.Nsenter, "/bin/nsenter"},
	} {
		if c[0] != c[1] {
			t.Errorf("steer: got %q; want %q", c[0], c[1])
		}
	}
	if len(st.session.Params) != 2 {
		t.Errorf("steer: params %v; want workspace and k alone", st.session.Params)
	}

	co, err := parseConnect(append([]string{"-flong", "-nsenter", "/bin/nsenter", "-steering", "/s"}, launcher...), flongEnv)
	if err != nil {
		t.Fatal(err)
	}
	if co.name != "agent-strict-0a1b" || co.netns != "/proc/self/fd/5" || co.s.Helper.Userns != "/proc/self/fd/6" || co.file != "/s" {
		t.Errorf("connect: got name %q, netns %q, userns %q, steering %q", co.name, co.netns, co.s.Helper.Userns, co.file)
	}

	cl, name, err := parseClose([]string{"-flong", "-control", "/c", "--"}, flongEnv)
	if err != nil {
		t.Fatal(err)
	}
	if name != "agent-strict-0a1b" || cl.Control != "/c" {
		t.Errorf("close: got name %q, control %q", name, cl.Control)
	}
}

// $leader names a /proc entry, so it must be a pid and nothing else.
func TestFlongLeaderMustBeAPid(t *testing.T) {
	for _, leader := range []string{"self", "1/../self", "0", "-1", "+5", "01234", "12 ", "thread-self"} {
		e := env(map[string]string{"machine": "m1", "netns": "/n", "userns": "/u", "leader": leader, "workspace": "/w"})
		_, err := parseSteer([]string{"-flong", "-nsenter", "/bin/nsenter", "-roots", "/r", "-steering", "/s", "-policy", "/p"}, e)
		wantErr(t, err, "is not a pid")
	}
}

// A word before the "--" ends the flags there, and would drop every flag
// after it: with -flong as without, it is refused.
func TestFlongRefusesAStrayWordBeforeTheLaunchersArguments(t *testing.T) {
	setFlong(t)
	wantErr(t, runSteer([]string{"-flong", "-nsenter", "/bin/nsenter", "-policy", "/p", "stray", "-roots", "/r", "-steering", "/s", "--", "x"}),
		`unexpected argument "stray"`)
	wantErr(t, runConnect([]string{"-flong", "-nsenter", "/bin/nsenter", "stray", "-steering", "/s"}), `unexpected argument "stray"`)
	wantErr(t, runClose([]string{"-flong", "stray"}), `unexpected argument "stray"`)
}

func TestFlongMissingVariablesFail(t *testing.T) {
	setFlong(t)
	t.Setenv("leader", "")
	t.Setenv("workspace", "")
	err := runSteer([]string{"-flong", "-nsenter", "/bin/nsenter", "-roots", "/r", "-steering", "/s", "-policy", "/p"})
	wantErr(t, err, "$leader, $workspace")

	t.Setenv("machine", "")
	wantErr(t, runClose([]string{"-flong"}), "$machine")
	wantErr(t, runConnect([]string{"-flong", "-nsenter", "/bin/nsenter", "-steering", "/s"}), "$machine")
}

func TestFlongRefusesTheFlagsItReplaces(t *testing.T) {
	setFlong(t)
	base := []string{"-flong", "-nsenter", "/bin/nsenter", "-roots", "/r", "-steering", "/s", "-policy", "/p"}
	for _, extra := range [][]string{
		{"-name", "m2"}, {"-netns", "/n"}, {"-mntns", "/m"}, {"-userns", "/u"},
	} {
		wantErr(t, runSteer(append(append([]string{}, base...), extra...)), "do not give "+extra[0])
	}
	wantErr(t, runSteer(append(append([]string{}, base...), "-param", "workspace=/elsewhere")), "-param workspace")
	wantErr(t, runConnect([]string{"-flong", "-netns", "/n", "-steering", "/s"}), "do not give -netns")
	wantErr(t, runClose([]string{"-flong", "-name", "m2"}), "do not give -name")
}

// Without -flong nothing is read from the environment, and an argument after
// the flags is a mistake.
func TestWithoutFlong(t *testing.T) {
	setFlong(t)
	wantErr(t, runClose(nil), "-name is required")
	wantErr(t, runConnect([]string{"-steering", "/s"}), "are all required")
	wantErr(t, runSteer([]string{"-roots", "/r", "-steering", "/s", "-policy", "/p"}), "are all required")
	wantErr(t, runClose([]string{"-name", "m1", "extra"}), `unexpected argument "extra"`)
	wantErr(t, runConnect([]string{"-netns", "/n", "-steering", "/s", "-name", "m1", "--", "x"}), `unexpected argument "x"`)
}
