package sudo

import (
	"strings"
	"testing"
)

const bin = "/run/current-system/sw/bin/"

func decide(t *testing.T, rules map[string]Rule, runAs, command string) (Match, bool) {
	t.Helper()
	e, err := CompileExec(rules)
	if err != nil {
		t.Fatal(err)
	}
	return e.Decide(runAs, strings.Split(command, " "))
}

func TestALiteralRuleBeatsAPatternAndANarrowerPatternAWiderOne(t *testing.T) {
	rules := map[string]Rule{
		bin + "systemctl **":                  {Answer: Ask},
		bin + "systemctl status **":           {Answer: Allow},
		bin + "systemctl status sshd.service": {Answer: Refuse},
		bin + "systemctl * foo.service":       {RunAs: "root", Answer: Allow},
		bin + "journalctl **":                 {Answer: Allow},
		bin + "journalctl ** [arg --vacuum*]": {Answer: Ask},
		bin + "journalctl ** [arg --flush]":   {Answer: Refuse},
		bin + "nft list ruleset":              {Answer: Allow},
	}
	for command, want := range map[string]string{
		bin + "systemctl restart x.service":   "ask " + bin + "systemctl **",
		bin + "systemctl status x.service":    "allow " + bin + "systemctl status **",
		bin + "systemctl status sshd.service": "refuse " + bin + "systemctl status sshd.service",
		bin + "systemctl restart foo.service": "allow " + bin + "systemctl * foo.service",
		bin + "journalctl -u foo":             "allow " + bin + "journalctl **",
		bin + "journalctl --vacuum-time=1s":   "ask " + bin + "journalctl ** [arg --vacuum*]",
		bin + "journalctl -u x --flush":       "refuse " + bin + "journalctl ** [arg --flush]",
		bin + "nft list ruleset":              "allow " + bin + "nft list ruleset",
	} {
		m, ok := decide(t, rules, "root", command)
		if got := m.Answer + " " + m.Pattern; !ok || got != want {
			t.Errorf("%s: %v %q, want %q", command, ok, got, want)
		}
	}
	for _, command := range []string{
		bin + "nft list ruleset extra", bin + "nft flush ruleset", bin + "id", "systemctl status x", bin + "journalctl2",
	} {
		if m, ok := decide(t, rules, "root", command); ok {
			t.Errorf("%s matched %+v", command, m)
		}
	}
}

// An arg rule only tightens, and unmatched is the gate's password, which
// is stricter than a question: an arg rule that asks leaves a command no
// command rule matches unmatched, and one that refuses refuses it.
func TestAnArgRuleNeverLoosensAnUnmatchedCommand(t *testing.T) {
	rules := map[string]Rule{
		bin + "dmesg ** [arg --clear]": {Answer: Ask},
		bin + "dmesg ** [arg -C]":      {Answer: Refuse},
	}
	if m, ok := decide(t, rules, "root", bin+"dmesg --clear"); ok {
		t.Errorf("an asking arg rule decided an unmatched command: %+v", m)
	}
	if m, ok := decide(t, rules, "root", bin+"dmesg -C"); !ok || m.Answer != Refuse {
		t.Errorf("a refusing arg rule: %v %+v", ok, m)
	}
}

func TestARuleForAnotherUserNeverMatches(t *testing.T) {
	rules := map[string]Rule{
		bin + "id **":  {Answer: Allow},
		bin + "lpq **": {RunAs: "lp", Answer: Allow},
	}
	if _, ok := decide(t, rules, "root", bin+"id -u"); !ok {
		t.Error("runAs default is not root")
	}
	for _, tc := range [][2]string{{"lp", bin + "id -u"}, {"root", bin + "lpq -a"}, {"", bin + "id -u"}, {"bob", bin + "lpq"}} {
		if m, ok := decide(t, rules, tc[0], tc[1]); ok {
			t.Errorf("%s as %q matched %+v", tc[1], tc[0], m)
		}
	}
	if _, ok := decide(t, rules, "lp", bin+"lpq -a"); !ok {
		t.Error("lp's rule did not match as lp")
	}
	var none *ExecRules
	if _, ok := none.Decide("root", []string{bin + "id"}); ok {
		t.Error("nil rules matched")
	}
}

func TestOnlyRefusalsCompile(t *testing.T) {
	if m, ok := decide(t, map[string]Rule{bin + "reboot **": {Answer: Refuse}}, "root", bin+"reboot"); !ok || m.Answer != Refuse {
		t.Errorf("%v %+v", ok, m)
	}
	if m, ok := decide(t, map[string]Rule{bin + "reboot **": {Answer: Refuse}}, "root", never); ok {
		t.Errorf("the rule that never matches matched: %+v", m)
	}
}

func TestABadExecRuleIsRefused(t *testing.T) {
	for name, rules := range map[string]map[string]Rule{
		"no answer":           {bin + "id": {}},
		"bad answer":          {bin + "id": {Answer: "yes"}},
		"bare name":           {"systemctl **": {Answer: Allow}},
		"pattern first":       {"** id": {Answer: Allow}},
		"star first":          {"* id": {Answer: Allow}},
		"unclean":             {"/run/current-system/sw/bin/../bin/id": {Answer: Allow}},
		"arg alone":           {"[arg .ssh]": {Answer: Refuse}},
		"arg rule allows":     {bin + "cat ** [arg shadow]": {Answer: Allow}},
		"bad runAs":           {bin + "id": {RunAs: "Root!", Answer: Allow}},
		"double space":        {bin + "id  -u": {Answer: Allow}},
		"** not last":         {bin + "id ** -u": {Answer: Allow}},
		"empty":               {"": {Answer: Allow}},
		"unreadable glob":     {bin + "cat ** [arg *]": {Answer: Refuse}},
		"quoted pattern word": {bin + "echo 'x'": {Answer: Allow}},
		"glob in a word":      {bin + "systemctl restart postgresql*": {Answer: Allow}},
	} {
		if err := CheckExec(rules); err == nil || !strings.HasPrefix(err.Error(), "exec") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := CheckExec(nil); err != nil {
		t.Errorf("no rules: %v", err)
	}
}
