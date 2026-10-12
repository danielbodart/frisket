package sudo

import (
	"strings"
	"testing"

	"github.com/danielbodart/frisket/execrule"
)

func TestTheCatalogueCompilesAndEveryMatchAsksWithAReason(t *testing.T) {
	rules, err := Danger(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, unit := range []string{"frisket.service", "galley.service", "sshd.service", "nftables.service", "debug-shell.service"} {
		d := rules.DecideWords([]string{"systemctl", "status", unit})
		if d.Outcome != execrule.Ask || d.Rule == execrule.RuleUnmatched || d.Operation == nil || d.Operation.Summary == "" {
			t.Errorf("systemctl status %s: %+v", unit, d)
		}
	}
	if d := rules.DecideWords([]string{"systemctl", "restart", "foo"}); d.Rule != execrule.RuleUnmatched {
		t.Errorf("systemctl restart foo matched %q", d.Rule)
	}
}

func TestExtraRulesAddDangerBesideTheCatalogue(t *testing.T) {
	rules, err := Danger(map[string]Extra{
		"reboot **":    {Reason: "reboots this machine"},
		"systemctl **": {Args: map[string]string{"postgresql*": "touches the database"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		words  []string
		reason string
	}{
		{[]string{"reboot"}, "reboots this machine"},
		{[]string{"reboot", "now"}, "reboots this machine"},
		{[]string{"systemctl", "restart", "postgresql.service"}, "touches the database"},
		{[]string{"systemctl", "stop", "sshd.service"}, "touches a unit that guards this machine"},
	} {
		d := rules.DecideWords(tc.words)
		if d.Outcome != execrule.Ask || d.Operation == nil || d.Operation.Summary != tc.reason {
			t.Errorf("%q: %+v", tc.words, d)
		}
	}
	if d := rules.DecideWords([]string{"systemctl", "restart", "foo"}); d.Rule != execrule.RuleUnmatched {
		t.Errorf("systemctl restart foo matched %q", d.Rule)
	}
}

// An extra rule asks, so even one over the same command as the
// catalogue's leaves the catalogue's units danger.
func TestAnExtraRuleCannotTakeTheCataloguesDangerAway(t *testing.T) {
	rules, err := Danger(map[string]Extra{"systemctl status **": {Reason: "reads a unit"}})
	if err != nil {
		t.Fatal(err)
	}
	if d := rules.DecideWords([]string{"systemctl", "stop", "frisket.service"}); d.Outcome != execrule.Ask || d.Operation.Summary != "touches a unit that guards this machine" {
		t.Errorf("%+v", d)
	}
	if d := rules.DecideWords([]string{"systemctl", "status", "frisket.service"}); d.Outcome != execrule.Ask {
		t.Errorf("%+v", d)
	}
}

func TestABadExtraRuleIsRefused(t *testing.T) {
	for name, extra := range map[string]map[string]Extra{
		"empty pattern":       {"": {Reason: "x"}},
		"nothing":             {"reboot": {}},
		"empty reason":        {"systemctl **": {Args: map[string]string{"foo*": ""}}},
		"empty glob":          {"systemctl **": {Args: map[string]string{"": "x"}}},
		"double space":        {"reboot  now": {Reason: "x"}},
		"** not last":         {"** reboot": {Reason: "x"}},
		"the catalogue's own": {"systemctl **": {Args: map[string]string{"frisket*": "x"}}},
	} {
		if _, err := Danger(extra); err == nil || !strings.HasPrefix(err.Error(), "danger") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
