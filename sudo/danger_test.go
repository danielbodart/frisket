package sudo

import (
	"testing"

	"github.com/danielbodart/frisket/execrule"
)

func TestTheCatalogueCompilesAndEveryMatchAsksWithAReason(t *testing.T) {
	rules, err := Danger()
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
