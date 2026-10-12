// Package sudo holds frisket-sudo's danger catalogue: an Ask match is a
// danger command, and its operation's summary the reason line.
package sudo

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/danielbodart/frisket/execrule"
	"github.com/danielbodart/frisket/policy"
)

//go:embed danger.json
var dangerJSON []byte

// Extra is a danger rule the host adds to the built-in catalogue, keyed by
// its command pattern: the whole command, with Reason, and any argument
// matching a glob in Args, with that glob's reason. Every one asks, so the
// host can add danger but never take the catalogue's away.
type Extra struct {
	Reason string            `json:"reason,omitempty"`
	Args   map[string]string `json:"args,omitempty"`
}

// Danger is the built-in catalogue with extra's rules after it.
func Danger(extra map[string]Extra) (*execrule.Rules, error) {
	d := json.NewDecoder(bytes.NewReader(dangerJSON))
	d.DisallowUnknownFields()
	var rules []policy.ExecRule
	if err := d.Decode(&rules); err != nil {
		return nil, fmt.Errorf("danger.json: %w", err)
	}
	builtin := len(rules)
	for _, command := range slices.Sorted(maps.Keys(extra)) {
		e := extra[command]
		if command == "" {
			return nil, errors.New("danger: an empty command pattern")
		}
		if e.Reason == "" && len(e.Args) == 0 {
			return nil, fmt.Errorf("danger.%s: neither a reason nor args", command)
		}
		if e.Reason != "" {
			rules = append(rules, rule(command, "", e.Reason))
		}
		for _, arg := range slices.Sorted(maps.Keys(e.Args)) {
			if arg == "" || e.Args[arg] == "" {
				return nil, fmt.Errorf("danger.%s.args: an empty glob or reason", command)
			}
			rules = append(rules, rule(command, arg, e.Args[arg]))
		}
	}
	r, err := execrule.Compile(policy.SSHRoute{Exec: rules})
	if err != nil && len(rules) > builtin {
		return nil, fmt.Errorf("danger: %w", err)
	}
	return r, err
}

func rule(command, arg, reason string) policy.ExecRule {
	return policy.ExecRule{Command: command, Arg: arg, Ask: true,
		Operation: &policy.Operation{ID: "host-danger", Summary: reason}}
}
