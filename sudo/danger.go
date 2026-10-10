// Package sudo holds frisket-sudo's danger catalogue: an Ask match is a
// danger command, and its operation's summary the reason line.
package sudo

import (
	"bytes"
	_ "embed"
	"encoding/json"

	"github.com/danielbodart/frisket/execrule"
	"github.com/danielbodart/frisket/policy"
)

//go:embed danger.json
var dangerJSON []byte

func Danger() (*execrule.Rules, error) {
	d := json.NewDecoder(bytes.NewReader(dangerJSON))
	d.DisallowUnknownFields()
	var rules []policy.ExecRule
	if err := d.Decode(&rules); err != nil {
		return nil, err
	}
	return execrule.Compile(policy.SSHRoute{Exec: rules})
}
