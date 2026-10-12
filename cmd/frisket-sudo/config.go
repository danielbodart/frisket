package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/danielbodart/frisket/projpolicy"
	"github.com/danielbodart/frisket/sudo"
	"golang.org/x/crypto/ssh"
)

const defaultConfig = "/etc/frisket-sudo/config.json"

// config is the gate's settings file, its keys named as the NixOS module's
// options are.
type config struct {
	ForUser    string                `json:"forUser"`
	RemoteKeys []string              `json:"remoteKeys"`
	Danger     map[string]sudo.Extra `json:"danger"`
	// Exec are the host's exec rules: a sudo one matches is allowed, asked
	// with no password, or refused, unless it is a danger or a warning.
	Exec map[string]sudo.Rule `json:"exec"`
	// Policy, when set, reads the signed policy of the project a sudo is
	// run in through the courier, its sudo.exec merged over Exec.
	Policy *policyConfig `json:"policy"`

	keys []ssh.PublicKey
}

type policyConfig struct {
	Courier        string `json:"courier"`
	AllowedSigners string `json:"allowedSigners"`
	FileName       string `json:"fileName"`
}

// loadConfig reads path strictly: an unknown or misspelt key, a second
// value, a remote key that does not parse or a danger rule that does not
// compile is an error, since each would be a setting that silently does
// not apply.
func loadConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: more than one JSON value", path)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *config) validate() error {
	if c.ForUser == "" {
		return errors.New("forUser is required")
	}
	c.keys = nil
	for i, line := range c.RemoteKeys {
		if strings.ContainsAny(line, "\r\n") {
			return fmt.Errorf("remoteKeys[%d]: more than one line", i)
		}
		k, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return fmt.Errorf("remoteKeys[%d]: %w", i, err)
		}
		if len(rest) > 0 {
			return fmt.Errorf("remoteKeys[%d]: more than one key", i)
		}
		c.keys = append(c.keys, k)
	}
	if _, err := sudo.Danger(c.Danger); err != nil {
		return err
	}
	if err := sudo.CheckExec(c.Exec); err != nil {
		return err
	}
	if p := c.Policy; p != nil {
		for _, k := range []string{"courier", "allowedSigners"} {
			path := map[string]string{"courier": p.Courier, "allowedSigners": p.AllowedSigners}[k]
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return fmt.Errorf("policy.%s: %q is not absolute and clean", k, path)
			}
		}
		switch f := p.FileName; {
		case f == "" || f == "." || f == ".." || strings.ContainsAny(f, "/\x00"):
			return fmt.Errorf("policy.fileName: %q is not a file name", f)
		case strings.HasSuffix(f, projpolicy.SigSuffix):
			return fmt.Errorf("policy.fileName: %q ends in %s, which names its signature", f, projpolicy.SigSuffix)
		}
	}
	return nil
}

// schema is the config file's JSON Schema.
const schema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "frisket-sudo config",
  "type": "object",
  "additionalProperties": false,
  "required": ["forUser"],
  "properties": {
    "forUser": {
      "description": "The gated user, and the user whose galley is asked.",
      "type": "string",
      "minLength": 1
    },
    "remoteKeys": {
      "description": "SSH public key lines, as authorized_keys has them, whose signature approves forUser's remote sudo with no tty. None is remote mode off.",
      "type": "array",
      "items": { "type": "string", "pattern": "^[^\\r\\n]+$" }
    },
    "danger": {
      "description": "Danger rules beside the built-in catalogue, keyed by an execrule command pattern: words, * for one, ** last for any number. Each asks, so none takes the catalogue's away.",
      "type": "object",
      "propertyNames": { "minLength": 1 },
      "additionalProperties": { "$ref": "#/$defs/danger" }
    },
    "exec": {
      "description": "The host's exec rules, keyed by an execrule command pattern of the resolved command: the program's absolute path, then words, * for one, ** last for any number, and optionally [arg GLOB] after it, an arg rule, which only asks or refuses. A literal pattern beats a pattern and a narrower one a wider one. A project's signed sudo.exec is merged over these. Never applied to a danger or a warning, a command not seen whole, one with a variable outside the allowlist, or a shell or env.",
      "type": "object",
      "propertyNames": { "pattern": "^/" },
      "additionalProperties": { "$ref": "#/$defs/rule" }
    },
    "policy": {
      "description": "A project's signed policy: read through the courier for the process that ran sudo, its sudo.exec merged over exec when it verifies.",
      "type": "object",
      "additionalProperties": false,
      "required": ["courier", "allowedSigners", "fileName"],
      "properties": {
        "courier": { "description": "The courier's socket.", "type": "string", "pattern": "^/" },
        "allowedSigners": { "description": "The allowed signers a policy must verify against.", "type": "string", "pattern": "^/" },
        "fileName": { "description": "A project's policy file's name.", "type": "string", "minLength": 1, "not": { "pattern": "(/|\\.sig$)" } }
      }
    }
  },
  "$defs": {
    "rule": {
      "type": "object",
      "additionalProperties": false,
      "required": ["answer"],
      "properties": {
        "runAs": {
          "description": "The user the command runs as; a sudo as any other is not this rule's. Default root.",
          "type": "string",
          "pattern": "^[a-z_][a-z0-9_-]*$"
        },
        "answer": {
          "description": "allow: run with no question and no password; ask: a plain Allow/Refuse question, no password; refuse: refused.",
          "enum": ["allow", "ask", "refuse"]
        }
      }
    },
    "danger": {
      "type": "object",
      "additionalProperties": false,
      "minProperties": 1,
      "properties": {
        "reason": {
          "description": "The danger line for any command the pattern matches.",
          "type": "string",
          "minLength": 1
        },
        "args": {
          "description": "The danger line for a command the pattern matches with an argument this glob matches: * is any run of characters but /.",
          "type": "object",
          "propertyNames": { "minLength": 1 },
          "additionalProperties": { "type": "string", "minLength": 1 }
        }
      }
    }
  }
}
`
