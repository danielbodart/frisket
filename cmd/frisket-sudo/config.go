package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

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

	keys []ssh.PublicKey
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
    }
  },
  "$defs": {
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
