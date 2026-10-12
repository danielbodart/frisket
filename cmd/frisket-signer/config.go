package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/danielbodart/frisket/internal/agentsrv"
)

const defaultConfig = "/etc/frisket-signer/config.json"

// config is the signer's settings file, its keys named as the NixOS module's
// options are.
type config struct {
	ForUser  string                   `json:"forUser"`
	Terminal agentsrv.Rule            `json:"terminal"`
	SSHSIG   map[string]agentsrv.Rule `json:"sshsig"`
	SSH      sshConfig                `json:"ssh"`
}

type sshConfig struct {
	// Hosts is keyed by a host's name as the known hosts file lists it.
	Hosts map[string]agentsrv.Rule `json:"hosts"`
}

// loadConfig reads path strictly: an unknown or misspelt key, a second
// value or a rule other than allow or ask is an error, since each would be
// a setting that silently does not apply.
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
	if err := checkRule(c.Terminal); err != nil {
		return fmt.Errorf("terminal: %w", err)
	}
	for ns, r := range c.SSHSIG {
		if ns == "" {
			return errors.New("sshsig: an empty namespace")
		}
		if err := checkRule(r); err != nil {
			return fmt.Errorf("sshsig.%s: %w", ns, err)
		}
	}
	for name, r := range c.SSH.Hosts {
		if name == "" || strings.ContainsAny(name, ", \t\r\n") {
			return fmt.Errorf("ssh.hosts: %q is not a name the known hosts file could list", name)
		}
		if err := checkRule(r); err != nil {
			return fmt.Errorf("ssh.hosts.%s: %w", name, err)
		}
	}
	return nil
}

func checkRule(r agentsrv.Rule) error {
	switch r {
	case agentsrv.Allow, agentsrv.Ask:
		return nil
	}
	return fmt.Errorf("%q is not allow or ask", string(r))
}

// schema is the config file's JSON Schema.
const schema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "frisket-signer config",
  "type": "object",
  "additionalProperties": false,
  "required": ["forUser", "terminal"],
  "properties": {
    "forUser": {
      "description": "The only user served, and whose galley is asked.",
      "type": "string",
      "minLength": 1
    },
    "terminal": {
      "description": "A real tab's bound, direct sign to a host in /etc/ssh/ssh_known_hosts.",
      "$ref": "#/$defs/rule"
    },
    "sshsig": {
      "description": "A direct SSHSIG sign in each namespace. An unlisted namespace is asked, Allow once.",
      "type": "object",
      "propertyNames": { "minLength": 1 },
      "additionalProperties": { "$ref": "#/$defs/rule" }
    },
    "ssh": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "hosts": {
          "description": "A bound, direct userauth from any process to a host key listed under this name in /etc/ssh/ssh_known_hosts. Never a forwarded sign.",
          "type": "object",
          "propertyNames": { "pattern": "^[^,\\s]+$" },
          "additionalProperties": { "$ref": "#/$defs/rule" }
        }
      }
    }
  },
  "$defs": {
    "rule": { "enum": ["allow", "ask"] }
  }
}
`
