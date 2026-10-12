package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/danielbodart/frisket/internal/agentsrv"
	"github.com/danielbodart/frisket/projpolicy"
)

const defaultConfig = "/etc/frisket-signer/config.json"

// config is the signer's settings file, its keys named as the NixOS module's
// options are.
type config struct {
	ForUser  string                   `json:"forUser"`
	Terminal agentsrv.Rule            `json:"terminal"`
	SSHSIG   map[string]agentsrv.Rule `json:"sshsig"`
	SSH      sshConfig                `json:"ssh"`
	// Policy, when set, reads the asking process's project policy through
	// the courier, offers Always, and serves policy-sign.
	Policy *policyConfig `json:"policy"`
}

type policyConfig struct {
	Courier        string `json:"courier"`
	AllowedSigners string `json:"allowedSigners"`
	FileName       string `json:"fileName"`
}

type sshConfig struct {
	// Hosts is keyed by a host's name as the known hosts file lists it, or
	// a pattern of names: * alone a label, * within one any run of it, **
	// as the first label one or more.
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
		if strings.HasPrefix(ns, projpolicy.NamespacePrefix) {
			return fmt.Errorf("sshsig.%s: a %s namespace is never signed raw, whatever this says", ns, projpolicy.NamespacePrefix)
		}
		if err := checkRule(r); err != nil {
			return fmt.Errorf("sshsig.%s: %w", ns, err)
		}
	}
	for name, r := range c.SSH.Hosts {
		if err := agentsrv.CheckHostRule(name); err != nil {
			return fmt.Errorf("ssh.hosts: %w", err)
		}
		if err := checkRule(r); err != nil {
			return fmt.Errorf("ssh.hosts.%s: %w", name, err)
		}
	}
	if p := c.Policy; p != nil {
		for k, path := range map[string]string{"courier": p.Courier, "allowedSigners": p.AllowedSigners} {
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
      "description": "A direct SSHSIG sign in each namespace. An unlisted namespace is asked, Allow once. A frisket-policy namespace is refused whatever this says.",
      "type": "object",
      "propertyNames": { "minLength": 1, "not": { "pattern": "^frisket-policy" } },
      "additionalProperties": { "$ref": "#/$defs/rule" }
    },
    "ssh": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "hosts": {
          "description": "A bound, direct userauth from any process to a host key listed under this name in /etc/ssh/ssh_known_hosts, or under a name this pattern matches: * alone is one label, * within a label any run of it, ** as the first label one or more. A literal beats a pattern and a narrower pattern a wider one. Never a forwarded sign.",
          "type": "object",
          "propertyNames": { "pattern": "^[^.,\\s?!|][^,\\s?!]*$" },
          "additionalProperties": { "$ref": "#/$defs/rule" }
        }
      }
    },
    "policy": {
      "description": "A project's signed policy: read through the courier for the process that asks, Always offered, and policy-sign served.",
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
    "rule": { "enum": ["allow", "ask"] }
  }
}
`
