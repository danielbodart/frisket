package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/danielbodart/frisket/internal/control"
)

const defaultConfig = "/etc/frisket/config.json"

// config is the daemon's settings file, its keys named as the NixOS
// module's options are. The policies are not in it: each is a document of
// its own, which a session names.
type config struct {
	// DNS is where the names a session is allowed are resolved. Empty is
	// whatever the host's /etc/resolv.conf names, followed as it changes.
	DNS []string `json:"dns"`
	// LogLevel is debug, info, warn or error; empty is info.
	LogLevel string `json:"logLevel"`
	// ControlSocket is made when systemd has not passed one.
	ControlSocket string `json:"controlSocket"`
	// PolicyRoots are the directories a policy document may be read from.
	// None is anywhere.
	PolicyRoots []string `json:"policyRoots"`
	// Asker is the program a question is put to. None refuses each.
	Asker           string `json:"asker"`
	AskerConcurrent int    `json:"askerConcurrent"`
	AskerPerSession int    `json:"askerPerSession"`
	// RecordDir is where a recording session's lines may be appended. None
	// refuses a document with a sink.
	RecordDir      string           `json:"recordDir"`
	MaxConnections int              `json:"maxConnections"`
	GitSigning     gitSigningConfig `json:"gitSigning"`
}

type gitSigningConfig struct {
	// Agent is the SSH agent the git signing sockets pass signs on to.
	Agent string `json:"agent"`
	// Policies are the policies whose git signing socket is served.
	Policies []string `json:"policies"`
}

// loadConfig reads path strictly: an unknown or misspelt key, a second
// value or a value out of range is an error, since each would be a setting
// that silently does not apply. A field left out takes its default.
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

func absClean(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p }

func (c *config) validate() error {
	switch c.LogLevel {
	case "":
		c.LogLevel = "info"
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logLevel %q: debug, info, warn or error", c.LogLevel)
	}
	if c.ControlSocket == "" {
		c.ControlSocket = control.DefaultPath
	} else if !absClean(c.ControlSocket) {
		return fmt.Errorf("controlSocket %q is not an absolute, clean path", c.ControlSocket)
	}
	for _, r := range c.PolicyRoots {
		if !absClean(r) {
			return fmt.Errorf("policyRoots: %q is not an absolute, clean path", r)
		}
	}
	if c.Asker != "" && !filepath.IsAbs(c.Asker) {
		return fmt.Errorf("asker %q is not an absolute path", c.Asker)
	}
	if c.AskerConcurrent == 0 {
		c.AskerConcurrent = 1
	}
	if c.AskerPerSession == 0 {
		c.AskerPerSession = 1
	}
	if c.AskerConcurrent < 1 || c.AskerPerSession < 1 {
		return errors.New("askerConcurrent and askerPerSession are at least 1")
	}
	if c.RecordDir != "" && !absClean(c.RecordDir) {
		return fmt.Errorf("recordDir %q is not an absolute, clean path", c.RecordDir)
	}
	if c.MaxConnections < 0 {
		return fmt.Errorf("maxConnections %d: 0 is the default, and none is fewer", c.MaxConnections)
	}
	seen := map[string]bool{}
	for _, name := range c.GitSigning.Policies {
		if err := checkPolicyName(name); err != nil {
			return fmt.Errorf("gitSigning.policies: %w", err)
		}
		if seen[name] {
			return fmt.Errorf("gitSigning.policies: %q is listed twice", name)
		}
		seen[name] = true
	}
	if len(c.GitSigning.Policies) > 0 && !filepath.IsAbs(c.GitSigning.Agent) {
		return fmt.Errorf("gitSigning.policies needs gitSigning.agent, by absolute path; got %q", c.GitSigning.Agent)
	}
	return nil
}

// schema is the config file's JSON Schema.
const schema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "frisket config",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "dns": {
      "description": "Where the names a session is allowed are resolved: ip or ip:port. None is whatever /etc/resolv.conf names, followed as it changes.",
      "type": "array",
      "items": { "type": "string", "minLength": 1 }
    },
    "logLevel": {
      "description": "debug adds a line per intercepted request with its headers, credentials described and never shown. None is info.",
      "enum": ["debug", "info", "warn", "error"]
    },
    "controlSocket": {
      "description": "The control socket made when systemd has not passed one. None is /run/frisket/control.sock.",
      "$ref": "#/$defs/path"
    },
    "policyRoots": {
      "description": "Directories a session's policy document may be read from. None is anywhere.",
      "type": "array",
      "items": { "$ref": "#/$defs/path" }
    },
    "asker": {
      "description": "The program a request a route asks about is put to. None refuses each.",
      "$ref": "#/$defs/path"
    },
    "askerConcurrent": {
      "description": "Questions open at once, daemon-wide. None is 1.",
      "type": "integer",
      "minimum": 1
    },
    "askerPerSession": {
      "description": "Questions one session may have queued or open. None is 1.",
      "type": "integer",
      "minimum": 1
    },
    "recordDir": {
      "description": "The directory a recording session's sink may be in. None refuses a document with a sink.",
      "$ref": "#/$defs/path"
    },
    "maxConnections": {
      "description": "Concurrent connections per session; 0 is the built-in default.",
      "type": "integer",
      "minimum": 0
    },
    "gitSigning": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "agent": {
          "description": "The SSH agent the git signing sockets pass signs on to. Required with policies.",
          "$ref": "#/$defs/path"
        },
        "policies": {
          "description": "The policies whose git signing socket is served at /run/frisket-sign/<policy>/agent.",
          "type": "array",
          "uniqueItems": true,
          "items": { "type": "string", "pattern": "^[A-Za-z0-9_][A-Za-z0-9_.-]*$" }
        }
      }
    }
  },
  "$defs": {
    "path": { "type": "string", "pattern": "^/" }
  }
}
`
