package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultConfig = "/etc/frisket-policy/config.json"

// config is the courier's settings file, its keys named as the NixOS
// module's options are.
type config struct {
	// FileName is a project's policy file's name. frisket has no default:
	// what a project calls it is the launcher's choice.
	FileName string `json:"fileName"`
	// AllowedSigners is the file a written policy's signature must verify
	// against.
	AllowedSigners string `json:"allowedSigners"`
	// Peers maps each system unit allowed to call to the user it runs as.
	Peers map[string]string `json:"peers"`
}

// loadConfig reads path strictly: an unknown or misspelt key, a second
// value or a setting that cannot apply is an error.
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
	switch {
	case c.FileName == "":
		return errors.New("fileName is required")
	case c.FileName == "." || c.FileName == ".." || strings.ContainsAny(c.FileName, "/\x00"):
		return fmt.Errorf("fileName %q is not a file name", c.FileName)
	case strings.HasSuffix(c.FileName, ".sig"):
		return fmt.Errorf("fileName %q ends in .sig, which names its signature", c.FileName)
	}
	if c.AllowedSigners == "" {
		return errors.New("allowedSigners is required")
	}
	if !filepath.IsAbs(c.AllowedSigners) || filepath.Clean(c.AllowedSigners) != c.AllowedSigners {
		return fmt.Errorf("allowedSigners %q is not absolute and clean", c.AllowedSigners)
	}
	for unit, user := range c.Peers {
		if !strings.HasSuffix(unit, ".service") || len(unit) == len(".service") || strings.ContainsAny(unit, "/\x00 ") {
			return fmt.Errorf("peers: %q is not a system service's unit name", unit)
		}
		if user == "" {
			return fmt.Errorf("peers.%s: no user", unit)
		}
	}
	return nil
}

// schema is the config file's JSON Schema.
const schema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "frisket-policy config",
  "type": "object",
  "additionalProperties": false,
  "required": ["fileName", "allowedSigners"],
  "properties": {
    "fileName": {
      "description": "A project's policy file's name, found in the nearest directory from a process's working directory up to home. Its signature is beside it, with .sig added.",
      "type": "string",
      "pattern": "^[^/\\u0000]+$",
      "not": { "anyOf": [{ "enum": [".", ".."] }, { "pattern": "\\.sig$" }] }
    },
    "allowedSigners": {
      "description": "The allowed signers file a written policy's signature must verify against.",
      "type": "string",
      "pattern": "^/"
    },
    "peers": {
      "description": "The system units allowed to call, each to the user it runs as: a caller must be that user, in that unit's cgroup.",
      "type": "object",
      "propertyNames": { "pattern": "^[^/\\s]+\\.service$" },
      "additionalProperties": { "type": "string", "minLength": 1 }
    }
  }
}
`
