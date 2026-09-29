package docker

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/danielbodart/frisket/internal/dns"
)

// Address is the project's own loopback address, which everything it
// publishes is bound to: 127.b1.b2.b3 from the first three bytes of the
// SHA-256 of the slug, lower-cased. A b1 of 0 would be in 127.0.0.0/16, where
// 127.0.0.1 and 127.0.0.53 are, and 255.255.255 is the broadcast; either
// hashes the hash's own 64 hex digits again. chase and nix-config derive it
// the same way, and the three must agree byte
// for byte.
func Address(project string) netip.Addr {
	h := hexSum(lowerASCII(project))
	for {
		b, _ := hex.DecodeString(h[:6])
		if b[0] != 0 && !(b[0] == 255 && b[1] == 255 && b[2] == 255) {
			return netip.AddrFrom4([4]byte{127, b[0], b[1], b[2]})
		}
		h = hexSum(h)
	}
}

func hexSum(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// reservedJSON is the list of names no project's name may equal or fall
// under: frisket's own route hosts, docker.frisket.internal among them, and
// the cloud's metadata.google.internal. GCE's own per-VM names have four labels
// or more and no project's name can be one, so they need no entry. The list is
// part of the derivation and frisket owns it: the flake exports this same file
// as lib.docker.reserved, and chase and nix-config read it from there rather
// than keep a copy that could drift.
//
//go:embed reserved.json
var reservedJSON []byte

// reserved is reservedJSON, parsed once. A file that does not parse, or holds
// a name that could never be generated, stops the program rather than
// reserving less than it says: a list that silently came out empty would
// reserve nothing, and frisket would hand a project its own route host.
var reserved = mustParseReserved(reservedJSON)

func mustParseReserved(b []byte) []string {
	names, err := parseReserved(b)
	if err != nil {
		panic("docker/reserved.json: " + err.Error())
	}
	return names
}

// parseReserved holds each entry to the shape of a name Names could give or
// fall under: a valid, lower-case DNS name ending in .internal. The bare
// "internal" is not one, and would reserve every name there is.
func parseReserved(b []byte) ([]string, error) {
	var names []string
	if err := json.Unmarshal(b, &names); err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no names")
	}
	for _, n := range names {
		if !dns.ValidQueryName(n) || lowerASCII(n) != n || !strings.HasSuffix(n, ".internal") {
			return nil, fmt.Errorf("%q is not a lower-case DNS name under .internal", n)
		}
	}
	return names, nil
}

// projectRE is owner/repo as a route may name it: a GitHub owner, lower-case,
// and a repository name.
var projectRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9._-]{1,100}$`)

// ValidProject is whether a route may name a project: owner/repo, already
// lower-cased, and a repository that is a name rather than . or .., which no
// repository can be. frisket refuses a route whose project is not, and chase
// refuses to approve one, so a checkout that would name one is refused when
// it is approved rather than when its session fails to start.
func ValidProject(project string) bool {
	return projectRE.MatchString(project) && !strings.HasSuffix(project, "/.") && !strings.HasSuffix(project, "/..")
}

var ownerRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}$`)

// Names are the names the project's address is known by: the short
// `<label>.internal` and the long `<label>.<owner>.internal`, in that order.
// The label is the repo, lower-cased, with everything outside [a-z0-9-] made
// a '-' and the '-'s at either end trimmed; a label that is empty or longer
// than a DNS label's 63 bytes gives no names. A name that is, or is under, a
// reserved name is left out, so frisket/docker is known only as
// docker.internal. Neither name is unique -- two owners can share a repo's
// name, and bodar.ts and bodar-ts one label -- which is why a session answers
// only its own, and the host only those one project gives.
func Names(project string) []string {
	owner, repo, ok := strings.Cut(lowerASCII(project), "/")
	if !ok {
		return nil
	}
	label := strings.Trim(strings.Map(func(r rune) rune {
		if 'a' <= r && r <= 'z' || '0' <= r && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, repo), "-")
	if label == "" || len(label) > 63 {
		return nil
	}
	candidates := []string{label + ".internal"}
	if ownerRE.MatchString(owner) {
		candidates = append(candidates, label+"."+owner+".internal")
	}
	var names []string
	for _, n := range candidates {
		if !Reserved(n) {
			names = append(names, n)
		}
	}
	return names
}

// Reserved is whether a name is, or is under, one no project may be named by.
func Reserved(name string) bool {
	for _, r := range reserved {
		if name == r || strings.HasSuffix(name, "."+r) {
			return true
		}
	}
	return false
}

func lowerASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}
