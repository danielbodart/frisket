// Package project is frisket's project address: the name and the loopback
// address every project -- a checkout, by its origin's slug, owner/repo --
// is known by on the machine. Its name is `<repo>.<owner>.internal` and its
// address 127.b1.b2.b3, from the SHA-256 of the slug, so that a project's
// dev servers, its containers' published ports and anything else of its own
// can be bound to an address no other project has, and reached by a name.
//
// Both are pure functions of the slug, and the name reads back as its slug
// (FromName), so nothing has to be registered or kept in step: a session's
// DNS answers a project's name with its address, the host's `frisket dns`
// answers any project's name with its, and a program that binds or forwards
// to a project's address -- chase, for a session's dev-server forwards and
// its Docker project's ports -- calls Address and Names here rather than
// deriving them again. The Docker route (package docker, and the route's
// relay) is one user of the address; it is not the address's owner.
//
// The names no project may take are reserved.json's, which the flake also
// exports as lib.project.reserved.
package project

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
// hashes the hash's own 64 hex digits again. This is the one derivation:
// frisket's session DNS, its relay and `frisket dns` call it, and so does
// any program that binds to a project's address, rather than keep a copy
// that could drift.
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
// as lib.project.reserved, for any Nix that needs it, rather than a copy that
// could drift.
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
		panic("project/reserved.json: " + err.Error())
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

// Valid is whether a slug names a project: owner/repo, already lower-cased,
// and a repository that is a name rather than . or .., which no repository
// can be. frisket refuses a Docker route whose project is not, so a program
// that launches sessions refuses one before it gets that far.
func Valid(project string) bool {
	return projectRE.MatchString(project) && !strings.HasSuffix(project, "/.") && !strings.HasSuffix(project, "/..")
}

var ownerRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}$`)

// labelRE is one label of a project's name: what glibc's resolver takes in
// an answer (res_hnok, which nss_dns holds every answer's owner name to),
// measured with glibc 2.42 -- letters, digits, '-' and '_' anywhere in a
// label, but for a '-' that starts the name, which is the repo's first byte
// here and checked in Names. RFC 1123's rule, with no '_' and no '-' at a
// label's ends, would refuse repos whose names resolve wherever they are
// used.
var labelRE = regexp.MustCompile(`^[a-z0-9_-]{1,63}$`)

// Names are the names the project's address is known by: one,
// `<repo>.<owner>.internal`, lower-cased and otherwise as the slug spells it,
// so bodar/bodar.ts is bodar.ts.bodar.internal and has four labels. Nothing
// is folded, so no two projects share a name, and FromName reads one back:
// an owner has no dots, so the label before .internal is the owner and
// everything before that the repo. A repo that does not make labels glibc
// resolves -- an empty one, as .github's first is, a label over 63 bytes, a
// '-' first -- gives no name, and neither does an owner whose name would
// be, or be under, a reserved one (frisket, google): nil, and the address
// is still the project's.
func Names(project string) []string {
	owner, repo, ok := strings.Cut(lowerASCII(project), "/")
	if !ok || !ownerRE.MatchString(owner) {
		return nil
	}
	if strings.HasPrefix(repo, "-") {
		return nil
	}
	for _, l := range strings.Split(repo, ".") {
		if !labelRE.MatchString(l) {
			return nil
		}
	}
	name := repo + "." + owner + ".internal"
	if Reserved(name) || !dns.ValidQueryName(name) {
		return nil
	}
	return []string{name}
}

// FromName is the project a name is, as Names gives it: the slug, and
// whether the name is one at all. A name is read normalised, lower-case and
// without a trailing dot, and is one only if it is exactly the name Names
// gives the slug it reads as -- so a reserved name, or a label no repo's
// name could give, is none, and frisket answers for no name it would not
// give a project.
func FromName(name string) (string, bool) {
	rest, ok := strings.CutSuffix(dns.Normalize(name), ".internal")
	if !ok {
		return "", false
	}
	i := strings.LastIndexByte(rest, '.')
	if i < 0 {
		return "", false
	}
	p := rest[i+1:] + "/" + rest[:i]
	if !Valid(p) {
		return "", false
	}
	if n := Names(p); len(n) != 1 || n[0] != dns.Normalize(name) {
		return "", false
	}
	return p, true
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
