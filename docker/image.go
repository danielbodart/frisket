package docker

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var (
	digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// hex64RE is an image's ID without its algorithm, in any case.
	hex64RE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	// shortHexRE is what the daemon may read as a prefix of an image's ID.
	shortHexRE = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// registries are the only registries a route may name an image from, by
// the exact lower-case host moby would read from a reference's first
// component. The daemon runs in the host's network namespace and treats a
// loopback registry as insecure, so a registry judged by its spelling alone
// would let a listed image send a pull to the host's own loopback: by a name
// that resolves there (localtest.me, anything.nip.io, a host in /etc/hosts
// such as a project's .internal name), or by an address spelt as inet_aton
// reads it (127.1, 0177.0.0.1). A fixed list of public registries, whose
// names no project controls, leaves nothing to spell.
var registries = [...]string{
	"docker.io", "registry-1.docker.io", "ghcr.io", "quay.io", "gcr.io",
	"mcr.microsoft.com", "public.ecr.aws", "registry.k8s.io",
}

// registrySuffixes are registries a route may name by any one label under a
// public suffix no project controls: gcr.io's regions (eu.gcr.io) and
// Artifact Registry's (europe-west2-docker.pkg.dev).
var registrySuffixes = [...]string{".gcr.io", "-docker.pkg.dev"}

// ValidImage is whether a route may list an image: a reference with a tag or
// a digest, so that it names one image and not whatever `latest` is today,
// and pulled from docker.io or a registry on a fixed list of public ones, so
// that nothing listed can pull from the host's own loopback (see registries).
func ValidImage(ref string) error {
	if ref == "" {
		return errors.New("an empty image")
	}
	if strings.ContainsFunc(ref, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return errors.New("an image with a space or a control character in it")
	}
	parts := strings.Split(ref, "/")
	for _, p := range parts {
		if p == "" {
			return errors.New("an image with an empty component")
		}
	}
	// The daemon takes sha256:<hex>, and a bare 64-hex string, for an
	// image's ID, and sha256:<prefix> for any image whose ID begins so: it
	// would run whatever local image has that ID, made or loaded by anyone,
	// and not one pulled from a registry by name. A component named either
	// way is refused wherever it stands, rather than judged by where the
	// daemon would read it as an ID.
	for _, p := range parts {
		name, _, _ := strings.Cut(p, "@")
		name, _, _ = strings.Cut(name, ":")
		if strings.EqualFold(name, "sha256") || hex64RE.MatchString(name) {
			return errors.New("an image's ID, not its name")
		}
	}
	if len(parts) > 1 && isDomain(parts[0]) && !knownRegistry(parts[0]) {
		return fmt.Errorf("an image from registry %q, which is not docker.io or one of %s", parts[0], strings.Join(registries[:], ", "))
	}
	if !Tagged(ref) {
		return errors.New("an image with no :tag or @sha256: digest")
	}
	last := parts[len(parts)-1]
	if name, digest, ok := strings.Cut(last, "@"); ok {
		if !digestRE.MatchString(digest) {
			return errors.New("an image whose digest is not sha256:<64 hex>")
		}
		last = name
	}
	if name, tag, ok := strings.Cut(last, ":"); ok && (name == "" || tag == "") {
		return errors.New("an image with an empty name or tag")
	}
	return nil
}

// isDomain is whether moby reads a reference's first component as a
// registry rather than a docker.io namespace: it holds a '.' or a ':', is
// localhost, or has an upper-case letter (distribution's splitDockerDomain).
func isDomain(first string) bool {
	return strings.ContainsAny(first, ".:") || first == "localhost" || strings.ToLower(first) != first
}

// knownRegistry is whether a registry, spelt exactly as moby would dial it,
// is one a route may pull from. An upper-case letter, a trailing dot or a
// port is a different spelling, and is refused rather than normalised.
func knownRegistry(host string) bool {
	for _, r := range registries {
		if host == r {
			return true
		}
	}
	for _, s := range registrySuffixes {
		label, ok := strings.CutSuffix(host, s)
		if ok && label != "" && dnsLabel(label) {
			return true
		}
	}
	return false
}

// dnsLabel is whether s is one lower-case DNS label, with no dot in it.
func dnsLabel(s string) bool {
	if len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Tagged is whether a reference already says which of a repository's images
// it is: a :tag or an @digest after its last '/'. A ':' before that is a
// registry's port, not a tag.
func Tagged(ref string) bool {
	last := ref[strings.LastIndex(ref, "/")+1:]
	return strings.ContainsAny(last, ":@")
}

// ValidBuild is whether a route may list what a project builds: a
// repository, every tag and digest of which is the project's, or a
// namespace, ending in '/', every repository under which is. It names no
// tag, digest or ID, and no registry is refused, since a build is pulled
// from none: an image a project built is on the daemon already, and one
// that is not is never pulled by its build's name.
func ValidBuild(build string) error {
	if build == "" {
		return errors.New("an empty build")
	}
	if strings.ContainsFunc(build, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return errors.New("a build with a space or a control character in it")
	}
	parts := strings.Split(strings.TrimSuffix(build, "/"), "/")
	for i, p := range parts {
		if p == "" {
			return errors.New("a build with an empty component")
		}
		if strings.EqualFold(p, "sha256") || hex64RE.MatchString(p) {
			return errors.New("a build named by an image's ID")
		}
		// A registry's port is the one ':' a repository may hold.
		if strings.Contains(p, "@") || i > 0 && strings.Contains(p, ":") {
			return errors.New("a build with a tag or digest: name its repository, or a namespace ending in /")
		}
	}
	return nil
}

// Built is whether ref, an image as a client sends it, is in a repository
// one of builds names, or under a namespace one of them is: its
// repository, without its :tag or @digest, is a build exactly or begins
// with a namespace. It is false for anything ValidImage refuses as an ID.
func Built(ref string, builds []string) bool {
	if ref == "" || len(builds) == 0 {
		return false
	}
	repo := ref
	last := strings.LastIndex(repo, "/") + 1
	if at := strings.IndexByte(repo[last:], '@'); at >= 0 {
		repo = repo[:last+at]
	}
	if colon := strings.IndexByte(repo[last:], ':'); colon >= 0 {
		repo = repo[:last+colon]
	}
	for _, p := range strings.Split(repo, "/") {
		if p == "" || strings.EqualFold(p, "sha256") || hex64RE.MatchString(p) {
			return false
		}
	}
	// An untagged name of hex alone the daemon also tries as a prefix of
	// any image's ID, when no image has that name.
	if repo == ref && shortHexRE.MatchString(ref) {
		return false
	}
	for _, b := range builds {
		if repo == b || strings.HasSuffix(b, "/") && strings.HasPrefix(repo, b) {
			return true
		}
	}
	return false
}
