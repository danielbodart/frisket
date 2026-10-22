package docker

import "testing"

// An image is listed only from docker.io or a known public registry, so no
// spelling of a registry, and no name that resolves to one, can send the
// daemon's pull to the host's own loopback; and only by a name, never by an
// ID or an ID's prefix, which the daemon would answer with whatever local
// image has it.
func TestAnImageIsFromDockerHubOrAKnownPublicRegistryOnly(t *testing.T) {
	for _, ok := range []string{
		"postgres:18",
		"library/postgres:18",
		"docker.io/postgres:18",
		"docker.io/library/postgres:18",
		"bitnami/redis:7",
		"ghcr.io/example/app:1",
		"eu.gcr.io/p/app:1",
		"europe-west2-docker.pkg.dev/p/r/app:1",
		"postgres@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	} {
		if err := ValidImage(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"localhost/x:1",
		"localhost./x:1",
		"LOCALHOST.localdomain/x:1",
		"localtest.me/x:1",
		"127.0.0.1.nip.io/x:1",
		"Dan-desktop/x:1",
		"shop.internal/x:1",
		"127.1/postgres:18",
		"0177.0.0.1/postgres:18",
		"0x7f.1/postgres:18",
		"10.0.0.1/postgres:18",
		"[::1]/postgres:18",
		"registry:5000/postgres:18",
		"docker.io:443/postgres:18",
		"docker.io./postgres:18",
		"Docker.io/postgres:18",
		"evil.eu.gcr.io.example/x:1",
		"a.b-docker.pkg.dev/x:1",
		"-docker.pkg.dev/x:1",
		"postgres",
		"sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"SHA256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"sha256:0123456789ab",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:1",
		"library/sha256:0123456789ab",
		"docker.io/library/sha256:0123456789ab",
		"x/0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef:1",
	} {
		if err := ValidImage(bad); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

// A build names a repository or a namespace, and never a tag, a digest or
// an ID; any registry is one, since nothing is pulled by a build's name.
func TestABuildIsARepositoryOrANamespace(t *testing.T) {
	for _, ok := range []string{
		"shop/", "shop/tool", "tool", "localhost:5000/shop/",
		"europe-west2-docker.pkg.dev/p/data-lab-artifacts/",
	} {
		if err := ValidBuild(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "/", "shop//tool", "shop/tool:1", "shop/tool@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"sha256/", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "shop tool",
	} {
		if err := ValidBuild(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

// An image is built when its repository is a build, or under a namespace
// that is: any tag or digest of it, and never by an ID.
func TestAnImageIsBuiltByItsRepository(t *testing.T) {
	builds := []string{"shop/", "tool", "europe-west2-docker.pkg.dev/p/artifacts/"}
	for _, ok := range []string{
		"shop/a:1", "shop/a/b:latest", "shop/a", "tool:local", "tool",
		"europe-west2-docker.pkg.dev/p/artifacts/core-data:5f2a",
		"shop/a@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	} {
		if !Built(ok, builds) {
			t.Errorf("%s: not built", ok)
		}
	}
	for _, bad := range []string{
		"", "shopper/a:1", "shop:1", "tools:1", "other/tool:1", "tool/x:1",
		"europe-west2-docker.pkg.dev/p/other/core-data:1",
		"sha256:0123456789ab", "shop/sha256:0123",
		"shop/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	} {
		if Built(bad, builds) {
			t.Errorf("%s: built", bad)
		}
	}
	if Built("cafe", []string{"cafe"}) || !Built("cafe:1", []string{"cafe"}) {
		t.Error("an untagged hex name was built, or a tagged one was not")
	}
}
