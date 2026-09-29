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
