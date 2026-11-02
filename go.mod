module github.com/danielbodart/frisket

// The oldest Go a consumer is likely to have. frisket itself builds with
// 1.27 (mise.toml, and go_1_27 in flake.nix), but nothing here needs more
// than 1.26, so that stays the floor. Written as 1.26.0 so that any patch
// release of the toolchain satisfies it.
go 1.26.0

require (
	github.com/danielbodart/galley v0.39.29
	github.com/danielbodart/quoin v0.100.28
	github.com/go-jose/go-jose/v4 v4.1.7
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
	pgregory.net/rapid v1.3.0
)

require github.com/vishvananda/netns v0.0.5 // indirect
