module github.com/danielbodart/frisket

// The oldest Go a consumer is likely to have. Both nixpkgs branches in play --
// nixos-26.05, which nix-config pins, and nixos-unstable, which this flake
// pins -- ship 1.26.7, so 1.26 is the floor and there is nothing to gain by
// claiming a newer one. Written as 1.26.0 rather than 1.26.7 so that any
// patch release of the toolchain satisfies it.
go 1.26.0

require (
	golang.org/x/sys v0.48.0
	pgregory.net/rapid v1.3.0
)
