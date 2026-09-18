{
  description = "Credentials on the wire, never in the sandbox";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      # The MAJOR only, which is the one part of the version that is a decision
      # rather than a count -- 0 says the interfaces are still moving.
      # scripts/version.sh derives the release name (major.commit-count.run-
      # number) from the repository, and a build from a store path has no
      # repository to count, so the two are deliberately different things: this
      # names the package, that names the artefact CI publishes.
      version = nixpkgs.lib.fileContents ./VERSION;

      mkFrisket = pkgs: pkgs.buildGoModule {
        pname = "frisket";
        inherit version;
        src = ./.;

        # Pinned rather than null, because there are dependencies: x/sys for
        # setns, and x/net/dns/dnsmessage once DNS lands. vendorHash = null is a
        # nice property and never a security one -- see PLAN.md, decision 1.
        vendorHash = "sha256-1JOxilzB1HukcixIkQAqwi3kZvL0CXT0teG3MkK9pt8=";

        # A STATIC BINARY. frisket runs as a systemd unit on the host with
        # ProtectSystem=strict, and the whole point of the design is that it has
        # no moving parts inside anything it is protecting. cgo would drag in
        # glibc's NSS, which resolves names through whatever the host's
        # nsswitch.conf says -- exactly the kind of implicit configuration this
        # is trying to remove.
        env.CGO_ENABLED = 0;

        ldflags = [ "-s" "-w" "-X" "main.version=${version}" ];

        # buildGoModule runs `go test ./...` here. The namespace tests create a
        # user+network namespace with clone flags and skip cleanly where the
        # kernel refuses, so this passes in the Nix sandbox and means something
        # on a machine where it does not have to.
        doCheck = true;

        meta = {
          description = "Keeps credentials out of sandboxes by adding them on the wire";
          homepage = "https://github.com/danielbodart/frisket";
          license = nixpkgs.lib.licenses.mit;
          mainProgram = "frisket";
          platforms = nixpkgs.lib.platforms.linux;
        };
      };
    in
    {
      packages = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        rec {
          frisket = mkFrisket pkgs;
          default = frisket;
        });

      devShells = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          default = pkgs.mkShell {
            packages = [ pkgs.go pkgs.gopls pkgs.golangci-lint ];
            # The same setting the package builds with, so a `go build` in the
            # shell produces the same binary the flake does rather than a
            # dynamically linked one that works here and nowhere else.
            CGO_ENABLED = "0";
          };
        });

      checks = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          pkg = self.packages.${system}.frisket;
        in
        {
          # The build, which is also the unit tests, the property tests and the
          # fuzz corpora.
          inherit (self.packages.${system}) frisket;

          # Formatting as a gate rather than a habit: this is one repository
          # with one formatter and no argument to have about it.
          gofmt = pkgs.runCommand "gofmt"
            { nativeBuildInputs = [ pkgs.go ]; }
            ''
              cd ${./.}
              unformatted=$(gofmt -l .)
              if [ -n "$unformatted" ]; then
                echo "not gofmt'd:" >&2
                echo "$unformatted" >&2
                exit 1
              fi
              touch $out
            '';

          # go vet from inside the package's own build, because vet needs the
          # module's dependencies and this is where they already are.
          govet = pkg.overrideAttrs (_: {
            pname = "frisket-vet";
            checkPhase = ''
              runHook preCheck
              go vet ./...
              runHook postCheck
            '';
          });

          # The version script decides what every release is called, so it is
          # gated by the same check that gates the release.
          shellcheck = pkgs.runCommand "shellcheck"
            { nativeBuildInputs = [ pkgs.shellcheck ]; }
            ''
              shellcheck ${./scripts/version.sh}
              touch $out
            '';
        });

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixpkgs-fmt);
    };
}
