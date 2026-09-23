{
  description = "Credentials on the wire, never in the sandbox";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  # TEST-ONLY. frisket knows nothing about flong (PLAN.md decision 7); the
  # adapter is tested against a pinned flong because it is the layer where the
  # security properties meet and nothing else tests it. Nothing outside
  # `checks` reads this input, so a consumer never fetches it.
  inputs.flong = {
    url = "github:danielbodart/flong";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flong }:
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
        # setns, x/net for dns/dnsmessage, the one parser frisket points at
        # hostile DNS, and vishvananda/netlink for the routing steer and
        # connect make inside a sandbox. vendorHash = null is a nice property
        # and never a security one -- see PLAN.md, decision 1.
        vendorHash = "sha256-NSVDeE9VKhJHP0evL1r2QkbSY4wmzbyuQit1EyJcp9E=";

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
      # The ruleset and the listener specification, as one attrset, for any
      # launcher. See nix/steering.nix.
      lib.steering = import ./nix/steering.nix { inherit (nixpkgs) lib; };

      # The daemon, and the adapter that maps its sessions onto flong's hooks.
      # Keyed, so the module system can tell it is one module however many
      # times it is imported: the flong adapter imports it too, and without a
      # key two imports are two anonymous functions declaring every option twice.
      nixosModules.default = {
        key = "github:danielbodart/frisket#nixosModules.default";
        imports = [ (import ./nix/module.nix self) ];
      };
      nixosModules.flong = import ./nix/flong.nix self;

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

          # Importing the daemon module beside the flong adapter, which imports
          # it too, must evaluate: the key on nixosModules.default is what makes
          # the second import the same module rather than a second declaration
          # of every option.
          modules =
            let
              eval = nixpkgs.lib.nixosSystem {
                inherit system;
                modules = [
                  flong.nixosModules.default
                  self.nixosModules.default
                  self.nixosModules.flong
                  { boot.isContainer = true; system.stateVersion = "26.05"; }
                ];
              };
            in
            pkgs.writeText "frisket-modules"
              (builtins.toJSON { inherit (eval.config.services.frisket) enable; });

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

          # The tests again, under the race detector. It needs cgo -- the race
          # runtime is C -- so this check turns it on for itself; the package
          # is still built static, with CGO_ENABLED=0, and never ships this.
          race = pkg.overrideAttrs (old: {
            pname = "frisket-race";
            env = (old.env or { }) // { CGO_ENABLED = 1; };
            checkPhase = ''
              runHook preCheck
              go test -race ./...
              runHook postCheck
            '';
          });

          # Both steering sets, as lib.steering writes them: checked by
          # frisket's own reader, which is what steer and connect run, and by
          # nft itself, in a network namespace of the build's own so the check
          # has the privilege to ask the kernel without touching anything.
          steering =
            let
              file = set: pkgs.writeText "steering-${set}.json"
                (self.lib.steering { inherit set; }).json;
            in
            pkgs.runCommand "steering"
              { nativeBuildInputs = [ pkg pkgs.nftables pkgs.util-linux pkgs.jq ]; }
              ''
                check() {
                  frisket steering "$2"
                  jq -r .ruleset "$2" > "$1.nft"
                  if unshare -rn true 2>/dev/null; then
                    unshare -rn nft -c -f "$1.nft"
                  else
                    echo "no user namespace in this build sandbox: nft -c skipped for $1" >&2
                  fi
                }
                check all ${file "all"}
                check service ${file "service"}
                touch $out
              '';

          # frisket in flong's real shape, end to end, in two VMs.
          flong = pkgs.testers.runNixOSTest (import ./tests/flong.nix { inherit self flong; });

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
