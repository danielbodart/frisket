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
        # hostile DNS, vishvananda/netlink for the routing steer and connect
        # make inside a sandbox, and go-jose for the JWTs a session key signs.
        # vendorHash = null is a nice property
        # and never a security one -- see PLAN.md, decision 1.
        vendorHash = "sha256-Co9KrSQ/rLnlnlRTCdp/hnHAPzfm618jYqVrNpDXkSQ=";

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
        # The ruleset lib.steering writes is loaded by nft, in a namespace of
        # the test's own, to see a relayed port reach the session's listener.
        nativeCheckInputs = [ pkgs.nftables ];

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

      # The names no project's .internal name may equal or fall under: the very
      # file the Go code embeds, and so the list Names() uses. Pure data, for
      # chase and nix-config to read rather than copy. frisket exports only the
      # list; the address and the names are chase's lib.docker to derive.
      lib.docker.reserved = builtins.fromJSON (builtins.readFile ./internal/docker/reserved.json);

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
            # nft, for the test that loads a session's ruleset in a namespace
            # of its own; it skips without one.
            packages = [ pkgs.go pkgs.gopls pkgs.golangci-lint pkgs.nftables ];
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
          #
          # The relay's sets are declared, and marked after DNS and before the
          # service address -- and in `all` before the local exemption, which
          # would otherwise hand a relayed port to a loopback where nothing
          # listens. And the copies the Go tests load in a namespace are
          # lib.steering's own, so what they show is what ships; regenerate
          # one with
          #   nix eval --raw .#lib.steering --apply 's: (s { set = "all"; }).json' | jq . \
          #     > internal/steering/testdata/steering-all.json
          steering =
            let
              file = set: pkgs.writeText "steering-${set}.json"
                (self.lib.steering { inherit set; }).json;
            in
            pkgs.runCommand "steering"
              { nativeBuildInputs = [ pkg pkgs.nftables pkgs.util-linux pkgs.jq ]; }
              ''
                fail() { echo "steering $set: $*" >&2; exit 1; }
                line() { grep -n -F -m1 -- "$1" "$set.nft" | cut -d: -f1; }
                check() {
                  set=$1
                  frisket steering "$2" | tee "$set.out"
                  grep -q '^relay sets inet frisket relay4, relay6' "$set.out" || fail "frisket steering does not print the relay sets"
                  jq -r .ruleset "$2" > "$set.nft"
                  grep -q '^  set relay4 { type ipv4_addr . inet_service; }$' "$set.nft" || fail "no relay4 set"
                  grep -q '^  set relay6 { type ipv6_addr . inet_service; }$' "$set.nft" || fail "no relay6 set"
                  dns=$(line 'th dport 53 meta mark set')
                  r4=$(line 'ip daddr . tcp dport @relay4 meta mark set')
                  r6=$(line 'ip6 daddr . tcp dport @relay6 meta mark set')
                  svc=$(line 'ip daddr 192.0.2.2 ')
                  [ -n "$dns" ] && [ -n "$r4" ] && [ -n "$r6" ] && [ -n "$svc" ] || fail "a mark is missing"
                  [ "$dns" -lt "$r4" ] && [ "$r4" -lt "$r6" ] && [ "$r6" -lt "$svc" ] ||
                    fail "the relay is not marked after DNS ($dns) and before the service address ($svc): $r4, $r6"
                  if [ "$set" = all ]; then
                    local=$(line 'fib daddr type local return')
                    [ -n "$local" ] && [ "$r6" -lt "$local" ] || fail "the relay is not marked before the local exemption ($local)"
                  fi
                  cmp <(jq -S . "$2") <(jq -S . "$3") || fail "$3 is not what lib.steering writes"
                  if unshare -rn true 2>/dev/null; then
                    unshare -rn nft -c -f "$set.nft"
                  else
                    echo "no user namespace in this build sandbox: nft -c skipped for $set" >&2
                  fi
                }
                check all ${file "all"} ${./internal/steering/testdata/steering-all.json}
                check service ${file "service"} ${./internal/steering/testdata/steering-service.json}
                touch $out
              '';

          # frisket in flong's real shape, end to end, in two VMs.
          flong = pkgs.testers.runNixOSTest (import ./tests/flong.nix { inherit self flong; });

          # lib.docker.reserved is exactly the list the Go test pins, so the
          # file cannot change under a consumer without a test failing here and
          # one failing there.
          docker-reserved =
            let
              got = builtins.toJSON self.lib.docker.reserved;
              want = builtins.toJSON [ "frisket.internal" "google.internal" ];
            in
            pkgs.runCommand "docker-reserved" { inherit got want; } ''
              if [ "$got" != "$want" ]; then
                echo "lib.docker.reserved is $got, want $want" >&2
                exit 1
              fi
              touch $out
            '';

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
