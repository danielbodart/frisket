# frisket-sudo's Zig (sudo/), built as flong builds its own: zig_0_15,
# ReleaseSafe, one zig build per derivation, the lazy dependencies (minish,
# zwanzig) fetched once as a fixed output for the checks only.
{ pkgs }:
let
  inherit (pkgs) lib;
  zig = pkgs.zig_0_15;
  root = ../sudo;

  zigBuild = { pname, files, steps, flags ? "", deps ? false, passthru ? { } }:
    pkgs.stdenv.mkDerivation {
      inherit pname passthru;
      version = "0";
      src = lib.fileset.toSource {
        inherit root;
        fileset = lib.fileset.unions ([ (root + "/build.zig") (root + "/build.zig.zon") ] ++ files);
      };
      nativeBuildInputs = [ zig ];
      # sudo_plugin.h and pam_appl.h; neither is referenced by what is built.
      buildInputs = [ pkgs.linux-pam pkgs.sudo.dev ];
      dontUseZigBuild = true;
      doCheck = false;
      disallowedReferences = [ zig ];
      postConfigure = lib.optionalString deps ''
        ln -s ${zigDeps} "$ZIG_GLOBAL_CACHE_DIR/p"
      '';
      installPhase = ''
        runHook preInstall
        mkdir -p $out
        TERM=dumb zig build ${steps} -j$NIX_BUILD_CORES $zigDefaultCpuFlag --release=safe --prefix $out ${flags}
        runHook postInstall
      '';
    };

  # On a build.zig.zon change: hash = lib.fakeHash, build checks.sudo-zig,
  # copy `got:`.
  zigDeps = zig.fetchDeps {
    pname = "frisket-sudo";
    version = "0";
    fetchAll = true;
    src = lib.fileset.toSource {
      inherit root;
      fileset = lib.fileset.unions [ (root + "/build.zig") (root + "/build.zig.zon") ];
    };
    hash = "sha256-GicN77r9Oh9xPqlIP5CS0/y2hSenxlM6thAiv1bjBW8=";
  };

  sources = map (f: root + "/${f}") [ "abi.zig" "fd.zig" "wire.zig" "chain.zig" "frisket_sudo.zig" "frisket-sudo-pam.zig" "frisket-sudo-check-plugin.zig" ];

  plugin = misread: zigBuild {
    pname = if misread then "frisket-sudo-plugin-misread" else "frisket-sudo-plugin";
    files = sources;
    steps = "install";
    flags = "-Dsudo-version=${pkgs.sudo.version}" + lib.optionalString misread " -Dmisread-mode=true";
    passthru = lib.optionalAttrs (!misread) { misread = plugin true; };
  };

  # sudo's own parse_args, built alone from the source of nixpkgs' sudo,
  # for the mode parse's property test.
  oracle = pkgs.stdenv.mkDerivation {
    pname = "sudo-parse-args-oracle";
    inherit (pkgs.sudo) version src;
    buildInputs = [ pkgs.linux-pam ];
    buildPhase = ''
      runHook preBuild
      make -C lib/util -j$NIX_BUILD_CORES
      $CC -o oracle -I. -Iinclude -Isrc src/parse_args.c ${root + "/oracle/oracle.c"} lib/util/.libs/*.o
      runHook postBuild
    '';
    installPhase = ''
      install -D oracle $out/bin/oracle
    '';
  };
in
{
  # lib/frisket_sudo.so, bin/frisket-sudo-pam, bin/frisket-sudo-check-plugin.
  # passthru.misread is the plugin whose mode test always says -v, for the
  # sudo VM's Ticket case.
  package = plugin false;

  # The unit and property tests, the check-plugin's verdicts, lint, fmt and
  # zwanzig with its planted bugs.
  check = zigBuild {
    pname = "frisket-sudo-zig-check";
    files = sources ++ map (f: root + "/${f}") [ "plugin_test.zig" "misread_test.zig" "planted_type.zig" "lint.zig" "analyze" ".zwanzig.json" ];
    steps = "test lint fmt analyze";
    flags = "-Ddev=true -Doracle=${oracle}/bin/oracle";
    deps = true;
  };
}
