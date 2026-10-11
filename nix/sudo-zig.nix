# frisket-sudo's Zig (sudo/), built as flong builds its own.
{ pkgs, sudo ? pkgs.sudo }:
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
      buildInputs = [ pkgs.linux-pam sudo.dev ];
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

  sources = map (f: root + "/${f}") [ "abi.zig" "fd.zig" "wire.zig" "chain.zig" "agent.zig" "ids.zig" "frisket_sudo.zig" "frisket-sudo-pam.zig" "frisket-sudo-check-plugin.zig" ];

  plugin = misread: zigBuild {
    pname = if misread then "frisket-sudo-plugin-misread" else "frisket-sudo-plugin";
    files = sources;
    steps = "install";
    flags = "-Dsudo-version=${sudo.version}" + lib.optionalString misread " -Dmisread-mode=true";
    passthru = lib.optionalAttrs (!misread) { misread = plugin true; };
  };

  # sudo's parse_args alone, the mode parse's test oracle.
  oracle = pkgs.stdenv.mkDerivation {
    pname = "sudo-parse-args-oracle";
    inherit (sudo) version src;
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
  # passthru.misread's mode test always says -v, for the sudo VM.
  package = plugin false;

  check = zigBuild {
    pname = "frisket-sudo-zig-check";
    files = sources ++ map (f: root + "/${f}") [ "plugin_test.zig" "misread_test.zig" "remote_test.zig" "planted_type.zig" "lint.zig" "analyze" ".zwanzig.json" ];
    steps = "test lint fmt analyze";
    flags = "-Ddev=true -Doracle=${oracle}/bin/oracle";
    deps = true;
  };
}
