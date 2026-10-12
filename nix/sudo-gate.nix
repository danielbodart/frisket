# nixosModules.sudoGate: frisket-sudo, asking forUser's galley about every
# sudo of forUser's that has no terminal.
self:
{ config, lib, pkgs, utils, ... }:

let
  cfg = config.services.frisket.sudoGate;
  policy = config.services.frisket.policy;
  inherit (lib) mkOption types;
  system = pkgs.stdenv.hostPlatform.system;
  plugin = (import ./sudo-zig.nix { inherit pkgs; sudo = config.security.sudo.package; }).package;
  package = self.packages.${system}.frisket-sudo;
  gate = lib.getExe package;
  sudoConf = import ./sudo-conf.nix { inherit pkgs plugin; } {
    version = config.security.sudo.package.version;
    user = cfg.forUser;
    remote = cfg.remoteKeys != [ ];
  };

  auth = config.security.pam.services.sudo.rules.auth;
  authStack = service: map (r: r.name) (lib.sort (a: b: a.order < b.order)
    (lib.filter (r: r.enable) (lib.attrValues config.security.pam.services.${service}.rules.auth)));

  sudoers = lib.filter (l: !lib.hasPrefix "#" (lib.trim l)) (lib.splitString "\n" config.security.sudo.configFile);
  matches = re: lib.concatMap (l: lib.filter lib.isList (builtins.split re l)) sudoers;
  timestampTypes = lib.unique (map lib.head (matches "timestamp_type[[:space:]]*=[[:space:]]*\"?([A-Za-z]*)")
    ++ map (_: "global") (matches "(^|[^!])![[:space:]]*(tty_tickets)([^A-Za-z_]|$)"));
  refused = lib.unique (map (m: lib.elemAt m 1) (matches "(^|[^!A-Za-z_])(rootpw|targetpw|runaspw|intercept|log_subcmds|INTERCEPT|LOG_SUBCMDS)([^A-Za-z_]|$)"));

  ptraceScope = config.boot.kernel.sysctl."kernel.yama.ptrace_scope" or null;

  # Checked as serve will read it, when the system is built.
  configFile = pkgs.runCommand "frisket-sudo-config.json"
    {
      nativeBuildInputs = [ package ];
      config = builtins.toJSON ({
        inherit (cfg) forUser remoteKeys;
        danger = lib.mapAttrs (_: d: lib.filterAttrs (_: v: v != null && v != { }) d) cfg.danger;
        inherit (cfg) exec;
      } // lib.optionalAttrs policy.courier.enable {
        # The signed policy of the project a sudo is run in, read through
        # the courier: its sudo.exec merged over exec.
        policy = {
          courier = "/run/frisket-policy/sock";
          allowedSigners = "/etc/frisket/allowed_signers";
          inherit (policy) fileName;
        };
      });
      passAsFile = [ "config" ];
    } ''
    cp "$configPath" "$out"
    frisket-sudo check "$out"
  '';
in
{
  imports = [ self.nixosModules.policy ];

  options.services.frisket.sudoGate = {
    enable = lib.mkEnableOption "frisket-sudo: the plugin line in sudo.conf, the PAM rule, the frisket-sudo PAM service, the sudoers defaults and the gate";
    forUser = mkOption {
      type = types.str;
      default = "dan";
      description = "The gated user, and the user whose galley is asked.";
    };
    remoteKeys = mkOption {
      type = types.listOf (types.strMatching "[^\n]+");
      default = [ ];
      description = "SSH public key lines whose signature approves forUser's remote sudo with no tty (`ssh -A host sudo x`); empty is remote mode off.";
    };
    danger = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          reason = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "The danger line for any command the pattern matches.";
          };
          args = mkOption {
            type = types.attrsOf types.str;
            default = { };
            description = "The danger line for a command the pattern matches with an argument this glob matches: `*` is any run of characters but `/`.";
          };
        };
      });
      default = { };
      example = {
        "reboot **".reason = "reboots this machine";
        "systemctl **".args."postgresql*" = "touches the database";
      };
      description = ''
        Danger rules beside the built-in catalogue, keyed by a command
        pattern: words, `*` for one, `**` last for any number. A match is
        always asked, with galley's danger banner and no window, so no rule
        here takes the catalogue's danger away.
      '';
    };
    exec = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          runAs = mkOption {
            type = types.strMatching "[a-z_][a-z0-9_-]*";
            default = "root";
            description = "The user the command runs as: a sudo as anyone else is not this rule's.";
          };
          answer = mkOption {
            type = types.enum [ "allow" "ask" "refuse" ];
            description = "`allow` runs it with no question and no password, `ask` puts a plain Allow/Refuse question with no password, `refuse` refuses it.";
          };
        };
      });
      default = { };
      example = {
        "/run/current-system/sw/bin/journalctl **".answer = "allow";
        "/run/current-system/sw/bin/journalctl ** [arg --vacuum*]".answer = "ask";
        "/run/current-system/sw/bin/systemctl restart foo.service".answer = "ask";
      };
      description = ''
        The host's exec rules, keyed by a pattern of the resolved command:
        the program's absolute path, then words, `*` for one, `**` last for
        any number, and optionally ` [arg GLOB]` after it, an arg rule,
        which only asks or refuses. A literal pattern beats a pattern, a
        narrower one a wider one. With services.frisket.policy.courier on,
        the signed chase.json of the project a sudo is run in has its
        `sudo.exec` merged over these, RFC 7396's way. No rule ever
        decides a danger or a warning, a command the gate did not see
        whole, one with a variable outside the allowlist, or a shell or
        env: each is asked as it is with none. A sudo no rule matches is
        the password dialog, or the window's question, as before.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    services.frisket.policy.courier.peers."frisket-sudo.service" = "sudo-gate";

    assertions = [
      {
        assertion = authStack "sudo" == [ "frisket-sudo-pam" "unix" "deny" ];
        message = "a conversation-free auth module would run on every terminal sudo -n: sudo's auth rules are ${toString (authStack "sudo")}, not frisket-sudo-pam unix deny";
      }
      {
        assertion = authStack "frisket-sudo" == [ "unix" "deny" ];
        message = "only the password may verify the sudo dialog: the frisket-sudo PAM service's auth rules are ${toString (authStack "frisket-sudo")}, not unix deny";
      }
      {
        assertion = timestampTypes == [ "tty" ];
        message = "a no-tty sudo's ticket under another timestamp_type is good for the next terminal sudo: sudoers sets timestamp_type ${toString timestampTypes}";
      }
      {
        assertion = refused == [ ];
        message = "frisket-sudo cannot work with sudoers setting ${toString refused}";
      }
      {
        assertion = ptraceScope == null || lib.toInt (toString ptraceScope) >= 1;
        message = "the sudo window's galley pin needs ptrace_scope >= 1";
      }
      {
        assertion = !policy.courier.enable || policy.courier.forUser == cfg.forUser;
        message = "services.frisket.policy.courier.forUser (${policy.courier.forUser}) is not services.frisket.sudoGate.forUser (${cfg.forUser}): the gate reads the projects of the user it gates.";
      }
    ];

    users.users.sudo-gate = {
      uid = 952;
      group = "sudo-gate";
      isSystemUser = true;
    };
    users.groups.sudo-gate.gid = 952;

    environment.etc."sudo.conf".source = sudoConf;
    environment.etc."frisket-sudo/config.json".source = configFile;

    security.sudo.extraConfig = ''
      Defaults noninteractive_auth
      Defaults timestamp_type=tty
    '';

    security.pam.services.frisket-sudo = { };
    security.pam.services.sudo.rules.auth.frisket-sudo-pam = {
      order = auth.unix.order - 10;
      control = "sufficient";
      modulePath = "${config.security.pam.package}/lib/security/pam_exec.so";
      args = [ "seteuid" "quiet" "${plugin}/bin/frisket-sudo-pam" cfg.forUser ];
    };

    systemd.sockets.frisket-sudo = {
      description = "frisket-sudo gate socket";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "/run/frisket-sudo/gate.sock";
        SocketUser = "sudo-gate";
        SocketMode = "0600";
        DirectoryMode = "0700";
        FileDescriptorName = "gate";
      };
    };

    systemd.services.frisket-sudo = {
      description = "frisket-sudo: sudo with no terminal, asked through galley";
      requires = [ "frisket-sudo.socket" ];
      wants = lib.optional policy.courier.enable "frisket-policy.socket";
      after = [ "frisket-sudo.socket" ] ++ lib.optional policy.courier.enable "frisket-policy.socket";
      startLimitIntervalSec = 0;
      restartTriggers = [ configFile ];
      serviceConfig = {
        ExecStart = utils.escapeSystemdExecArgs [ gate "serve" "-config" "/etc/frisket-sudo/config.json" ];
        Type = "notify";
        NotifyAccess = "main";
        User = "sudo-gate";
        Group = "sudo-gate";
        Restart = "always";
        RestartSec = "1s";
        CapabilityBoundingSet = "";
        ProcSubset = "pid";
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
      };
    };
  };
}
