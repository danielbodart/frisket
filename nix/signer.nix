# nixosModules.signer: frisket-signer, the only holder of the TPM, serving
# forUser's SSH agent at /run/frisket-signer/agent.
self:
{ config, lib, pkgs, utils, ... }:

let
  cfg = config.services.frisket.signer;
  policy = config.services.frisket.policy;
  inherit (lib) mkOption types;
  package = self.packages.${pkgs.stdenv.hostPlatform.system}.frisket-signer;
  signer = lib.getExe package;
  rule = types.enum [ "allow" "ask" ];

  inTss = lib.filter
    (name:
      let u = config.users.users.${name}; in
      u.isNormalUser && (u.group == "tss" || lib.elem "tss" u.extraGroups || lib.elem name config.users.groups.tss.members))
    (lib.attrNames config.users.users);

  tpm = {
    User = "ssh-signer";
    Group = "ssh-signer";
    SupplementaryGroups = [ "tss" ];
    DevicePolicy = "closed";
    DeviceAllow = [ "/dev/tpmrm0 rw" ];
  };

  # Checked as serve will read it, when the system is built.
  configFile = pkgs.runCommand "frisket-signer-config.json"
    {
      nativeBuildInputs = [ package ];
      config = builtins.toJSON ({
        inherit (cfg) forUser terminal sshsig;
        ssh = { inherit (cfg.ssh) hosts; };
      } // lib.optionalAttrs policy.courier.enable {
        # A project's signed policy, read through the courier for the
        # process that asks: its signer section over these settings, Always
        # offered, and policy-sign served.
        policy = {
          courier = "/run/frisket-policy/sock";
          allowedSigners = "/etc/frisket/allowed_signers";
          inherit (policy) fileName;
        };
      });
      passAsFile = [ "config" ];
    } ''
    cp "$configPath" "$out"
    frisket-signer check "$out"
  '';
in
{
  imports = [ self.nixosModules.policy ];

  options.services.frisket.signer = {
    enable = lib.mkEnableOption "frisket-signer, the SSH agent whose keys live in the TPM";
    forUser = mkOption {
      type = types.str;
      default = "dan";
      description = "The only peer uid served, and the user whose galley is asked.";
    };
    terminal = mkOption {
      type = rule;
      default = "allow";
      description = "A real tab's bound, direct sign to a host in /etc/ssh/ssh_known_hosts.";
    };
    sshsig = mkOption {
      type = types.attrsOf rule;
      default = { git = "allow"; };
      description = "A direct SSHSIG sign in each namespace. An unlisted namespace is asked, Allow once.";
    };
    ssh.hosts = mkOption {
      type = types.attrsOf rule;
      default = { };
      example = { "github.com" = "allow"; };
      description = ''
        A bound, direct login from any of forUser's processes to a host key
        listed under this name in /etc/ssh/ssh_known_hosts, or a name this
        pattern matches: `*` alone is one label, `*` within a label any run
        of it (`*-ap`), and `**` as the first label one or more
        (`**.bodar.com`). A literal beats a pattern and a narrower pattern a
        wider one. A forwarded sign, an unknown host key and a cut chain are
        asked whatever this says. With services.frisket.policy.courier on, a
        project's signed policy file merges its signer.ssh.hosts over these.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    services.frisket.policy.courier.peers."frisket-signer.service" = "ssh-signer";

    assertions = [{
      assertion = inTss == [ ];
      message = "a login user in tss could sign with any key blob: ${toString inTss}";
    }
      {
        assertion = !policy.courier.enable || policy.courier.forUser == cfg.forUser;
        message = "services.frisket.policy.courier.forUser (${policy.courier.forUser}) is not services.frisket.signer.forUser (${cfg.forUser}): the signer reads the projects of the user it serves.";
      }];

    security.tpm2.enable = true;

    users.users.ssh-signer = {
      uid = 951;
      group = "ssh-signer";
      isSystemUser = true;
    };
    users.groups.ssh-signer.gid = 951;

    environment.etc."frisket-signer/config.json".source = configFile;

    systemd.sockets.frisket-signer = {
      description = "frisket-signer agent socket";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "/run/frisket-signer/agent";
        SocketUser = cfg.forUser;
        SocketMode = "0600";
        DirectoryMode = "0755";
        FileDescriptorName = "agent";
      };
    };

    systemd.services.frisket-signer = {
      description = "frisket-signer: SSH keys in the TPM, asked for through galley";
      requires = [ "frisket-signer.socket" ];
      wants = lib.optional policy.courier.enable "frisket-policy.socket";
      after = [ "frisket-signer.socket" ] ++ lib.optional policy.courier.enable "frisket-policy.socket";
      startLimitIntervalSec = 0;
      restartTriggers = [ configFile ];
      serviceConfig = tpm // {
        ExecStart = utils.escapeSystemdExecArgs [ signer "serve" "-config" "/etc/frisket-signer/config.json" ];
        Type = "notify";
        NotifyAccess = "main";
        Restart = "always";
        StateDirectory = "frisket-signer";
        StateDirectoryMode = "0700";
        NoNewPrivileges = true;
        CapabilityBoundingSet = "";
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        SystemCallFilter = [ "@system-service" "~@privileged" ];
        MemoryDenyWriteExecute = true;
      };
    };

    systemd.services.frisket-signer-keygen = {
      description = "frisket-signer: a new key in the TPM, in /var/lib/frisket-signer/new";
      serviceConfig = tpm // {
        Type = "oneshot";
        ExecStart = utils.escapeSystemdExecArgs [ signer "keygen" "-out" "/var/lib/frisket-signer/new" "-comment" "${cfg.forUser}@${config.networking.hostName}" ];
        StateDirectory = [ "frisket-signer" "frisket-signer/new" ];
        StateDirectoryMode = "0700";
      };
    };
  };
}
