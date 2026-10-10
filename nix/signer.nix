# nixosModules.signer: frisket-signer, the only holder of the TPM, serving
# forUser's SSH agent at /run/frisket-signer/agent.
self:
{ config, lib, pkgs, utils, ... }:

let
  cfg = config.services.frisket.signer;
  inherit (lib) mkOption types;
  signer = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.frisket-signer;
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
in
{
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
  };

  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = inTss == [ ];
      message = "a login user in tss could sign with any key blob: ${toString inTss}";
    }];

    security.tpm2.enable = true;

    users.users.ssh-signer = {
      uid = 951;
      group = "ssh-signer";
      isSystemUser = true;
    };
    users.groups.ssh-signer.gid = 951;

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
      after = [ "frisket-signer.socket" ];
      startLimitIntervalSec = 0;
      serviceConfig = tpm // {
        ExecStart = utils.escapeSystemdExecArgs ([ signer "serve" "-user" cfg.forUser "-terminal" cfg.terminal ]
          ++ lib.concatLists (lib.mapAttrsToList (ns: v: [ "-sshsig" "${ns}=${v}" ]) cfg.sshsig));
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
