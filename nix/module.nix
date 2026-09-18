# nixosModules.default: the daemon, `frisket serve`.
#
# It runs as the user whose credentials it holds (PLAN.md decision 9), NOT as a
# DynamicUser: it must read credential files that change under it, and a
# DynamicUser can do neither that nor anything else that user can. It holds
# nothing that user does not already have, and systemd takes the rest away.
self:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.frisket;
  inherit (lib) mkOption types;

  # A session stores its four listeners and its record: one sealed memfd.
  perSession = 5;
in
{
  options.services.frisket = {
    enable = lib.mkEnableOption "frisket, which holds sandboxes' listeners and adds their credentials on the wire";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.frisket;
      defaultText = lib.literalExpression "frisket.packages.\${system}.frisket";
      description = "The frisket to run. This flake's build unless you say otherwise.";
    };

    user = mkOption {
      type = types.str;
      default = "frisket";
      example = "alice";
      description = ''
        Who the daemon runs as: the user whose credentials it holds. Not a
        DynamicUser, because it has to read that user's credential files. The
        default creates a system user of that name, for a frisket that holds
        no credential yet.
      '';
    };

    group = mkOption {
      type = types.str;
      default = "frisket";
      description = "The daemon's group. The default creates it.";
    };

    controlSocket = mkOption {
      type = types.path;
      default = "/run/frisket/control.sock";
      description = ''
        Where root's `frisket steer`, `connect` and `close` reach the daemon.
        Made by a socket unit, root-owned and 0600: the daemon is not root and
        cannot make the socket root's itself, and it also refuses any peer that
        is not uid 0. Never bound into a sandbox.
      '';
    };

    maxSessions = mkOption {
      type = types.ints.positive;
      default = 256;
      description = ''
        How many sessions systemd's file-descriptor store can hold across a
        restart. Each stores ${toString perSession} descriptors. systemd closes
        what does not fit, silently as far as the daemon can tell -- and a
        session that loses its listeners that way does not survive a restart.
      '';
    };

    maxConnections = mkOption {
      type = types.ints.unsigned;
      default = 0;
      description = ''
        Concurrent connections per session; 0 is the built-in default. Every
        steered connection costs a descriptor on the host.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    users.users = lib.mkIf (cfg.user == "frisket") {
      frisket = { isSystemUser = true; inherit (cfg) group; };
    };
    users.groups = lib.mkIf (cfg.group == "frisket") { frisket = { }; };

    # ROOT'S SOCKET, HELD BY A USER. The daemon is not root, so anything it
    # created would be its own; systemd makes the socket instead, root-owned
    # and 0600, and passes it in by name.
    systemd.sockets.frisket = {
      description = "frisket control socket";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenSequentialPacket = cfg.controlSocket;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0755";
        FileDescriptorName = "control";
      };
    };

    systemd.services.frisket = {
      description = "frisket: credentials on the wire, never in the sandbox";
      wantedBy = [ "multi-user.target" ];
      wants = [ "frisket.socket" ];
      after = [ "frisket.socket" ];

      # RESTARTED, NOT STOPPED AND STARTED, by nixos-rebuild. The fd store is
      # kept across a restart and released on a stop -- so the NixOS default,
      # stop-then-start, would sever every running session on every switch
      # that touches this unit, which is exactly what the store is for.
      stopIfChanged = false;

      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} serve -control ${cfg.controlSocket}"
          + lib.optionalString (cfg.maxConnections > 0) " -max-conns ${toString cfg.maxConnections}";
        User = cfg.user;
        Group = cfg.group;
        Restart = "on-failure";

        # SESSIONS SURVIVE A RESTART THROUGH THE FD STORE. A listener inside a
        # sandbox's namespace cannot be reopened from a path, so PID 1 holds a
        # copy of each from the moment the session is created -- a crash is
        # covered as well as a restart -- and passes them back by name.
        # NotifyAccess=main, because only the daemon itself may store.
        Type = "notify";
        NotifyAccess = "main";
        FileDescriptorStoreMax = cfg.maxSessions * perSession;
        FileDescriptorStorePreserve = "restart";

        # Everything else it could reach, taken away. It dials out from the
        # host's network namespace, so the network stays; it receives
        # sockets from root, so AF_UNIX stays.
        UMask = "0077";
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        PrivateTmp = true;
        PrivateDevices = true;
        PrivateIPC = true;
        DevicePolicy = "closed";
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        NoNewPrivileges = true;
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        KeyringMode = "private";
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        SystemCallArchitectures = "native";
        # EPERM rather than death for anything outside the set: Go's runtime
        # probes a few calls at start and copes with a refusal.
        SystemCallFilter = [ "@system-service" "~@privileged" ];
        SystemCallErrorNumber = "EPERM";
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
        # Deliberately NOT RemoveIPC: the user is a person, and it would remove
        # THEIR IPC objects whenever this unit stops.
      };
    };
  };
}
