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

  stateDir = "/var/lib/frisket";

  # THE POLICIES ARE DATA, read by the daemon at start and checked there in
  # full: a configuration that does not hold stops the daemon, loudly, rather
  # than refusing every session later.
  configFile = pkgs.writeText "frisket.json" (builtins.toJSON {
    inherit (cfg) dns;
    policies = lib.mapAttrs
      (_: p: {
        inherit (p) allow intercept;
        routes = lib.mapAttrsToList
          (name: r: {
            inherit name;
            inherit (r) host upstream credentialFile strip paths;
          } // lib.optionalAttrs (r.upstreamCA != null) { upstreamCA = "${r.upstreamCA}"; }
          // lib.optionalAttrs (r.header != null) { inherit (r) header; })
          p.routes;
      })
      cfg.policies;
  });

  # A name is on the allowlist exactly, or under one of its wildcards. The
  # daemon makes the same check with the real matcher; this one only says so
  # at evaluation, where the mistake was made.
  allowed = allow: n: lib.elem n allow
    || lib.any (w: lib.hasPrefix "*." w && lib.hasSuffix (lib.removePrefix "*" w) n) allow;

  pathRule = types.submodule {
    options = {
      methods = mkOption {
        type = types.nonEmptyListOf types.str;
        example = [ "GET" "POST" ];
        description = "The methods admitted, compared exactly.";
      };
      prefix = mkOption {
        type = types.strMatching "/.*";
        example = "/v1";
        description = ''
          The path admitted, and everything under it, matched by segment:
          `/v1` admits `/v1/models` and not `/v1-evil`.
        '';
      };
    };
  };

  route = types.submodule {
    options = {
      host = mkOption {
        type = types.str;
        example = "api.example.com";
        description = "The name the sandbox connects to. It must be in the policy's `intercept`.";
      };
      upstream = mkOption {
        type = types.strMatching "https://.*";
        example = "https://api.example.com";
        description = "Where its requests go. Never plain HTTP: the credential crosses this hop.";
      };
      upstreamCA = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "A PEM bundle to verify the upstream with, instead of the host's roots.";
      };
      credentialFile = mkOption {
        type = types.strMatching "/.*";
        example = "/run/secrets/example-token";
        description = ''
          The token, alone in a file on the host, read by the daemon as
          `services.frisket.user` and re-read when it is replaced -- by rename
          too. A string and not a path, so it is never copied into the store.
          Not under /tmp, which the daemon's PrivateTmp hides.
        '';
      };
      header = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "X-Api-Key";
        description = "The header the token goes in, bare. Null is `Authorization: Bearer <token>`.";
      };
      strip = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          Further request headers removed before the credential is added.
          `Authorization`, `Proxy-Authorization` and the credential's own header
          always are.
        '';
      };
      paths = mkOption {
        type = types.nonEmptyListOf pathRule;
        description = "The route's scope. A request no rule admits is refused with a 403.";
      };
    };
  };
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

    dns = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "192.0.2.53" "[2001:db8::53]:53" ];
      description = ''
        Where frisket resolves the names a session is allowed. Empty is the
        host's own /etc/resolv.conf, read once at start.
      '';
    };

    policies = mkOption {
      default = { };
      description = ''
        The policies a session can name. A session naming one that is not here
        is refused before it has any rules, so it never runs.
      '';
      example = lib.literalExpression ''
        {
          research = {
            allow = [ "api.example.com" "*.pkg.example.org" ];
            intercept = [ "api.example.com" ];
            routes.example = {
              host = "api.example.com";
              upstream = "https://api.example.com";
              credentialFile = "/run/secrets/example-token";
              paths = [ { methods = [ "GET" "POST" ]; prefix = "/v1"; } ];
            };
          };
        }
      '';
      type = types.attrsOf (types.submodule {
        options = {
          allow = mkOption {
            type = types.listOf types.str;
            default = [ ];
            description = ''
              Names a session may resolve: `name` or `*.name`, which matches
              every name below it and not the name itself. A name not here is
              refused at DNS without an upstream lookup, and egress accepts only
              addresses DNS resolved for a name that is.
            '';
          };
          intercept = mkOption {
            type = types.listOf types.str;
            default = [ ];
            description = ''
              Names answered with the session's service address, so their TLS
              is terminated by frisket and their requests carry a route's
              credential. Each must be on `allow` and have a route.
            '';
          };
          routes = mkOption {
            type = types.attrsOf route;
            default = { };
            description = "The intercepted hosts' credentials and scopes, by a name for the log.";
          };
        };
      });
    };

    caCertificate = mkOption {
      type = types.path;
      readOnly = true;
      default = "${stateDir}/ca/ca.crt";
      description = ''
        The machine's CA certificate, made by the daemon on its first start:
        what a sandbox must trust for interception. The key beside it never
        leaves the state directory. How each runtime inside is told to trust it
        -- NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, REQUESTS_CA_BUNDLE, a system
        bundle -- is the consumer's to decide.
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
    assertions = lib.concatLists (lib.mapAttrsToList
      (name: p:
        map
          (n: {
            assertion = allowed p.allow n;
            message = "services.frisket.policies.${name}.intercept names ${n}, which is not on its allowlist: interception is how an allowed host gets its credential, not a way round the allowlist.";
          })
          p.intercept
        ++ lib.mapAttrsToList
          (rname: r: {
            assertion = lib.elem r.host p.intercept;
            message = "services.frisket.policies.${name}.routes.${rname} is for ${r.host}, which is not in the policy's intercept list, so no connection would ever reach it.";
          })
          p.routes
        ++ lib.mapAttrsToList
          (rname: r: {
            assertion = ! lib.hasPrefix builtins.storeDir r.credentialFile;
            message = "services.frisket.policies.${name}.routes.${rname}.credentialFile is in the Nix store, which every user can read.";
          })
          p.routes)
      cfg.policies);

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
          + " -config ${configFile} -state ${stateDir}"
          + lib.optionalString (cfg.maxConnections > 0) " -max-conns ${toString cfg.maxConnections}";
        # The CA key lives here, 0600 inside a 0700 directory.
        StateDirectory = "frisket";
        StateDirectoryMode = "0700";
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
