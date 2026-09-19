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


  # THE POLICIES ARE DATA, read by the daemon at start and checked there in
  # full: a configuration that does not hold stops the daemon, loudly, rather
  # than refusing every session later.
  configFile = pkgs.writeText "frisket.json" (builtins.toJSON {
    inherit (cfg) dns;
    policies = lib.mapAttrs
      (_: p: {
        inherit (p) allow;
        routes = lib.mapAttrsToList
          (name: r: {
            inherit name;
            inherit (r) host upstream paths;
          } // lib.optionalAttrs (r.upstreamCA != null) { upstreamCA = "${r.upstreamCA}"; }
          // lib.optionalAttrs (r.credentialFile != null) { inherit (r) credentialFile; }
          // lib.optionalAttrs (r.placeholder != null) { inherit (r) placeholder; }
          // lib.optionalAttrs (r.header != null) { inherit (r) header; }
          // lib.optionalAttrs (r.basicUser != null) { inherit (r) basicUser; }
          // lib.optionalAttrs (r.git != null) { git = { inherit (r.git) repos push; }; }
          // lib.optionalAttrs (r.credentialJSON != null) {
            credentialJSON = { inherit (r.credentialJSON) token; }
              // lib.optionalAttrs (r.credentialJSON.expiresMillis != null) { inherit (r.credentialJSON) expiresMillis; };
          })
          p.routes;
      })
      cfg.policies;
  });

  # A name is on the allowlist exactly, under one of its wildcards, or the
  # list has "*". The daemon makes the same checks with the real matcher;
  # these only say so at evaluation, where the mistake was made.
  allowed = allow: n: lib.elem "*" allow || lib.elem n allow
    || lib.any (w: lib.hasPrefix "*." w && lib.hasSuffix (lib.removePrefix "*" w) n) allow;

  # A "*" is the whole entry, or a leading "*.", and nowhere else.
  starPlaced = w: w == "*" || ! lib.hasInfix "*" (lib.removePrefix "*." w);

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
        description = "The name the sandbox connects to, intercepted because this route is for it. It must be on the policy's `allow`.";
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
        type = types.nullOr (types.strMatching "/.*");
        default = null;
        example = "/run/secrets/example-token";
        description = ''
          The token, alone in a file on the host -- or, with `credentialJSON`,
          a JSON file that names it -- read by the daemon as
          `services.frisket.user` and re-read when it is replaced -- by rename
          too. A string and not a path, so it is never copied into the store.
          Not under /tmp, which the daemon's PrivateTmp hides. Null: a route
          with no credential, which only holds requests to its scope and
          sends them on as they came; it then has no placeholder, header or
          basicUser.
        '';
      };
      credentialJSON = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            token = mkOption {
              type = types.strMatching ".+";
              example = "claudeAiOauth.accessToken";
              description = "The dotted path through the file's JSON to the token.";
            };
            expiresMillis = mkOption {
              type = types.nullOr (types.strMatching ".+");
              default = null;
              example = "claudeAiOauth.expiresAt";
              description = ''
                The dotted path to its expiry, in milliseconds since the epoch.
                Past it the daemon answers 503, which the client retries,
                rather than sending a token the upstream would 401. Null: the
                file does not say.
              '';
            };
          };
        });
        default = null;
        description = "Read `credentialFile` as JSON, for a file that is not a bare token. Null: the whole file, trimmed.";
      };
      header = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "X-Api-Key";
        description = "The header the token goes in, bare. Null is `Authorization: Bearer <token>`.";
      };
      basicUser = mkOption {
        type = types.nullOr (types.strMatching "[^:[:space:]]+");
        default = null;
        example = "x-access-token";
        description = ''
          Put the token in `Authorization: Basic` as the password, under this
          user: git over HTTPS, which GitHub accepts in no other form. Not with
          `header`.
        '';
      };
      placeholder = mkOption {
        type = types.nullOr (types.strMatching "[^[:space:]]+");
        default = null;
        example = "proxy-injected";
        description = ''
          What the sandbox is given in the credential's place -- in the
          environment variable or file its client reads a token from. A request
          carrying exactly this in the credential's header, bare or after its
          scheme, has it replaced with the credential; that is the only change
          frisket makes. Anything else, or nothing, goes upstream as sent.
        '';
      };
      paths = mkOption {
        type = types.listOf pathRule;
        default = [ ];
        description = "The route's scope, with `git`. A request neither admits is refused with a 403.";
      };
      git = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            repos = mkOption {
              type = types.nonEmptyListOf types.str;
              example = [ "owner/repo" ];
              description = ''`owner/name`, or `"*"` alone for every repository.'';
            };
            push = mkOption {
              type = types.bool;
              default = false;
              description = "Admit git-receive-pack. Without it a push is refused at its first request.";
            };
          };
        });
        default = null;
        description = ''
          Git's smart-HTTP protocol as GitHub serves it --
          `/owner/name[.git]/info/refs` and `git-upload-pack`, and
          `git-receive-pack` with `push` -- for these repositories.
        '';
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

    logLevel = mkOption {
      type = types.enum [ "debug" "info" "warn" "error" ];
      default = "info";
      description = ''
        `debug` adds a line per intercepted request with its headers as the
        client sent them, the response's, and the start of an error's body --
        to see what a client does on the wire. A header that can carry a
        credential is described (its kind, length and a short hash), never
        shown.
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
        Where frisket resolves the names a session is allowed. Empty is
        whatever the host's /etc/resolv.conf names, followed as it changes:
        a query in flight keeps its server, the next one asks the new one, and
        a file naming no usable server keeps the last one that did.
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
              Names a session may resolve: `name`; `*.name`, which matches
              every name below it at any depth and not the name itself; or `*`
              alone, every name. A `*` anywhere else is refused. A name not
              here is answered NXDOMAIN without an upstream lookup, and egress
              accepts only addresses DNS resolved for a name that is.
            '';
          };
          routes = mkOption {
            type = types.attrsOf route;
            default = { };
            description = ''
              The intercepted hosts' credentials and scopes, by a name for the
              log. A route's host is what makes a name intercepted: it is
              answered with the session's service address, so its TLS is
              terminated by frisket and its requests carry the route's
              credential. Each host must be on `allow`.
            '';
          };
        };
      });
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
          (w: {
            assertion = starPlaced w;
            message = "services.frisket.policies.${name}.allow has ${w}: a `*` is allowed only alone, meaning every name, or as a leading `*.`.";
          })
          p.allow
        ++ lib.mapAttrsToList
          (rname: r: {
            assertion = allowed p.allow r.host;
            message = "services.frisket.policies.${name}.routes.${rname} is for ${r.host}, which is not on its allowlist: interception is how an allowed host gets its credential, not a way round the allowlist.";
          })
          p.routes
        ++ lib.mapAttrsToList
          (rname: r: {
            assertion = r.credentialFile == null || ! lib.hasPrefix builtins.storeDir r.credentialFile;
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
        ExecStart = "${lib.getExe cfg.package} serve -log-level ${cfg.logLevel} -control ${cfg.controlSocket}"
          + " -config ${configFile}"
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
