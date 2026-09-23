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


  # THE POLICIES ARE DOCUMENTS, one per policy, under /etc/frisket/policies.
  # A session names its document by path, and the daemon reads it when the
  # session opens and again if the session is restored: a switch that
  # tightens a policy tightens the sessions already running under it. The
  # daemon's own file says only where names are resolved.
  configFile = pkgs.writeText "frisket.json" (builtins.toJSON { inherit (cfg) dns; });

  document = name: p: {
    inherit name;
    inherit (p) allow;
    routes = lib.mapAttrsToList
      (name: r: {
        inherit name;
        inherit (r) host upstream unmatched;
        paths = map (lib.filterAttrs (_: v: v != null)) r.paths;
      } // lib.optionalAttrs (r.upstreamCA != null) { upstreamCA = "${r.upstreamCA}"; }
      // lib.optionalAttrs (r.refusal != null) { inherit (r) refusal; }
      // lib.optionalAttrs (r.credentialFile != null) { inherit (r) credentialFile; }
      // lib.optionalAttrs (r.placeholder != null) { inherit (r) placeholder; }
      // lib.optionalAttrs (r.header != null) { inherit (r) header; }
      // lib.optionalAttrs (r.basicUser != null) { inherit (r) basicUser; }
      // lib.optionalAttrs (r.git != null) { git = { inherit (r.git) repos push; }; }
      // lib.optionalAttrs (r.credentialJSON != null) {
        credentialJSON = { inherit (r.credentialJSON) token; }
          // lib.optionalAttrs (r.credentialJSON.expiresMillis != null) { inherit (r.credentialJSON) expiresMillis; }
          // lib.optionalAttrs (r.credentialJSON.expiresJWT != null) { inherit (r.credentialJSON) expiresJWT; };
      })
      p.routes;
  };

  # Checked as the daemon will read them, when the system is built: a
  # document that does not hold together fails the build, rather than
  # refusing every session later. Whether its credential files exist yet is
  # not the document's to say, and is not checked.
  policies = pkgs.runCommand "frisket-policies"
    {
      nativeBuildInputs = [ cfg.package ];
      documents = lib.mapAttrs (name: p: builtins.toJSON (document name p)) cfg.policies;
      __structuredAttrs = true;
    } ''
    mkdir -p "$out"
    for name in "''${!documents[@]}"; do
      printf '%s' "''${documents[$name]}" > "$out/$name.json"
    done
    if [ -n "$(ls -A "$out")" ]; then
      frisket check "$out"/*.json
    fi
  '';

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
        description = "The methods the rule decides, compared exactly.";
      };
      prefix = mkOption {
        type = types.nullOr (types.strMatching "/.*");
        default = null;
        example = "/v1";
        description = ''
          The path the rule decides, and everything under it, matched by
          segment: `/v1` matches `/v1/models` and not `/v1-evil`. A segment
          that is `*` alone matches any one segment. Not with `path`.
        '';
      };
      path = mkOption {
        type = types.nullOr (types.strMatching "/.*");
        default = null;
        example = "/zones/*/dns_records/*";
        description = ''
          Exactly this path and nothing under it, matched by segment, `*`
          alone matching any one segment: an API operation. Where several
          rules match a request, the most specific decides -- a literal beats
          `*`, and either beats the end of a prefix. Not with `prefix`.
        '';
      };
      ask = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Put a matching request to `services.frisket.asker` instead of
          admitting it. With no asker, it is refused.
        '';
      };
      refuse = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Refuse a matching request: a hole in a broader rule -- where it is
          as specific as a rule that admits or asks, it wins -- or, alone, a
          route whose whole purpose is that nothing it matches goes anywhere.
          Not with `ask`.
        '';
      };
      operation = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            id = mkOption { type = types.strMatching ".+"; description = "The operation's id, for the log."; };
            summary = mkOption { type = types.strMatching ".+"; description = "What it does, in a line."; };
            description = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = "What it does, at more length.";
            };
          };
        });
        default = null;
        description = ''
          What the rule is, in its API's own words: the only prose a person
          being asked about a matching request is shown. It comes from here,
          never from the request.
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
            expiresJWT = mkOption {
              type = types.nullOr (types.strMatching ".+");
              default = null;
              example = "tokens.access_token";
              description = ''
                The dotted path to a JWT whose `exp` claim is the expiry --
                usually the token itself, which is where codex's login keeps
                it. The claim is read, not verified. Not with expiresMillis.
                Null: the file does not say.
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
        description = "The route's scope, with `git`. What neither decides, `unmatched` does.";
      };
      refusal = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            contentType = mkOption {
              type = types.strMatching ".+";
              example = "application/json";
              description = "The refusal's Content-Type.";
            };
            body = mkOption {
              type = types.strMatching ".*[{][{]message[}][}].*";
              example = ''{"success":false,"errors":[{"code":403,"message":"{{message}}"}]}'';
              description = ''
                The refusal's body, holding `{{message}}` exactly once:
                frisket's reason, and the matched operation's summary, never
                anything from the request. For a JSON content type it goes in
                escaped as the inside of a JSON string.
              '';
            };
          };
        });
        default = null;
        description = ''
          Refusals in the API's own error shape, so a client that reads that
          shape says why rather than only that the request failed. Null:
          plain text. The status is frisket's either way.
        '';
      };
      unmatched = mkOption {
        type = types.enum [ "refuse" "ask" ];
        default = "refuse";
        description = ''
          A request no rule matches: refused with a 403, or put to
          `services.frisket.asker` -- secure by default without being closed
          by default, so an endpoint nobody has classified is asked about
          rather than admitted or refused.
        '';
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
      example = "alice";
      description = ''
        Who the daemon runs as: the user whose credentials it holds, and the
        one user whose launchers may steer sessions to it -- they run as the
        caller, and the control socket answers only this user. Not a
        DynamicUser, because it has to read that user's credential files.
      '';
    };

    group = mkOption {
      type = types.str;
      default = config.users.users.${cfg.user}.group;
      defaultText = lib.literalExpression "config.users.users.\${user}.group";
      description = ''
        The daemon's group: the user's primary group, so that the control
        socket can read who is asking. The socket learns a peer's user
        namespace through the peer's pidfd, and the kernel answers that only
        to a process whose gid is the peer's too.
      '';
    };

    controlSocket = mkOption {
      type = types.path;
      default = "/run/frisket/control.sock";
      description = ''
        Where a launcher's `frisket steer`, `connect` and `close` reach the
        daemon. Made by a socket unit, `user`'s and 0600, and the daemon
        refuses any peer that is not `user` in the host's user namespace: a
        sandbox's workload runs as the same host uid, and the namespace is
        what tells it apart. Never bound into a sandbox; the flong adapter
        protects its directory from every bind.
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

    policyRoots = mkOption {
      type = types.listOf (types.strMatching "/.*");
      default = [ ];
      example = [ "/run/user/1000/chase" ];
      description = ''
        Directories, beside /etc/frisket/policies, that a session's policy
        document may be read from. A document is also refused unless it is a
        regular file, owned by root or the daemon's user, that nobody else
        can write: it says which credential goes to which host.
      '';
    };

    asker = mkOption {
      type = types.nullOr (types.strMatching "/.*");
      default = null;
      example = lib.literalExpression ''"''${pkgs.writeShellScript "ask" "..."}"'';
      description = ''
        The program a request is put to when a route asks about it. It runs
        as `user`, once per question and one question at a time, inside the
        daemon's own sandbox -- no display, a private /tmp -- so a graphical
        asker reaches the desktop some other way, `systemd-run --user` for
        one. The question is one JSON document on stdin: `session`, `policy`,
        `route`, `method`, `host`, `path` and `query` as sent, and the
        matched `operation`'s `id`, `summary` and `description` if there was
        one. Exit 0 admits the request, 1 declines it, anything else refuses
        it and is logged as the asker failing. Everything but `operation` is
        the workload's choosing: show it as the request, never as prose, and
        escape it for whatever renders it. Null: every request a route asks
        about is refused.
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
    assertions = [
      {
        assertion = cfg.group == config.users.users.${cfg.user}.group;
        message = "services.frisket.group is ${cfg.group}, not ${cfg.user}'s primary group: the control socket could read no launcher's user namespace, and would refuse every one.";
      }
    ] ++ lib.concatLists (lib.mapAttrsToList
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
        ++ lib.concatLists (lib.mapAttrsToList
          (rname: r: map
            (rule: {
              assertion = (rule.prefix == null) != (rule.path == null);
              message = "services.frisket.policies.${name}.routes.${rname} has a path rule with ${if rule.prefix == null then "neither a prefix nor a path" else "both a prefix and a path"}: a rule is one or the other.";
            })
            r.paths)
          p.routes)
        ++ lib.mapAttrsToList
          (rname: r: {
            assertion = r.credentialFile == null || ! lib.hasPrefix builtins.storeDir r.credentialFile;
            message = "services.frisket.policies.${name}.routes.${rname}.credentialFile is in the Nix store, which every user can read.";
          })
          p.routes)
      cfg.policies);

    # A directory of the documents, so the path a session names stays the
    # same across a switch while what it holds changes.
    environment.etc."frisket/policies".source = policies;

    # THE USER'S SOCKET, MADE BY SYSTEMD. The launchers that steer sessions
    # run as the user whose credentials the daemon holds -- the daemon's own
    # user -- so the socket is theirs and 0600. systemd makes it rather than
    # the daemon so that it exists, with that mode, before the daemon does,
    # and outlives a restart; its directory stays root's.
    systemd.sockets.frisket = {
      description = "frisket control socket";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenSequentialPacket = cfg.controlSocket;
        SocketUser = cfg.user;
        SocketGroup = cfg.group;
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

      # A changed policy restarts the daemon, and every session comes back
      # from the fd store served under its document as it reads now. The
      # documents are not in the unit, so without this a switch would leave
      # running sessions under what they were opened with.
      restartTriggers = [ policies ];

      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} serve -log-level ${cfg.logLevel} -control ${cfg.controlSocket}"
          + " -config ${configFile}"
          + lib.optionalString (cfg.asker != null) " -asker ${cfg.asker}"
          + lib.concatMapStrings (r: " -policy-root ${lib.escapeShellArg r}") ([ "/etc/frisket/policies" ] ++ cfg.policyRoots)
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
        # sockets from the launchers, so AF_UNIX stays.
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
