# nixosModules.flong: the adapter, which maps a frisket session onto flong's
# hooks for a given launcher. flong knows nothing about frisket and frisket
# knows nothing about flong; this is the one place they meet, and so the place
# the security properties actually meet (PLAN.md decision 7).
#
#   services.frisket.flong.<launcher> = { policy = "..."; set = "all"; };
#
# flong's contract is an ordering: whatever `postStart` installs is in place
# before anything gives the namespace egress, and flong attaches its own
# network after `postStart` returns. frisket's is the same ordering one level
# down -- listeners, then rules, then connectivity -- so the hook is laid out
# around the consumer's own:
#
#   mkBefore  frisket steer    listeners inside, handed to the daemon; rules
#   (default) your postStart   more rules, if you have any: still no egress
#   mkAfter   frisket connect  the service address, and for "all" the dummy
#   (flong)   network          pasta, for "service"
#
# Each frisket step refuses to run out of turn, so a snippet that gets this
# wrong fails the launch rather than leaving a session unsteered.
#
# The adapter puts nothing on the hooks' PATH: its own steps name frisket,
# nsenter and nft by store path, so no PATH decides what runs, and a rules
# hook of your own must name its tools the same way (or add them to the
# launcher's `path` itself). A bare `nft` in it is not found.
#
# The declarations are rootless: the launcher runs as whoever calls it, and
# its hooks with it, so frisket's steps do too. The control socket answers
# only `services.frisket.user`, so that is who runs these launchers -- the
# person whose credentials the daemon holds.
#
# `frisket steer` also puts the session's own CA at /etc/frisket, on a
# read-only tmpfs in the session's mount namespace: ca.crt, and ca-bundle.crt,
# the host's roots with the CA after them. WHERE THE BUNDLE IS is frisket's to
# say; which of a runtime's dozen CA variables point at it is not. That list
# is a fact about the tools a sandbox runs, it drifts as they change, and the
# consumer is what knows them -- so it lives there. chase carries the set
# these containers used to get from here.
self:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.frisket;
  inherit (lib) mkOption types;
  frisket = lib.getExe cfg.package;
  control = [ "-control" cfg.controlSocket ];
  # steer and connect each enter the session once, under this nsenter, in
  # the user namespace that owns the session's, which -flong reads from
  # $userns: the hooks run as the caller, who is root only there. By store
  # path, as nft is, so PATH never decides which runs.
  nsenter = [ "-nsenter" (lib.getExe' pkgs.util-linux "nsenter") ];
  nft = [ "-nft" (lib.getExe pkgs.nftables) ];

  steeringFile = name: s: pkgs.writeText "frisket-steering-${name}.json"
    (self.lib.steering ({ inherit (s) set; } // s.steering)).json;

  # A flong hook is an argument list, which flong never parses as shell: a
  # hook program of flong's in the store execs its words as they are, with
  # what flong knows of the session in the environment -- $machine, $netns,
  # $userns, $leader, $workspace in postStart, $machine alone in postStop --
  # which -flong has frisket read itself. postStart gets the launcher's own
  # arguments after its words, which the trailing "--" keeps from ever being
  # read as flags, and -flong ignores; postStop gets none, and ends in "--"
  # only because every step is built the same way.
  hook = step: flags: [ frisket step "-flong" ] ++ control ++ flags ++ [ "--" ];

  paramFlags = s: lib.concatMap (k: [ "-param" "${k}=${s.params.${k}}" ]) (lib.attrNames s.params);

  # A path with at most one {machine}, the session's name, which frisket
  # substitutes itself, and no other brace.
  policyTemplate = types.strMatching "/[^{}]*([{]machine[}][^{}]*)?";
in
{
  imports = [ self.nixosModules.default ];

  options.services.frisket.flong = mkOption {
    default = { };
    description = ''
      frisket sessions for flong launchers, by the launcher's name: every
      session `flong.<name>` starts is steered to frisket before it has any
      egress, and closed when it ends -- by its own trap, or by the next
      launch's sweep if it was killed.
    '';
    type = types.attrsOf (types.submodule {
      options = {
        policy = mkOption {
          type = types.strMatching "[A-Za-z0-9][A-Za-z0-9_.-]*";
          description = ''
            The policy in `services.frisket.policies` frisket serves the
            session under, unless `policyFile` says otherwise.
          '';
        };
        policyFile = mkOption {
          type = types.nullOr policyTemplate;
          default = null;
          example = "/run/user/1000/chase/{machine}/policy.json";
          description = ''
            The path of the policy document the session is served under
            instead of `policy`'s: a document the launcher wrote for this
            session, say. `{machine}` in it is the session's name, which
            frisket substitutes when it steers the session; nothing else is
            special, and a path holding any other brace, or `{machine}` more
            than once, is refused here. It must be absolute, and what it names
            must be under `services.frisket.policyRoots`; one that does not
            read, or does not hold together, fails the launch.
          '';
        };
        set = mkOption {
          type = types.enum [ "all" "service" ];
          default = "all";
          description = ''
            What is steered. `all`: everything, for a sandbox with no network;
            frisket is its only way out. `service`: DNS and frisket's service
            address, for a sandbox with a network of its own (flong's
            `network`), where everything else goes direct.
          '';
        };
        params = mkOption {
          type = types.attrsOf types.str;
          default = { };
          description = ''
            The policy's parameters. `workspace` is always passed, from the
            session's own, and cannot be set here.
          '';
        };
        steering = mkOption {
          type = types.attrs;
          default = { };
          example = { service = { v4 = "192.0.2.53"; }; };
          description = "Further arguments to `lib.steering`: ports, service, dummy, table.";
        };
      };
    });
  };

  config = lib.mkIf (cfg.flong != { }) {
    services.frisket.enable = lib.mkDefault true;

    flong = lib.mapAttrs
      (name: s:
        let file = steeringFile name s; in {
          # The control socket's directory is the one way into a session from
          # outside, and no bind may reach it: a workload that could open the
          # socket would steer sessions, its own included.
          protect = [ (dirOf cfg.controlSocket) ];
          # Listeners, handed over, the rules, and the session's CA in its
          # mount namespace. A failure here ends the session: flong ends a
          # session whose hook exits non-zero.
          postStart = lib.mkMerge [
            (lib.mkBefore [
              (hook "steer" (nsenter ++ nft ++ [
                "-roots"
                config.security.pki.caBundle
                "-steering"
                "${file}"
                "-policy"
                (if s.policyFile != null then s.policyFile else "/etc/frisket/policies/${s.policy}.json")
              ] ++ paramFlags s))
            ])
            # Connectivity, last. It checks the daemon holds this
            # namespace's session and its table is loaded before touching
            # anything.
            (lib.mkAfter [ (hook "connect" (nsenter ++ [ "-steering" "${file}" ])) ])
          ];
          # Keyed on $machine alone, because on the sweep's path that is all
          # there is; and safe for a session that is already gone.
          postStop = [ (hook "close" [ ]) ];
        })
      cfg.flong;

    # A warning and not an assertion: the daemon refuses such a session at
    # launch in any case, and that refusal is worth being able to test.
    warnings = lib.concatLists (lib.mapAttrsToList
      (name: s: lib.optional (! cfg.policies ? ${s.policy})
        "services.frisket.flong.${name}.policy is \"${s.policy}\", which services.frisket.policies does not define: every session it starts will be refused.")
      cfg.flong);

    assertions = lib.concatLists (lib.mapAttrsToList
      (name: s:
        let
          fl = config.flong.${name};
          declared = config.containers.${fl.container} or null;
        in
        [
          {
            assertion = declared != null && declared.privateNetwork;
            message = ''
              services.frisket.flong.${name} steers flong.${name}, whose
              container does not have privateNetwork = true: its sessions share
              the host's network namespace, and steering one would steer the
              host. (frisket steer refuses such a namespace at launch too.)
            '';
          }
          {
            assertion = (s.set == "all") == (fl.network == null);
            message = ''
              services.frisket.flong.${name}: the "all" set is for a session
              with no network -- frisket's dummy interface is its only egress --
              and "service" is for one with flong's `network`, whose egress is
              pasta. flong.${name}.network is ${if fl.network == null then "unset" else "set"} and the set is "${s.set}".
            '';
          }
          {
            assertion = ! (s.params ? workspace);
            message = ''
              services.frisket.flong.${name}.params names `workspace`, which is
              the session's own and always passed.
            '';
          }
        ])
      cfg.flong);
  };
}
