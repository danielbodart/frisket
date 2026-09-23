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
  control = "-control ${cfg.controlSocket}";
  # steer and connect each enter the session once, under this nsenter, in
  # $userns, the user namespace that owns the session's: the hooks run as the
  # caller, who is root only there. By store path, so no PATH decides which
  # runs.
  enter = "-userns \"$userns\" -nsenter ${lib.getExe' pkgs.util-linux "nsenter"}";

  steeringFile = name: s: pkgs.writeText "frisket-steering-${name}.json"
    (self.lib.steering ({ inherit (s) set; } // s.steering)).json;

  paramFlags = s: lib.concatMapStringsSep " "
    (k: "-param ${lib.escapeShellArg "${k}=${s.params.${k}}"}")
    (lib.attrNames s.params);
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
          type = types.nullOr types.str;
          default = null;
          example = "$(my-launcher-policy \"$workspace\")";
          description = ''
            A shell word, expanded in the launch hook, for the path of the
            policy document the session is served under instead of `policy`'s:
            a document the launcher wrote for this session, say. `$workspace`
            and `$machine` are set. It must name an absolute path; one that
            does not read, or does not hold together, fails the launch.
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
          # frisket itself, and the nft it runs inside the namespace,
          # resolved on the host before it enters.
          path = [ cfg.package pkgs.nftables ];
          # Listeners, handed over, the rules, and the session's CA in its
          # mount namespace. A failure here ends the session: flong ends a
          # session whose hook exits non-zero.
          postStart = lib.mkMerge [
            (lib.mkBefore ''
              frisket steer ${control} ${enter} -netns "$netns" -mntns "/proc/$leader/ns/mnt" \
                -roots ${config.security.pki.caBundle} -steering ${file} \
                -name "$machine" -policy ${if s.policyFile != null then ''"${s.policyFile}"'' else "/etc/frisket/policies/${s.policy}.json"} \
                -param workspace="$workspace" ${paramFlags s}
            '')
            # Connectivity, last. It checks the daemon holds this
            # namespace's session and its table is loaded before touching
            # anything.
            (lib.mkAfter ''
              frisket connect ${control} ${enter} -netns "$netns" -steering ${file} -name "$machine"
            '')
          ];
          # Keyed on $machine alone, because on the sweep's path that is all
          # there is; and safe for a session that is already gone.
          postStop = ''
            frisket close ${control} -name "$machine"
          '';
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
