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
# And the machine's CA certificate is bound into every session at
# /etc/frisket/ca.crt, read-only. Which runtimes are told to trust it, and
# how, is the consumer's business.
self:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.frisket;
  inherit (lib) mkOption types;
  control = "-control ${cfg.controlSocket}";

  steeringFile = name: s: pkgs.writeText "frisket-steering-${name}.json"
    (self.lib.steering ({ inherit (s) set; } // s.steering)).json;

  paramFlags = s: lib.concatMapStringsSep " "
    (k: "-param ${lib.escapeShellArg "${k}=${s.params.${k}}"}")
    (lib.attrNames s.params);
in
{
  imports = [ (import ./module.nix self) ];

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
          type = types.str;
          description = "The policy frisket applies to the session. One it does not know fails the launch.";
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
          # frisket itself, and the nft and ip it runs inside the namespace,
          # resolved on the host before it enters.
          path = [ cfg.package pkgs.nftables pkgs.iproute2 ];
          # The daemon's own file, read-only: the workload cannot write it
          # through the bind, and a read-only bind cannot be made writable
          # from inside.
          preStart = ''
            flong-bind ${cfg.caCertificate} /etc/frisket/ca.crt
          '';
          # Listeners, handed over, and the rules. A failure here ends the
          # session: flong kills the scope of a hook that exits non-zero.
          postStart = lib.mkMerge [
            (lib.mkBefore ''
              frisket steer ${control} -netns "$netns" -steering ${file} \
                -name "$machine" -policy ${lib.escapeShellArg s.policy} \
                -param workspace="$workspace" ${paramFlags s}
            '')
            # Connectivity, last. It checks the daemon holds this
            # namespace's session and its table is loaded before touching
            # anything.
            (lib.mkAfter ''
              frisket connect ${control} -netns "$netns" -steering ${file} -name "$machine"
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
