# lib.steering: the ruleset AND the listener specification, from ONE attrset,
# so the ports the rules redirect to and the ports the listeners are bound to
# cannot drift apart. Any launcher can use it; nixosModules.flong is one.
#
#   (frisket.lib.steering { set = "all"; }).json   -> what `frisket steer` reads
#
# The ORDER inside the NAT chain is load-bearing and was arrived at by
# experiment, not reasoning (PLAN.md, "Redirect sets"):
#
#   1. DNS first, or a loopback resolver (127.0.0.53, or glibc's 127.0.0.1
#      default) is caught by the local exemption and never steered.
#   2. frisket's service address next, because it is assigned to lo -- so it
#      is "local", and the exemption below would otherwise let it through to
#      nothing.
#   3. The local exemption, so the sandbox's own loopback still works.
#   4. Everything else that is TCP, to the TCP listener.
#
# And the filter chain matches `fib daddr type local`, NOT `oifname "lo"`:
# after an output-path redirect `meta oif` is still the pre-NAT device, so the
# obvious rule silently drops every redirected DNS query. Other UDP is REJECTED
# rather than dropped, so a QUIC client fails over to TCP at once instead of
# hanging (measured).
{ lib }:

{
  # "all": a sandbox with no network; everything is steered, and a dummy
  #        interface is its only egress.
  # "service": a sandbox with its own network (pasta); only DNS and the
  #        service address are steered, and everything else goes direct.
  set ? "all"
, # The listeners' ports inside the sandbox. High, so nothing binds a
  # privileged port; nftables sends 53, 80 and 443 to them.
  ports ? { }
, # frisket's service address, one per family. Overrides merge.
  #
  # Documentation ranges (RFC 5737 TEST-NET-1, RFC 3849), because they are
  # never routed: in the `service` set the sandbox has a real network, and the
  # address is assigned to lo, where it shadows whatever real host has it. A
  # range nobody uses shadows nobody.
  #
  # Deliberately NOT 169.254.169.254: a 404 at the cloud metadata address
  # breaks Azure's credential chain outright (PLAN.md). NOT 169.254.1.1 or
  # 100::1 either, which are pasta's DNS forwarding addresses in flong's
  # `network` -- the port-53 redirect runs first, so DNS to them reaches
  # frisket anyway, but two mechanisms sharing an address would be two
  # mechanisms nobody can tell apart in a log. And not link-local, which is
  # never picked as a source for a global destination.
  service ? { }
, # The `all` set's dummy interface. It needs a NON-LINK-LOCAL address per
  # family, beside its default routes: with a route alone IPv4 picks source
  # 0.0.0.0 and the client resets, and IPv6 hangs until timeout (measured).
  dummy ? { }
, table ? "frisket"
}:

let
  p = { tcp = 15001; dns = 15353; } // ports;
  svc = { v4 = "192.0.2.2"; v6 = "2001:db8::2"; } // service;
  dm = { interface = "frisket0"; v4 = "192.0.2.1"; v6 = "2001:db8::1"; } // dummy;
  tcp = toString p.tcp;
  dns = toString p.dns;

  # FOUR SOCKETS: one TCP and one DNS listener, per family. On loopback,
  # because an output-path `redirect` sends to the loopback address of the
  # packet's family -- a listener anywhere else is never reached.
  listeners = [
    "tcp4:127.0.0.1:${tcp}"
    "tcp6:[::1]:${tcp}"
    "udp4:127.0.0.1:${dns}"
    "udp6:[::1]:${dns}"
  ];

  steerToFrisket = ''
    meta l4proto { tcp, udp } th dport 53 redirect to :${dns}
        ip daddr ${svc.v4} meta l4proto tcp redirect to :${tcp}
        ip6 daddr ${svc.v6} meta l4proto tcp redirect to :${tcp}'';

  rulesets = {
    all = ''
      table inet ${table} {
        chain out_nat {
          type nat hook output priority dstnat; policy accept;
          ${steerToFrisket}
          fib daddr type local return
          meta l4proto tcp redirect to :${tcp}
        }
        chain out_filter {
          type filter hook output priority filter; policy drop;
          fib daddr type local accept
          reject with icmpx admin-prohibited
        }
      }
    '';
    service = ''
      table inet ${table} {
        chain out_nat {
          type nat hook output priority dstnat; policy accept;
          ${steerToFrisket}
        }
      }
    '';
  };

  file = {
    inherit set table listeners;
    ruleset = rulesets.${set};
    service = [ svc.v4 svc.v6 ];
  } // lib.optionalAttrs (set == "all") {
    dummy = { inherit (dm) interface; addresses = [ dm.v4 dm.v6 ]; };
  };
in
assert lib.assertMsg (rulesets ? ${set})
  "lib.steering: set is \"${set}\"; want \"all\" or \"service\"";
file // {
  # What `frisket steer` and `frisket connect` read: `frisket steering FILE`
  # checks one and prints what it will do.
  json = builtins.toJSON file;
}
