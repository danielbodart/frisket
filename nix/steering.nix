# lib.steering: the ruleset AND the listener specification, from ONE attrset,
# so the ports and the mark the rules name and the ones the listeners and the
# daemon use cannot drift apart. Any launcher can use it; nixosModules.flong is
# one.
#
#   (frisket.lib.steering { set = "all"; }).json   -> what `frisket steer` reads
#
# TPROXY, NOT NAT. The output hook MARKS what is to be steered; a policy-routing
# rule (installed by `frisket steer` from `mark` and `routeTable`) turns a marked
# packet back onto lo; and prerouting's `tproxy` hands it to frisket's
# transparent socket without touching its destination. So the kernel keeps the
# address the client dialled -- getsockname for TCP, IP_ORIGDSTADDR for a
# datagram -- there is no NAT and no conntrack entry in the sandbox, and a
# datagram's reply can be sent from where the client sent it.
#
# The ORDER of the mark chain was arrived at by measurement (PLAN.md,
# "Steering sets"):
#
#   0. frisket's own sockets are never marked: see the `socket transparent`
#      line below.
#   1. DNS first, or a loopback resolver (127.0.0.53, or glibc's 127.0.0.1
#      default) is caught by the local exemption and never steered.
#   2. frisket's service address next, because it is assigned to lo -- so it
#      is "local", and the exemption below would otherwise let it through to
#      nothing.
#   3. The local exemption, so the sandbox's own loopback still works.
#   4. Everything else that is TCP.
#
# Other UDP is not marked, and in `all` is REJECTED rather than dropped, so a
# QUIC client fails over to TCP at once instead of hanging (measured).
{ lib }:

{
  # "all": a sandbox with no network; everything is steered, and a dummy
  #        interface is its only egress.
  # "service": a sandbox with its own network (pasta); only DNS and the
  #        service address are steered, and everything else goes direct.
  set ? "all"
, # The TCP listener's port inside the sandbox: `{ tcp = 15001; }`. High, and
  # never one the ruleset steers -- see steering.Plan. There is no DNS port to
  # choose: a UDP listener answers FROM its own port, so it is bound on 53.
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
  # `network` -- DNS is steered first, so DNS to them reaches frisket anyway,
  # but two mechanisms sharing an address would be two mechanisms nobody can
  # tell apart in a log. And not link-local, which is never picked as a source
  # for a global destination.
  service ? { }
, # The `all` set's dummy interface. It needs a NON-LINK-LOCAL address per
  # family, beside its default routes: with a route alone IPv4 picks source
  # 0.0.0.0 and the client resets, and IPv6 hangs until timeout (measured).
  dummy ? { }
, table ? "frisket"
, # The firewall mark on everything steered, and the routing table a marked
  # packet is looked up in. The daemon serves a datagram only if it carries the
  # mark, so the two travel together in the steering file.
  mark ? 1
, routeTable ? 100
}:

let
  p = { tcp = 15001; } // ports;
  svc = { v4 = "192.0.2.2"; v6 = "2001:db8::2"; } // service;
  dm = { interface = "frisket0"; v4 = "192.0.2.1"; v6 = "2001:db8::1"; } // dummy;
  tcp = toString p.tcp;
  m = toString mark;

  # FOUR SOCKETS: one TCP and one DNS listener, per family, on loopback. The
  # TCP listener takes every steered connection on its high port; each DNS
  # listener is on 53, because PKTINFO sets a reply's source ADDRESS and not
  # its port -- measured, a listener on :15353 answering a query to :5353 sent
  # without error and the client timed out.
  listeners = [
    "tcp4:127.0.0.1:${tcp}"
    "tcp6:[::1]:${tcp}"
    "udp4:127.0.0.1:53"
    "udp6:[::1]:53"
  ];

  # What to steer, in order. `return` after each mark, so a packet is marked
  # once and the rest of the chain is not consulted.
  #
  # `socket transparent 1 return` FIRST, AND IT IS LOAD-BEARING. frisket's own
  # replies -- a SYN-ACK from the service address, an answer from 8.8.8.8:53 --
  # are sent from its transparent sockets inside this namespace, so they pass
  # through this same output hook. A reply from the service address to the
  # service address matches the rule below, would be marked, re-routed to lo
  # and handed back to the listener, and the client never sees it. Measured:
  # without this line TCP to 192.0.2.2:443 timed out; with it, it connected.
  # The workload cannot make a transparent socket (IP_TRANSPARENT needs
  # CAP_NET_ADMIN over the namespace), so nothing of its escapes by this rule.
  steer = ''
    socket transparent 1 return
        meta l4proto { tcp, udp } th dport 53 meta mark set ${m} return
        ip daddr ${svc.v4} meta l4proto tcp meta mark set ${m} return
        ip6 daddr ${svc.v6} meta l4proto tcp meta mark set ${m} return'';

  # Where a marked packet goes, once policy routing has turned it onto lo.
  # tproxy assigns it to the socket at that address -- only a transparent one;
  # nft_tproxy skips any other -- and leaves the destination alone.
  #
  # ENDS IN REJECT, NOT DROP. A marked packet with no socket to take it -- a
  # session the daemon closed, a daemon that restarted without its store --
  # falls through to here, and a drop leaves the client hanging until its own
  # timeout. `reject with icmpx admin-prohibited` fails a datagram at once
  # (measured: "permission denied" in 0.00 s), but NOT a TCP connect: the SYN's
  # ICMP error left curl waiting out its 3 s timeout over IPv4 and failing after
  # a retransmit, ~1 s, over IPv6. A reset fails both in under 10 ms (measured),
  # so TCP gets one first.
  prerouting = ''
    chain pre {
        type filter hook prerouting priority mangle; policy accept;
        meta mark != ${m} return
        meta nfproto ipv4 meta l4proto tcp tproxy ip to 127.0.0.1:${tcp} accept
        meta nfproto ipv6 meta l4proto tcp tproxy ip6 to [::1]:${tcp} accept
        meta nfproto ipv4 udp dport 53 tproxy ip to 127.0.0.1:53 accept
        meta nfproto ipv6 udp dport 53 tproxy ip6 to [::1]:53 accept
        meta l4proto tcp reject with tcp reset
        reject with icmpx admin-prohibited
      }'';

  # THE GUARD: nothing marked leaves by any interface but lo. A marked packet
  # only reaches lo because of the policy-routing rule; without the rule it
  # follows the ordinary routes, and in the `service` set that is out through
  # pasta, unsteered. Measured: with the rule deleted, a steered DNS query left
  # through the sandbox's own network; with this in place it was refused at
  # send ("operation not permitted"), and with the rule restored DNS was
  # answered again. In `all` it costs nothing: the dummy goes nowhere anyway.
  guard = ''
    chain guard {
        type filter hook postrouting priority filter; policy accept;
        meta mark ${m} oifname != "lo" drop
      }'';

  rulesets = {
    all = ''
      table inet ${table} {
        chain steer {
          type route hook output priority mangle; policy accept;
          ${steer}
          fib daddr type local return
          meta l4proto tcp meta mark set ${m} return
        }
        ${prerouting}
        # Everything that is neither marked nor local is refused. `meta mark`
        # first: a marked packet's route is lo, but it is not addressed to a
        # local address, and the local rule would not let it through.
        chain out_filter {
          type filter hook output priority filter; policy drop;
          meta mark ${m} accept
          fib daddr type local accept
          reject with icmpx admin-prohibited
        }
        ${guard}
      }
    '';
    service = ''
      table inet ${table} {
        chain steer {
          type route hook output priority mangle; policy accept;
          ${steer}
        }
        ${prerouting}
        ${guard}
      }
    '';
  };

  file = {
    inherit set table listeners mark routeTable;
    ruleset = rulesets.${set};
    service = [ svc.v4 svc.v6 ];
  } // lib.optionalAttrs (set == "all") {
    dummy = { inherit (dm) interface; addresses = [ dm.v4 dm.v6 ]; };
  };
in
assert lib.assertMsg (rulesets ? ${set})
  "lib.steering: set is \"${set}\"; want \"all\" or \"service\"";
assert lib.assertMsg (lib.attrNames ports == [ ] || lib.attrNames ports == [ "tcp" ])
  "lib.steering: ports names ${toString (lib.attrNames ports)}; only `tcp` is a choice -- the DNS listeners answer from port 53";
file // {
  # What `frisket steer` and `frisket connect` read: `frisket steering FILE`
  # checks one and prints what it will do.
  json = builtins.toJSON file;
}
