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
# datagram -- nothing steered is NATed, and a datagram's reply can be sent
# from where the client sent it. The one NAT is the `service` set's inbound
# chain, for connections pasta forwards IN, which steering never sees.
#
# The ORDER of the mark chain was arrived at by measurement (PLAN.md,
# "Steering sets"):
#
#   0. frisket's own sockets are never marked: see the `socket transparent`
#      line below.
#   1. DNS first, or a loopback resolver (127.0.0.53, or glibc's 127.0.0.1
#      default) is caught by the local exemption and never steered.
#   2. A Docker project's relayed ports, 127.0.0.1:P, [::1]:P and the
#      project's own address at P, for the same reason: they are local, and
#      the exemption would hand them to a loopback where nothing listens.
#      Their sets are empty here; `frisket steer` fills them from what the
#      daemon answers `open` with, so a session with no Docker route steers
#      exactly what it steered before the sets existed. The same sets carry
#      a session's SSH routes, address and port, which frisket terminates:
#      in `service` nothing else would steer a private address at all, and
#      a route at an address the host owns is local too.
#   3. frisket's service address next, because it is assigned to lo -- so it
#      is "local", and the exemption below would otherwise let it through to
#      nothing.
#   4. The local exemption, so the sandbox's own loopback still works.
#   5. Everything else that is TCP -- in `all`. In `service` with
#      `lan = "frisket"`, only TCP to the structural table's ranges, the
#      private and local-network ones above all; with `lan = "direct"`,
#      nothing more at all.
#
# Other UDP is not marked, and in `all` is REJECTED rather than dropped, so a
# QUIC client fails over to TCP at once instead of hanging (measured). In
# `service` with `lan = "frisket"`, so is UDP to the table's ranges, for the
# same reason.
{ lib }:

{
  # "all": a sandbox with no network; everything is steered, and a dummy
  #        interface is its only egress.
  # "service": a sandbox with its own network (pasta); only DNS and the
  #        service address are steered, and everything else goes direct --
  #        the local network too, unless `lan` says otherwise.
  set ? "all"
, # The local network, in the `service` set: what pasta would otherwise
  # reach directly from the host, every machine on its LAN and the router
  # pasta names the gateway among them (measured: a session reached
  # 10.0.0.4:22, 10.0.0.1:22 and :53, and a ULA address at :22).
  #
  # "direct": as it always was, the default, so no launcher changes
  #        behaviour by taking a newer frisket.
  # "frisket": TCP to the structural table's ranges -- egress.DefaultRanges,
  #        the private, unique-local, link-local, CGNAT and the rest -- is
  #        steered to frisket's TCP listener, so egress decides it exactly as
  #        in `all`: refused structurally, but for a name in the document's
  #        `lan` list at its ports, by an address the session's DNS gave it,
  #        and never the host's routers, its own networks or a metadata
  #        service. UDP to the same ranges is rejected, as `all` rejects
  #        every datagram it does not steer.
  #
  # Meaningless in `all`, where everything is already steered and nothing
  # but loopback is let through: checked, and otherwise ignored there, as
  # `dummy` is in `service`.
  lan ? "direct"
, # The TCP listener's port inside the sandbox: `{ tcp = 230; }`. Below the
  # host's unprivileged floor, so pasta's `auto` never republishes it at the
  # project's address and each session of a project has its own; not 53,
  # which the ruleset steers; and below 512, where bindresvport and
  # rresvport take a privileged SOURCE port. IANA leaves 225-241
  # unassigned. See steering.Plan. There is no DNS port to
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
  p = { tcp = 230; } // ports;
  svc = { v4 = "192.0.2.2"; v6 = "2001:db8::2"; } // service;
  dm = { interface = "frisket0"; v4 = "192.0.2.1"; v6 = "2001:db8::1"; } // dummy;
  tcp = toString p.tcp;
  m = toString mark;

  # FOUR SOCKETS: one TCP and one DNS listener, per family, on loopback. The
  # TCP listener takes every steered connection on its one port; each DNS
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
        ip daddr . tcp dport @relay4 meta mark set ${m} return
        ip6 daddr . tcp dport @relay6 meta mark set ${m} return
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

  # INBOUND TO LOOPBACK, the `service` set's only: a connection pasta
  # forwards in from the host reaches the sandbox at its own address, not its
  # loopback, unless it came by the host's 127.0.0.1 with --host-lo-to-ns-lo,
  # which pasta does for no other host address. So a server that listens on
  # 127.0.0.1 alone -- most dev servers' default -- never sees it. A new TCP
  # connection that pasta brings in is sent to 127.0.0.1 at the same port,
  # by whichever of two ways it came (measured, pasta 2026_07):
  #
  #   - spliced: from a host LOOPBACK address, pasta dials the sandbox's own
  #     address from a socket of its own inside the sandbox, so the
  #     connection is local and only the output hook sees its first packet.
  #     What is marked there is steering's, and 127/8 is loopback already.
  #   - by its tap: from any other host address, the packet arrives by the
  #     sandbox's interface, and the kernel takes 127/8 from there only with
  #     route_localnet, which connect sets in this namespace alone.
  #
  # `dnat`, not `redirect`: redirect goes to the interface's own address,
  # where such a server is not. IPv4 only: IPv6 has no route_localnet, so
  # ::1 cannot be a destination from outside, and a server on ::1 alone is
  # not reached by a forward. Not frisket's own TCP listener's port, which
  # takes only what was steered to it. A workload dialling its own address
  # is sent to its loopback the same way, which is where a server for it
  # usually is anyway.
  inbound = ''
    chain inbound {
        type nat hook prerouting priority dstnat; policy accept;
        iifname != "lo" meta nfproto ipv4 tcp dport != ${tcp} ct state new dnat ip to 127.0.0.1
      }
      chain spliced {
        type nat hook output priority dstnat; policy accept;
        meta mark != ${m} meta nfproto ipv4 ip daddr != 127.0.0.0/8 fib daddr type local tcp dport != ${tcp} ct state new dnat ip to 127.0.0.1
      }'';

  # The relay's destinations, address and port, one set per family: a Docker
  # project's ports, and SSH routes. Only TCP: a published Docker port is
  # relayed as a stream, and a datagram to one is left to the sandbox's own
  # loopback, where nothing answers it.
  relaySets = ''
    set relay4 { type ipv4_addr . inet_service; }
      set relay6 { type ipv6_addr . inet_service; }'';

  # THE STRUCTURAL TABLE, as nft sets, for `lan = "frisket"`: every row of
  # egress.DefaultRanges, written out here because Nix cannot ask Go, and
  # held to it by a Go test (internal/steering, TestTheLANSetsAreTheStructuralTable)
  # over the copy of this file's output the flake's `steering` check holds
  # to lib.steering. The whole table and not only its RFC 1918 rows: CGNAT is
  # a tailnet's, and anything else in it that pasta could reach directly is
  # as much the host's network as a NAS is. Loopback is in it too, for the
  # table's sake, and never reached by it: the local exemption comes first.
  #
  # Not the table's v6 spellings of a v4 address -- NAT64, 6to4, Teredo and
  # the rest, which Classify decodes. Those reach a private address only
  # through a translator on the path, and in `service` they go direct like
  # any other v6 address.
  lanRanges = {
    v4 = [
      "0.0.0.0/8"
      "10.0.0.0/8"
      "100.64.0.0/10"
      "127.0.0.0/8"
      "169.254.0.0/16"
      "172.16.0.0/12"
      "192.168.0.0/16"
      "224.0.0.0/4"
      "240.0.0.0/4"
    ];
    v6 = [
      "::/128"
      "::1/128"
      "fe80::/10"
      "fec0::/10"
      "fc00::/7"
      "ff00::/8"
      "64:ff9b:1::/48"
    ];
  };
  lanSets = ''
    set lan4 { type ipv4_addr; flags interval; elements = { ${lib.concatStringsSep ", " lanRanges.v4} }; }
      set lan6 { type ipv6_addr; flags interval; elements = { ${lib.concatStringsSep ", " lanRanges.v6} }; }'';

  # The `service` set's local network, steered: after everything the chain
  # already marks, so DNS to a resolver on the LAN is still DNS, an SSH
  # route or a Docker port at a private address is still the relay's, and
  # the service address is still interception's; and after a local
  # exemption of its own, because pasta gives the sandbox the HOST'S address
  # -- private, as often as not -- and a connection to it stays inside the
  # sandbox, where the `spliced` chain sends it to 127.0.0.1.
  #
  # `ct direction original`, BECAUSE THIS SET HAS A WAY IN. A connection pasta
  # forwards in from a machine on the LAN arrives from that machine's
  # address, and the sandbox's answer to it -- a SYN-ACK to a private
  # address -- passes this hook too. Marked, it would be handed to
  # frisket's listener, which never saw the SYN, and the forward would
  # die. Only what the sandbox itself began is original; the workload
  # cannot make a connection the other way round.
  lanSteer = ''
    fib daddr type local return
        ct direction original ip daddr @lan4 meta l4proto tcp meta mark set ${m} return
        ct direction original ip6 daddr @lan6 meta l4proto tcp meta mark set ${m} return'';

  # And its datagrams refused, where they would have gone direct: `reject`,
  # not drop, as in `all`, and for the same reason. Not marked ones, which
  # are DNS on its way to frisket; not local ones, the sandbox's own; and
  # not answers to what pasta forwarded in. UDP alone: ICMPv6 to link-local
  # and multicast is neighbour discovery, without which the sandbox has no
  # IPv6 at all.
  lanFilter = ''
    chain lan_filter {
        type filter hook output priority filter; policy accept;
        meta mark ${m} accept
        fib daddr type local accept
        ct direction original ip daddr @lan4 meta l4proto udp reject with icmpx admin-prohibited
        ct direction original ip6 daddr @lan6 meta l4proto udp reject with icmpx admin-prohibited
      }'';
  steersLAN = set == "service" && lan == "frisket";

  rulesets = {
    all = ''
      table inet ${table} {
        ${relaySets}
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
        ${relaySets}${lib.optionalString steersLAN "\n  ${lanSets}"}
        chain steer {
          type route hook output priority mangle; policy accept;
          ${steer}${lib.optionalString steersLAN "\n    ${lanSteer}"}
        }
        ${prerouting}
        ${inbound}${lib.optionalString steersLAN "\n  ${lanFilter}"}
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
  } // lib.optionalAttrs (set == "service") {
    # Said, not only done, so `frisket steering FILE` can print it and check
    # the ruleset has the sets it names.
    inherit lan;
  };
in
assert lib.assertMsg (rulesets ? ${set})
  "lib.steering: set is \"${set}\"; want \"all\" or \"service\"";
assert lib.assertMsg (lib.elem lan [ "direct" "frisket" ])
  "lib.steering: lan is \"${lan}\"; want \"direct\" or \"frisket\"";
assert lib.assertMsg (lib.attrNames ports == [ ] || lib.attrNames ports == [ "tcp" ])
  "lib.steering: ports names ${toString (lib.attrNames ports)}; only `tcp` is a choice -- the DNS listeners answer from port 53";
file // {
  # What `frisket steer` and `frisket connect` read: `frisket steering FILE`
  # checks one and prints what it will do.
  json = builtins.toJSON file;
}
