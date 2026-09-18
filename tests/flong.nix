# frisket in flong's real shape: a launcher from flong's own module, over a
# container with privateNetwork, steered by nixosModules.flong.
#
# Two machines on the test VLAN and nothing else, so no real network is
# needed: `machine` runs frisket and the sessions, `upstream` runs a web server
# and a DNS server on both families. The upstream's addresses are TEST-NET-3
# and a documentation v6 prefix rather than the VLAN's 192.168.1.0/24, because
# the egress policy refuses RFC 1918 structurally.
{ self, flong }:
{ lib, ... }:

let
  upstream4 = "203.0.113.20";
  upstream6 = "2001:db8:113::20";
  url4 = "http://${upstream4}/";
  url6 = "http://[${upstream6}]/";
in
{
  name = "frisket-flong";

  nodes.upstream = { pkgs, ... }: {
    networking.interfaces.eth1.ipv4.addresses = [{ address = upstream4; prefixLength = 24; }];
    networking.interfaces.eth1.ipv6.addresses = [{ address = upstream6; prefixLength = 64; }];
    networking.firewall.enable = false;
    # A DNS server the sandbox can be seen NOT to reach: with frisket's steering
    # in place every query goes to frisket, so a query this logs came round it.
    services.dnsmasq = {
      enable = true;
      resolveLocalQueries = false;
      settings = {
        listen-address = [ upstream4 upstream6 ];
        # dynamic, because the v6 address is still tentative when it starts
        bind-dynamic = true;
        no-resolv = true;
        log-queries = true;
        address = [ "/allowed.test/${upstream4}" "/allowed.test/${upstream6}" ];
      };
    };
    systemd.services.upstream = {
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      # --bind :: is dual-stack in http.server, so one listener answers both
      # families.
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server --bind :: "
        + "--directory ${pkgs.writeTextDir "index.html" "upstream-body\n"} 80";
    };
  };

  nodes.machine = { config, pkgs, ... }: {
    imports = [ flong.nixosModules.default self.nixosModules.flong ];

    virtualisation.memorySize = 3072;
    virtualisation.diskSize = 8192;

    networking.interfaces.eth1.ipv4.addresses = [{ address = "203.0.113.10"; prefixLength = 24; }];
    networking.interfaces.eth1.ipv6.addresses = [{ address = "2001:db8:113::10"; prefixLength = 64; }];

    # Run by root, and as the session's uid inside its namespace, to look at
    # and poke at a session from outside it.
    environment.systemPackages = [ pkgs.nftables pkgs.curl pkgs.dnsutils pkgs.netcat pkgs.iproute2 ];

    # The daemon runs as the user whose credentials it would hold: a person,
    # not a DynamicUser.
    users.users.alice = { isNormalUser = true; uid = 1000; group = "users"; };
    services.frisket = { user = "alice"; group = "users"; };

    systemd.tmpfiles.rules = [ "d /srv/work 0777 root root -" ];

    # What a workload tries against what root installed. In the store, which
    # every session can read, rather than quoted through three shells.
    environment.etc."frisket-tamper".source = pkgs.writeText "tamper.sh" ''
      nft list ruleset >/dev/null 2>&1 && echo listed
      nft flush ruleset >/dev/null 2>&1 && echo flushed
      # -r, so it holds every capability a new user namespace can give.
      unshare -Ur nft list ruleset >/dev/null 2>&1 && echo listed-from-userns
      unshare -Ur nft flush ruleset >/dev/null 2>&1 && echo flushed-from-userns
      echo attempted
      curl -sS -m 5 ${url4}
    '';

    # A session that outlives a daemon restart. It talks to the workspace,
    # which is the one directory the test and the session share.
    environment.etc."frisket-long".source = pkgs.writeText "long.sh" ''
      curl -sS -m 5 ${url4} > before-restart
      touch started
      while [ ! -e go ]; do sleep 0.1; done
      curl -sS -m 5 ${url4} > after-restart
      touch done
      while [ ! -e release ]; do sleep 0.1; done
    '';

    containers.strict = {
      autoStart = false;
      privateNetwork = true;
      config = { pkgs, ... }: {
        system.stateVersion = "24.05";
        users.users.alice = { isNormalUser = true; uid = 1000; group = "users"; home = "/home/alice"; };
        users.groups.users.gid = 100;
        environment.systemPackages = [ pkgs.curl pkgs.nftables pkgs.netcat pkgs.dnsutils ];
      };
    };

    # The session under test: steered, in the `all` set, by the stand-in.
    flong.strict = {
      user = "alice";
      workspace = "realpath /srv/work";
      command = ''set -- bash -c "$1"'';
      # Ahead of frisket's own steps, so the test can find the session.
      attach = lib.mkOrder 100 ''echo "$machine" > /tmp/last-session'';
    };
    services.frisket.flong.strict.policy = "standin";

    # The same container, with a process in the session's namespace -- as
    # the session's uid, from before frisket's hook runs until after it is
    # done -- trying the upstream every 10 ms. With egress deliberately
    # delayed by a second after the rules land, and no barrier of any kind.
    flong.probed = {
      container = "strict";
      user = "alice";
      workspace = "realpath /srv/work";
      command = ''set -- bash -c "$1"'';
      attach = lib.mkMerge [
        (lib.mkOrder 100 ''
          echo "$machine" > /tmp/last-session
          ${pkgs.util-linux}/bin/nsenter --net="$netns" \
            ${pkgs.util-linux}/bin/setpriv --reuid=1000 --regid=100 --clear-groups \
            ${pkgs.writeShellScript "probe" ''
              end=$(( $(${pkgs.coreutils}/bin/date +%s) + 4 ))
              while [ "$(${pkgs.coreutils}/bin/date +%s)" -lt "$end" ]; do
                t=$(${pkgs.coreutils}/bin/date +%s.%N)
                if ${pkgs.curl}/bin/curl -s -m 1 -o /dev/null ${url4}; then
                  echo "$t ok"
                else
                  echo "$t fail"
                fi
                ${pkgs.coreutils}/bin/sleep 0.01
              done
            ''} > "/tmp/probe-$machine" 2>&1 &
          echo $! > "/tmp/probe-pid-$machine"
          # Held until the prober has tried a few times, or steer -- tens of
          # milliseconds -- is done before the first attempt, and "before the
          # rules" is a claim about nothing.
          for _ in $(seq 500); do
            [ "$(wc -l < "/tmp/probe-$machine")" -ge 5 ] && break
            sleep 0.01
          done
        '')
        # After frisket steer (mkBefore), before frisket connect (mkAfter).
        ''
          date +%s.%N > "/tmp/rules-at-$machine"
          sleep 1
          date +%s.%N > "/tmp/connect-at-$machine"
        ''
      ];
      detach = lib.mkAfter ''
        [ -e "/tmp/probe-pid-$machine" ] && kill "$(cat "/tmp/probe-pid-$machine")" 2>/dev/null || true
      '';
    };
    services.frisket.flong.probed.policy = "standin";

    # A policy the daemon does not have. The session must not run.
    flong.badpolicy = {
      container = "strict";
      user = "alice";
      workspace = "realpath /srv/work";
      command = ''set -- bash -c "$1"'';
      attach = lib.mkOrder 100 ''echo "$machine" > /tmp/last-session'';
    };
    services.frisket.flong.badpolicy.policy = "nonesuch";

    # The `service` set: a network of its own, through pasta, with only DNS and
    # the service address steered.
    flong.networked = {
      container = "strict";
      user = "alice";
      workspace = "realpath /srv/work";
      command = ''set -- bash -c "$1"'';
      network = { };
      attach = lib.mkOrder 100 ''echo "$machine" > /tmp/last-session'';
    };
    services.frisket.flong.networked = { policy = "standin"; set = "service"; };
  };

  testScript = { nodes, ... }:
    let
      strict = lib.getExe nodes.machine.flong.strict.launcher;
      probed = lib.getExe nodes.machine.flong.probed.launcher;
      badpolicy = lib.getExe nodes.machine.flong.badpolicy.launcher;
      networked = lib.getExe nodes.machine.flong.networked.launcher;
      frisket = lib.getExe nodes.machine.services.frisket.package;
    in
    ''
      import json
      import re
      import shlex
      import time

      start_all()
      upstream.wait_for_unit("upstream.service")
      upstream.wait_for_unit("dnsmasq.service")
      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("frisket.service")
      # Both families reach the upstream from the host, which is where
      # frisket dials from. v6 waits out duplicate address detection.
      machine.wait_until_succeeds("curl -sSf -m 2 ${url4}")
      machine.wait_until_succeeds("curl -sSf -m 2 -g '${url6}'")
      machine.wait_until_succeeds("dig +short +time=1 +tries=1 allowed.test @${upstream4} | grep -qx ${upstream4}")

      def lines_of(msg, session=None):
          out = machine.succeed("journalctl -u frisket.service -o cat --no-pager")
          lines = []
          for l in out.splitlines():
              try:
                  m = json.loads(l)
              except ValueError:
                  continue
              if m.get("msg") == msg and (session is None or m.get("session") == session):
                  lines.append(m)
          return lines

      def wait_log(msg, session, pred, what):
          for _ in range(100):
              found = [m for m in lines_of(msg, session) if pred(m)]
              if found:
                  return found
              time.sleep(0.1)
          raise AssertionError(f"no {msg} line for {what}: {lines_of(msg, session)}")

      def last_session():
          return machine.succeed("cat /tmp/last-session").strip()

      def sessions():
          out = machine.succeed("${frisket} sessions")
          return [json.loads(l) for l in out.splitlines() if l.strip()]

      def stored():
          return int(machine.succeed("systemctl show -P NFileDescriptorStore frisket.service").strip())

      def main_pid():
          return machine.succeed("systemctl show -P MainPID frisket.service").strip()

      def daemon_fds(pid):
          return int(machine.succeed(f"ls /proc/{pid}/fd | wc -l").strip())

      # A session held open, so a test can act on it from outside -- as root,
      # or as the session's uid inside its network namespace, which for
      # networking is exactly what the workload is. Released by a file in the
      # workspace, which the session and the test share.
      def hold(launcher, ready):
          machine.succeed("rm -f /srv/work/release /tmp/last-session")
          machine.succeed(f"{launcher} 'while [ ! -e release ]; do sleep 0.1; done' >/tmp/hold.out 2>&1 &")
          machine.wait_until_succeeds("test -s /tmp/last-session")
          name = last_session()
          machine.wait_until_succeeds(f"machinectl show {name} -P Leader")
          leader = machine.succeed(f"machinectl show {name} -P Leader").strip()
          machine.wait_until_succeeds(as_root(leader, ready))
          return name, leader

      def release(name):
          machine.succeed("touch /srv/work/release")
          machine.wait_until_fails(f"machinectl show {name}")

      def as_root(leader, cmd):
          return f"nsenter --net=/proc/{leader}/ns/net sh -c {shlex.quote(cmd)}"

      def as_workload(leader, cmd):
          return (f"nsenter --net=/proc/{leader}/ns/net setpriv --reuid=1000 --regid=100 "
                  f"--clear-groups -- sh -c {shlex.quote(cmd)}")

      def handle(leader, chain, pattern):
          out = machine.succeed(as_root(leader, f"nft -a list chain inet frisket {chain}"))
          for l in out.splitlines():
              h = re.search(r"# handle (\d+)", l)
              if h and re.search(pattern, l):
                  return h.group(1)
          raise AssertionError(f"no rule matching {pattern} in {chain}: {out}")

      def timed(cmd):
          t = time.monotonic()
          status, out = machine.execute(cmd)
          return status, out, time.monotonic() - t

      with subtest("the daemon runs as its user, hardened, behind a socket only root can use"):
          props = machine.succeed(
              "systemctl show -p User -p DynamicUser -p ProtectSystem -p NotifyAccess "
              "-p FileDescriptorStorePreserve frisket.service")
          for want in ["User=alice", "DynamicUser=no", "ProtectSystem=strict",
                       "NotifyAccess=main", "FileDescriptorStorePreserve=restart"]:
              assert want in props, props
          assert machine.succeed("stat -c '%U %a' /run/frisket/control.sock").strip() == "root 600"
          # Not even the daemon's own user.
          machine.fail("su alice -s /bin/sh -c '${frisket} sessions'")
          assert stored() == 0

      with subtest("a session is steered, and every connection logged once with where it was going"):
          out = machine.succeed("${strict} 'curl -sS -m 5 ${url4}; curl -sS -m 5 -g \"${url6}\"'")
          assert out.count("upstream-body") == 2, out
          name = last_session()
          for dst in ["${upstream4}:80", "[${upstream6}]:80"]:
              [e] = wait_log("egress", name, lambda m: m["dst"] == dst, dst)
              assert e["action"] == "spliced" and e["bytes_in"] > 0, e
          # Exactly one line per connection: the handler's. steer writes one
          # only for what it refuses.
          assert len(lines_of("egress", name)) == 2, lines_of("egress", name)
          assert lines_of("connection", name) == [], lines_of("connection", name)
          # And the session is gone with the launcher: flong's detach closed it.
          assert [s for s in sessions() if s["name"] == name] == []
          [closed] = wait_log("session closed", name, lambda m: True, "close")
          assert closed["descriptors"] == 5, closed

      with subtest("nothing is reachable before the rules land, and everything after is steered"):
          machine.succeed("${probed} 'sleep 4'")
          name = last_session()
          # The prober is done: it stops by itself four seconds in, and the
          # session's teardown stops it if it has not.
          machine.wait_until_fails(f"kill -0 $(cat /tmp/probe-pid-{name})")
          rules_at = float(machine.succeed(f"cat /tmp/rules-at-{name}"))
          connect_at = float(machine.succeed(f"cat /tmp/connect-at-{name}"))
          probes = [(float(t), r) for t, r in
                    (l.split() for l in machine.succeed(f"cat /tmp/probe-{name}").splitlines())]
          before = [r for t, r in probes if t < rules_at]
          waiting = [r for t, r in probes if rules_at <= t < connect_at]
          ok = [t for t, r in probes if r == "ok"]
          # Attempts were made before the rules existed and while the rules
          # existed but egress did not, and every one of them failed.
          assert len(before) > 0 and set(before) == {"fail"}, probes
          assert len(waiting) > 10 and set(waiting) == {"fail"}, probes
          # Egress arrived, and not one attempt got through before the rules.
          assert ok and min(ok) >= rules_at, (rules_at, probes)
          # And every one that got through, frisket saw.
          lines = lines_of("egress", name)
          assert len([m for m in lines if m["action"] == "spliced"]) == len(ok), (lines, len(ok))
          assert all(m["dst"] == "${upstream4}:80" for m in lines), lines

      name, leader = hold("${strict}", "ip link show frisket0")

      with subtest("the policy routing is in place, both families"):
          for fam in ["-4", "-6"]:
              rules = machine.succeed(as_root(leader, f"ip {fam} rule show"))
              assert re.search(r"fwmark 0x1 lookup 100", rules), rules
              routes = machine.succeed(as_root(leader, f"ip {fam} route show table 100"))
              assert routes.startswith("local default dev lo"), routes

      with subtest("DNS to the loopback resolvers is answered, as it is to anywhere else"):
          # 127.0.0.1:53 and [::1]:53 are the DNS listeners' own addresses:
          # glibc's default resolver, answered because the datagram carries
          # the ruleset's mark, whatever its address. dig takes an answer only
          # from the address it asked, so an answer is also the reply's
          # source being right.
          for server in ["127.0.0.1", "::1", "${upstream4}", "${upstream6}", "127.0.0.53"]:
              out = machine.succeed(as_workload(leader, f"dig +time=2 +tries=1 example.com @{server}"))
              assert "status: REFUSED" in out, (server, out)
              assert f"SERVER: {server}#53" in out, (server, out)
          dsts = {m["dst"] for m in lines_of("dns", name) if m["transport"] == "udp"}
          for dst in ["127.0.0.1:53", "[::1]:53", "${upstream4}:53", "[${upstream6}]:53", "127.0.0.53:53"]:
              assert dst in dsts, (dst, dsts)
          # None of it went anywhere near the upstream's DNS server.
          upstream.fail("journalctl -u dnsmasq -o cat | grep -q example.com")

      with subtest("DNS over TCP is answered by frisket, not a port nobody holds"):
          for server in ["${upstream4}", "127.0.0.1", "::1"]:
              out = machine.succeed(as_workload(leader, f"dig +tcp +time=2 +tries=1 example.com @{server}"))
              assert "status: REFUSED" in out, (server, out)
          tcp = [m for m in lines_of("dns", name) if m["transport"] == "tcp"]
          assert {m["dst"] for m in tcp} >= {"${upstream4}:53", "127.0.0.1:53", "[::1]:53"}, tcp
          assert all(m["queries"] == 1 for m in tcp), tcp

      with subtest("the service address on 443 reaches interception, both families"):
          for url in ["https://192.0.2.2/", "https://[2001:db8::2]/"]:
              machine.execute(as_workload(leader, f"curl -sk -m 5 -g {url}"))
          dsts = {m["dst"] for m in lines_of("intercept", name)}
          assert dsts == {"192.0.2.2:443", "[2001:db8::2]:443"}, dsts

      with subtest("without `socket transparent 1 return`, frisket's own replies are steered back to it"):
          # The proof that the line is load-bearing: frisket's SYN-ACK from
          # the service address is marked, turned back onto lo and handed to
          # the listener, and the client never connects.
          h = handle(leader, "steer", r"socket transparent")
          machine.succeed(as_root(leader, f"nft delete rule inet frisket steer handle {h}"))
          before = len(lines_of("intercept", name))
          status, out, _ = timed(as_workload(leader, "curl -sk -m 3 https://192.0.2.2/"))
          assert status != 0, (status, out)
          time.sleep(1)
          assert len(lines_of("intercept", name)) == before, lines_of("intercept", name)
          machine.succeed(as_root(leader, "nft insert rule inet frisket steer socket transparent 1 return"))
          machine.execute(as_workload(leader, "curl -sk -m 5 https://192.0.2.2/"))
          assert len(lines_of("intercept", name)) == before + 1

      with subtest("a direct connection to a listener is refused, and logged"):
          machine.execute(as_workload(leader, "nc -w 2 127.0.0.1 15001 </dev/null; nc -w 2 ::1 15001 </dev/null"))
          for listener in ["127.0.0.1:15001", "[::1]:15001"]:
              [c] = wait_log("connection", name, lambda m: m["listener"] == listener, listener)
              assert c["decision"] == "unsteered" and c["action"] == "refused", c
              assert c["reason"] == "listener's own address", c

      with subtest("a datagram the ruleset did not steer is refused, and logged"):
          # Every datagram to port 53 is steered, so the workload has no way
          # to send one that is not -- this takes the rule away, from outside,
          # and shows that what arrives without the mark is refused rather
          # than answered: DNS fails closed, and says so.
          machine.succeed(as_root(leader, "nft insert rule inet frisket steer udp dport 53 return"))
          machine.fail(as_workload(leader, "dig +time=2 +tries=1 example.com @127.0.0.1"))
          [d] = wait_log("datagram", name, lambda m: True, "the unmarked datagram")
          assert d["decision"] == "unsteered" and d["reason"] == "not marked by the ruleset", d
          assert d["dst"] == "127.0.0.1:53" and d["mark"] == 0, d
          h = handle(leader, "steer", r"^\s*udp dport 53 return")
          machine.succeed(as_root(leader, f"nft delete rule inet frisket steer handle {h}"))

      with subtest("a steered packet with no socket to take it is refused at once, not dropped"):
          machine.succeed(f"${frisket} close -name {name}")
          # TCP, both families. A datagram's ICMP error fails a connected
          # client as fast (measured), but dig does not act on one -- it waits
          # out its own timeout either way -- so it proves nothing here.
          for cmd in ["curl -sS -m 5 ${url4}", "curl -sS -m 5 -g '${url6}'"]:
              status, out, took = timed(as_workload(leader, cmd))
              assert status != 0 and status != 28 and took < 2, (cmd, status, out, took)
          # And with the rejects made drops, the client hangs: the proof that
          # it is the rejects, and not the missing socket, that fail it fast.
          for pattern in [r"reject with tcp reset", r"reject with icmpx"]:
              h = handle(leader, "pre", pattern)
              machine.succeed(as_root(leader, f"nft replace rule inet frisket pre handle {h} drop"))
          status, out, took = timed(as_workload(leader, "curl -sS -m 3 ${url4}"))
          assert status == 28, (status, out, took)

      release(name)

      with subtest("the `service` set: DNS and the service address are steered, the rest goes direct"):
          name, leader = hold("${networked}", "ip route show default | grep -q .")
          out = machine.succeed(as_workload(leader, "curl -sS -m 5 ${url4}"))
          assert "upstream-body" in out, out
          assert lines_of("egress", name) == [], lines_of("egress", name)
          out = machine.succeed(as_workload(leader, "dig +time=2 +tries=1 allowed.test @${upstream4}"))
          assert "status: REFUSED" in out, out
          wait_log("dns", name, lambda m: m["dst"] == "${upstream4}:53", "the steered query")
          for fam in ["-4", "-6"]:
              assert re.search(r"fwmark 0x1 lookup 100", machine.succeed(as_root(leader, f"ip {fam} rule show")))

      with subtest("without the policy routing the `service` set fails closed, because of the guard"):
          machine.succeed(as_root(leader, "ip -4 rule del fwmark 1 lookup 100"))
          before = len(lines_of("dns", name))
          machine.fail(as_workload(leader, "dig +time=2 +tries=1 guarded.allowed.test @${upstream4}"))
          assert len(lines_of("dns", name)) == before
          upstream.fail("journalctl -u dnsmasq -o cat | grep -q guarded.allowed.test")
          # The proof that the guard is what closed it: without it too, the
          # query leaves through pasta and the upstream answers it directly.
          h = handle(leader, "guard", r"oifname")
          machine.succeed(as_root(leader, f"nft delete rule inet frisket guard handle {h}"))
          out = machine.succeed(as_workload(leader, "dig +short +time=2 +tries=1 leaked.allowed.test @${upstream4}"))
          assert out.strip() == "${upstream4}", out
          upstream.succeed("journalctl -u dnsmasq -o cat | grep -q leaked.allowed.test")
          release(name)

      with subtest("the workload cannot list the ruleset, even after unshare -U"):
          out = machine.succeed("${strict} \"bash $(readlink -f /etc/frisket-tamper)\" 2>&1")
          lines = out.split()
          assert "attempted" in lines, out
          for bad in ["listed", "flushed", "listed-from-userns", "flushed-from-userns"]:
              assert bad not in lines, out
          # And it is still steered afterwards.
          assert "upstream-body" in out, out

      with subtest("a session with a policy the daemon does not have never runs"):
          err = machine.fail("${badpolicy} 'echo ran' 2>&1")
          assert "ran" not in err.split(), err
          assert "nonesuch" in err, err
          name = last_session()
          wait_log("session refused", name, lambda m: True, "the refusal")
          assert [s for s in sessions() if s["name"] == name] == []
          assert stored() == 0

      with subtest("a session survives the daemon restarting, through the fd store"):
          machine.succeed("rm -f /srv/work/*")
          machine.succeed("${strict} \"bash $(readlink -f /etc/frisket-long)\" >/tmp/long.out 2>&1 &")
          machine.wait_until_succeeds("test -e /srv/work/started")
          name = last_session()
          [s] = [s for s in sessions() if s["name"] == name]
          assert s["descriptors"] == 5 and not s["restored"], s
          assert stored() == 5
          # Root, from outside, still sees what the workload could not list.
          leader = machine.succeed(f"machinectl show {name} -P Leader").strip()
          machine.succeed(f"nsenter --net=/proc/{leader}/ns/net nft list table inet frisket")

          first = main_pid()
          # Twice, so the store is shown to be kept rather than handed over
          # once and lost.
          for _ in range(2):
              machine.succeed("systemctl restart frisket.service")
              machine.wait_for_unit("frisket.service")
          assert main_pid() != first
          assert len(wait_log("session restored", name, lambda m: True, "restore")) >= 2
          [s] = [s for s in sessions() if s["name"] == name]
          assert s["restored"] and s["descriptors"] == 5, s
          assert stored() == 5

          machine.succeed("touch /srv/work/go")
          machine.wait_until_succeeds("test -e /srv/work/done")
          assert "upstream-body" in machine.succeed("cat /srv/work/before-restart")
          assert "upstream-body" in machine.succeed("cat /srv/work/after-restart")
          # One connection before the restarts, one after, both logged.
          assert len(lines_of("egress", name)) == 2, lines_of("egress", name)

      with subtest("closing a session closes every descriptor it held"):
          pid = main_pid()
          held = daemon_fds(pid)
          machine.succeed("touch /srv/work/release")
          machine.wait_until_fails(f"machinectl show {name}")
          machine.wait_until_succeeds(f"! ${frisket} sessions | grep -q {name}")
          assert stored() == 0, stored()
          assert daemon_fds(pid) == held - 5, (held, daemon_fds(pid))
          [closed] = wait_log("session closed", name, lambda m: True, "close")
          assert closed["descriptors"] == 5, closed
    '';
}
