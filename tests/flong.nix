# frisket in flong's real shape: a launcher from flong's own module, over a
# container with privateNetwork, steered by nixosModules.flong.
#
# Two machines on the test VLAN and nothing else, so no real network is
# needed: `machine` runs frisket and the sessions, `upstream` runs a web server
# on both families. The upstream's addresses are TEST-NET-3 and a documentation
# v6 prefix rather than the VLAN's 192.168.1.0/24, because the egress policy
# that replaces the stand-in refuses RFC 1918 structurally, and this test
# should keep meaning something after it lands.
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

    environment.systemPackages = [ pkgs.nftables pkgs.curl ];

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
  };

  testScript = { nodes, ... }:
    let
      strict = lib.getExe nodes.machine.flong.strict.launcher;
      probed = lib.getExe nodes.machine.flong.probed.launcher;
      badpolicy = lib.getExe nodes.machine.flong.badpolicy.launcher;
      frisket = lib.getExe nodes.machine.services.frisket.package;
    in
    ''
      import json
      import time

      start_all()
      upstream.wait_for_unit("upstream.service")
      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("frisket.service")
      # Both families reach the upstream from the host, which is where
      # frisket dials from. v6 waits out duplicate address detection.
      machine.wait_until_succeeds("curl -sSf -m 2 ${url4}")
      machine.wait_until_succeeds("curl -sSf -m 2 -g '${url6}'")

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

      with subtest("a session is steered, and every connection logged with where it was going"):
          out = machine.succeed("${strict} 'curl -sS -m 5 ${url4}; curl -sS -m 5 -g \"${url6}\"'")
          assert out.count("upstream-body") == 2, out
          name = last_session()
          for dst, listener in [("${upstream4}:80", "127.0.0.1:15001"),
                                ("[${upstream6}]:80", "[::1]:15001")]:
              [c] = wait_log("connection", name, lambda m: m["dst"] == dst, dst)
              assert c["listener"] == listener, c
              assert c["decision"] == "steered" and c["action"] == "accepted", c
              [e] = wait_log("egress", name, lambda m: m["dst"] == dst, dst)
              assert e["action"] == "spliced" and e["bytes_in"] > 0, e
          # Exactly one line per connection, and the session is gone with the
          # launcher: flong's detach closed it.
          assert len(lines_of("connection", name)) == 2, lines_of("connection", name)
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
          lines = lines_of("connection", name)
          assert len(lines) == len(ok), (len(lines), len(ok))
          assert all(m["dst"] == "${upstream4}:80" and m["decision"] == "steered" for m in lines), lines

      # Reaches frisket, and no further, today. MEASURED HERE: a redirected
      # datagram's IP_ORIGDSTADDR is the POST-NAT address -- the listener's own
      # -- so steer.ServePacket classifies every one "listener's own address"
      # and refuses it before any DNS handler sees it. Asserted only as far as
      # the line; what a datagram's destination should be is still open.
      with subtest("DNS reaches frisket"):
          machine.succeed("${strict} 'dig +time=2 +tries=1 example.com @${upstream4} || true'")
          name = last_session()
          [d] = wait_log("datagram", name, lambda m: True, "a DNS query")
          assert d["listener"] == "127.0.0.1:15353", d
          print(f"DNS datagram as frisket logged it: {d}")

      with subtest("the workload cannot list the ruleset, even after unshare -U"):
          out = machine.succeed("${strict} \"bash $(readlink -f /etc/frisket-tamper)\" 2>&1")
          lines = out.split()
          assert "attempted" in lines, out
          for bad in ["listed", "flushed", "listed-from-userns", "flushed-from-userns"]:
              assert bad not in lines, out
          # And it is still steered afterwards.
          assert "upstream-body" in out, out

      with subtest("a direct connection to a listener is refused as unsteered"):
          machine.succeed("${strict} 'nc -w 2 127.0.0.1 15001 </dev/null; nc -w 2 ::1 15001 </dev/null; true'")
          name = last_session()
          for listener in ["127.0.0.1:15001", "[::1]:15001"]:
              [c] = wait_log("connection", name, lambda m: m["listener"] == listener, listener)
              assert c["decision"] == "unsteered" and c["action"] == "refused", c
          assert lines_of("egress", name) == [], lines_of("egress", name)

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
          assert len(lines_of("connection", name)) == 2, lines_of("connection", name)

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
