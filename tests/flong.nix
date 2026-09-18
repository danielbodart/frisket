# frisket in flong's real shape: a launcher from flong's own module, over a
# container with privateNetwork, steered by nixosModules.flong.
#
# Two machines on the test VLAN and nothing else, so no real network is
# needed: `machine` runs frisket and the sessions, `upstream` runs web servers
# -- HTTP, and HTTPS under a CA of its own -- and a DNS server, on both
# families. The upstream's addresses are TEST-NET-3 and a documentation v6
# prefix rather than the VLAN's 192.168.1.0/24, because the egress policy
# refuses RFC 1918 structurally.
#
# The policy under test is generic: one allowed name spliced through, and one
# intercepted name whose route adds a bearer token read from a file on the
# host. No tool's route is here; each is designed on its own.
{ self, flong }:
{ lib, hostPkgs, ... }:

let
  pkgs = hostPkgs;
  upstream4 = "203.0.113.20";
  upstream6 = "2001:db8:113::20";
  url4 = "http://${upstream4}/";
  url6 = "http://[${upstream6}]/";

  # The upstream's own CA and a certificate for both its names. In the store,
  # key and all: they are a test's, and trusted by nothing but this test.
  certs = pkgs.runCommand "frisket-test-upstream-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out && cd $out
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
      -keyout ca.key -out ca.crt -subj /CN=frisket-test-upstream-ca \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout server.key -out server.csr -subj /CN=api.test
    printf '%s\n' 'subjectAltName=DNS:api.test,DNS:allowed.test' 'extendedKeyUsage=serverAuth' > ext
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -days 3650 -extfile ext -out server.crt
  '';

  # Says what it was asked, and with which Authorization, in its own journal
  # -- never in its answer, which goes back into the sandbox.
  https = pkgs.writeText "https.py" ''
    import http.server, socket, ssl
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            auth = self.headers.get("Authorization", "-")
            print(f"upstream-request {self.command} {self.headers.get('Host')} {self.path} auth={auth}", flush=True)
            body = b"upstream-api-ok\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a):
            pass
    class S(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6
        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            super().server_bind()
    srv = S(("::", 443), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("${certs}/server.crt", "${certs}/server.key")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()
  '';
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
        address = [
          "/allowed.test/${upstream4}"
          "/allowed.test/${upstream6}"
          "/api.test/${upstream4}"
          "/api.test/${upstream6}"
          "/denied.test/${upstream4}"
          # On no allowlist: only a policy that allows every name resolves it.
          "/unlisted.test/${upstream4}"
        ];
      };
    };
    systemd.services.upstream-https = {
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${https}";
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
    environment.systemPackages = [ pkgs.nftables pkgs.curl pkgs.dnsutils pkgs.netcat pkgs.iproute2 pkgs.openssl ];

    # The host resolves through the upstream's DNS server: where the route's
    # upstream, api.test, is found. Nothing names it in /etc/hosts, so a
    # workload asking the same question is answered by frisket instead.
    networking.nameservers = [ upstream4 ];

    # The daemon runs as the user whose credentials it holds: a person, not a
    # DynamicUser. The token is theirs, in a directory only they can read.
    users.users.alice = { isNormalUser = true; uid = 1000; group = "users"; };
    services.frisket = {
      user = "alice";
      group = "users";
      dns = [ upstream4 ];
      policies.test = {
        allow = [ "allowed.test" "api.test" ];
        intercept = [ "api.test" ];
        routes.api = {
          host = "api.test";
          upstream = "https://api.test";
          upstreamCA = "${certs}/ca.crt";
          credentialFile = "/srv/secrets/token";
          paths = [{ methods = [ "GET" ]; prefix = "/v1"; }];
        };
      };
      # The trusted shape: every name, and the same route still intercepted.
      policies.trusted = {
        allow = [ "*" ];
        intercept = [ "api.test" ];
        routes.api = config.services.frisket.policies.test.routes.api;
      };
    };

    systemd.tmpfiles.rules = [
      "d /srv/work 0777 root root -"
      "d /srv/secrets 0700 alice users -"
    ];

    # What a workload tries against what root installed. In the store, which
    # every session can read, rather than quoted through three shells.
    environment.etc."frisket-tamper".source = pkgs.writeText "tamper.sh" ''
      nft list ruleset >/dev/null 2>&1 && echo listed
      nft flush ruleset >/dev/null 2>&1 && echo flushed
      # -r, so it holds every capability a new user namespace can give.
      unshare -Ur nft list ruleset >/dev/null 2>&1 && echo listed-from-userns
      unshare -Ur nft flush ruleset >/dev/null 2>&1 && echo flushed-from-userns
      echo attempted
      curl -sS -m 5 http://allowed.test/
    '';

    # A session that outlives a daemon restart. It talks to the workspace,
    # which is the one directory the test and the session share.
    environment.etc."frisket-long".source = pkgs.writeText "long.sh" ''
      curl -sS -m 5 http://allowed.test/ > before-restart
      touch started
      while [ ! -e go ]; do sleep 0.1; done
      curl -sS -m 5 http://allowed.test/ > after-restart
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

    # The session under test: steered, in the `all` set, under the policy.
    flong.strict = {
      user = "alice";
      workspace = "realpath /srv/work";
      command = ''set -- bash -c "$1"'';
      # Ahead of frisket's own steps, so the test can find the session.
      attach = lib.mkOrder 100 ''echo "$machine" > /tmp/last-session'';
    };
    services.frisket.flong.strict.policy = "test";

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
          # In the session's own mount namespace as well as its network one,
          # so names resolve as they do in there -- through frisket -- and
          # not through the host's nscd, which resolves outside the sandbox.
          ${pkgs.util-linux}/bin/nsenter --target="$leader" --mount --net \
            ${pkgs.util-linux}/bin/setpriv --reuid=1000 --regid=100 --clear-groups \
            ${pkgs.writeShellScript "probe" ''
              end=$(( $(${pkgs.coreutils}/bin/date +%s) + 4 ))
              while [ "$(${pkgs.coreutils}/bin/date +%s)" -lt "$end" ]; do
                t=$(${pkgs.coreutils}/bin/date +%s.%N)
                # By name, so each attempt asks frisket's DNS first. Before
                # the rules that query reaches the listener unmarked and is
                # refused, unanswered, so a short timeout keeps the attempts
                # coming.
                if ${pkgs.curl}/bin/curl -s -m 0.3 -o /dev/null http://allowed.test/; then
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
    services.frisket.flong.probed.policy = "test";

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
    services.frisket.flong.networked = { policy = "test"; set = "service"; };

    # The same, under the policy that allows every name.
    flong.trusted = {
      container = "strict";
      user = "alice";
      workspace = "realpath /srv/work";
      command = ''set -- bash -c "$1"'';
      network = { };
      attach = lib.mkOrder 100 ''echo "$machine" > /tmp/last-session'';
    };
    services.frisket.flong.trusted = { policy = "trusted"; set = "service"; };
  };

  testScript = { nodes, ... }:
    let
      strict = lib.getExe nodes.machine.flong.strict.launcher;
      probed = lib.getExe nodes.machine.flong.probed.launcher;
      badpolicy = lib.getExe nodes.machine.flong.badpolicy.launcher;
      networked = lib.getExe nodes.machine.flong.networked.launcher;
      trusted = lib.getExe nodes.machine.flong.trusted.launcher;
      frisket = lib.getExe nodes.machine.services.frisket.package;
      ca = nodes.machine.services.frisket.caCertificate;
    in
    ''
      import json
      import re
      import secrets
      import shlex
      import time
      from collections import Counter

      # The real credential, made here so it exists nowhere before the test
      # writes it to the host, and can be searched for everywhere after.
      token = "real-" + secrets.token_hex(16)
      sandbox_token = "sandbox-" + secrets.token_hex(8)

      def write_token(t):
          # By temp file and rename, as the tools that own credential files
          # write them: the rename is what the daemon has to notice.
          machine.succeed(f"echo {t} > /srv/secrets/token.new && chown alice:users /srv/secrets/token.new "
                          "&& chmod 0600 /srv/secrets/token.new && mv -f /srv/secrets/token.new /srv/secrets/token")

      start_all()
      write_token(token)
      upstream.wait_for_unit("upstream.service")
      upstream.wait_for_unit("upstream-https.service")
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
      def hold(launcher, ready, script="true"):
          machine.succeed("rm -f /srv/work/release /tmp/last-session")
          payload = shlex.quote(f"{script}; while [ ! -e release ]; do sleep 0.1; done")
          machine.succeed(f"{launcher} {payload} >/tmp/hold.out 2>&1 &")
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

      # As the workload: its uid, its network namespace AND its mount
      # namespace -- its files, its resolv.conf, the CA bound in at
      # /etc/frisket/ca.crt -- because a lookup made with the host's files
      # goes through the host's nscd, which resolves outside the sandbox.
      def as_workload(leader, cmd):
          return (f"nsenter --target={leader} --mount --net setpriv --reuid=1000 --regid=100 "
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
          out = machine.succeed("${strict} 'curl -sS -m 5 -4 http://allowed.test/; curl -sS -m 5 -6 http://allowed.test/'")
          assert out.count("upstream-body") == 2, out
          name = last_session()
          for dst in ["${upstream4}:80", "[${upstream6}]:80"]:
              [e] = wait_log("egress", name, lambda m: m["dst"] == dst, dst)
              assert e["decision"] == "accepted" and e["name"] == "allowed.test" and e["bytes_in"] > 0, e
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
          assert len(waiting) >= 2 and set(waiting) == {"fail"}, probes
          # Egress arrived, and not one attempt got through before the rules.
          assert ok and min(ok) >= rules_at, (rules_at, probes)
          # And every one that got through, frisket saw.
          lines = lines_of("egress", name)
          assert len([m for m in lines if m["decision"] == "accepted"]) >= len(ok), (lines, len(ok))
          assert all(m["dst"] in ("${upstream4}:80", "[${upstream6}]:80") for m in lines), lines

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
              assert "status: NXDOMAIN" in out, (server, out)
              assert f"SERVER: {server}#53" in out, (server, out)
          dsts = {m["dst"] for m in lines_of("dns", name) if m["transport"] == "udp"}
          for dst in ["127.0.0.1:53", "[::1]:53", "${upstream4}:53", "[${upstream6}]:53", "127.0.0.53:53"]:
              assert dst in dsts, (dst, dsts)
          # None of it went anywhere near the upstream's DNS server.
          upstream.fail("journalctl -u dnsmasq -o cat | grep -q example.com")

      with subtest("DNS over TCP is answered by frisket, not a port nobody holds"):
          for server in ["${upstream4}", "127.0.0.1", "::1"]:
              out = machine.succeed(as_workload(leader, f"dig +tcp +time=2 +tries=1 example.com @{server}"))
              assert "status: NXDOMAIN" in out, (server, out)
          tcp = [m for m in lines_of("dns", name) if m["transport"] == "tcp"]
          assert {m["dst"] for m in tcp} >= {"${upstream4}:53", "127.0.0.1:53", "[::1]:53"}, tcp
          assert all(m["decision"] == "refused" and m["reason"] == "not allowed" for m in tcp), tcp

      with subtest("the service address on 443 reaches interception, both families"):
          # By address, so with no SNI: interception refuses the handshake
          # rather than choose a route -- and so a credential -- for it.
          for url in ["https://192.0.2.2/", "https://[2001:db8::2]/"]:
              machine.execute(as_workload(leader, f"curl -sk -m 5 -g {url}"))
          tls = lines_of("tls", name)
          assert {m["dst"] for m in tls} == {"192.0.2.2:443", "[2001:db8::2]:443"}, tls
          assert all(m["decision"] == "refused" and m["reason"] == "no SNI" for m in tls), tls

      with subtest("without `socket transparent 1 return`, frisket's own replies are steered back to it"):
          # The proof that the line is load-bearing: frisket's SYN-ACK from
          # the service address is marked, turned back onto lo and handed to
          # the listener, and the client never connects.
          h = handle(leader, "steer", r"socket transparent")
          machine.succeed(as_root(leader, f"nft delete rule inet frisket steer handle {h}"))
          before = len(lines_of("tls", name))
          status, out, _ = timed(as_workload(leader, "curl -sk -m 3 https://192.0.2.2/"))
          assert status != 0, (status, out)
          time.sleep(1)
          assert len(lines_of("tls", name)) == before, lines_of("tls", name)
          machine.succeed(as_root(leader, "nft insert rule inet frisket steer socket transparent 1 return"))
          machine.execute(as_workload(leader, "curl -sk -m 5 https://192.0.2.2/"))
          wait_log("tls", name, lambda m: True, "the handshake")
          assert len(lines_of("tls", name)) == before + 1

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

      # Interception, end to end, in a session of its own. The first request
      # is the payload's, inside the session, through the CA the adapter bound
      # at /etc/frisket/ca.crt and a sandbox Authorization header that must
      # not survive. The rest are made as the workload from outside.
      api = ("curl -sS -m 10 --cacert /etc/frisket/ca.crt "
             f"-H 'Authorization: Bearer {sandbox_token}' https://api.test/v1/models > api-out 2>&1")
      name, leader = hold("${strict}", "ip link show frisket0", api)
      machine.wait_until_succeeds("grep -q upstream-api-ok /srv/work/api-out")

      def upstream_saw(pattern):
          return upstream.execute(f"journalctl -u upstream-https -o cat | grep -E {shlex.quote(pattern)}")[1]

      with subtest("the machine's CA is constrained to the intercepted hosts, critically"):
          # Every policy's intercepted hosts, which here is api.test in both,
          # and no IP address at all.
          text = machine.succeed("openssl x509 -noout -text -in ${ca}")
          assert re.search(r"X509v3 Name Constraints: critical\n\s+Permitted:\n\s+DNS:api\.test\n\s+Excluded:\n"
                           r"\s+IP:0\.0\.0\.0/0\.0\.0\.0\n\s+IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0\n", text), text

      with subtest("the machine's CA is bound into the session, and the workload cannot change it"):
          machine.succeed(f"cmp /proc/{leader}/root/etc/frisket/ca.crt ${ca}")
          machine.fail(as_workload(leader, "echo forged >> /etc/frisket/ca.crt"))
          machine.fail(as_workload(leader, "chmod u+w /etc/frisket/ca.crt"))
          machine.succeed(f"cmp /proc/{leader}/root/etc/frisket/ca.crt ${ca}")

      with subtest("the intercepted name resolves to the service address, and only that name does"):
          for qtype, want in [("A", "192.0.2.2"), ("AAAA", "2001:db8::2")]:
              out = machine.succeed(as_workload(leader, f"dig +short {qtype} api.test @127.0.0.1"))
              assert out.strip() == want, (qtype, out)
          out = machine.succeed(as_workload(leader, "dig +short A allowed.test @127.0.0.1"))
          assert out.strip() == "${upstream4}", out
          intercepted = [m for m in lines_of("dns", name) if m.get("name") == "api.test"]
          assert intercepted and all(m["decision"] == "intercepted" and "upstream" not in m for m in intercepted), intercepted

      with subtest("a request through it reaches the upstream with the real credential, and never the sandbox's"):
          assert machine.succeed("cat /srv/work/api-out").strip() == "upstream-api-ok"
          seen = upstream_saw("upstream-request GET api.test /v1/models")
          assert f"auth=Bearer {token}" in seen, seen
          assert sandbox_token not in upstream_saw("."), "the sandbox's own Authorization reached the upstream"
          [r] = wait_log("request", name, lambda m: m["path"] == "/v1/models", "the request")
          assert r["decision"] == "allowed" and r["status"] == 200 and r["route"] == "api", r
          assert r["dst"] in ("192.0.2.2:443", "[2001:db8::2]:443"), r

      with subtest("the credential is nowhere in the sandbox: not its files, not its processes' environments"):
          # Its filesystem as the session sees it -- its root, and every bind
          # in it, the workspace and the CA included -- less the store, which
          # was built before the token existed, and the kernel's own trees.
          # The same search finds what IS in there, so an empty answer means
          # something.
          def search(needle):
              return (f"cd /proc/{leader}/root && find . \\( -path ./nix -o -path ./proc -o -path ./sys -o -path ./dev \\) "
                      f"-prune -o -type f -print0 | xargs -0 grep -lsF -- {needle} | grep -q .")
          machine.succeed(search("upstream-api-ok"))
          machine.fail(search(token))
          # Every process in its pid namespace, and what each was started with.
          pids = machine.succeed(f"for p in /proc/[0-9]*; do [ \"$(readlink $p/ns/pid)\" = \"$(readlink /proc/{leader}/ns/pid)\" ] && echo $p; done; true").split()
          assert len(pids) >= 2, pids
          environs = " ".join(f"{p}/environ {p}/cmdline" for p in pids)
          # A `sleep` in the payload's loop can be gone by the time it is read.
          machine.succeed(f"{{ cat {environs} 2>/dev/null; true; }} | grep -aqF -- XDG_RUNTIME_DIR=")
          machine.fail(f"{{ cat {environs} 2>/dev/null; true; }} | grep -aqF -- {token}")

      with subtest("an out-of-scope request is refused, and never reaches the upstream"):
          out = machine.succeed(as_workload(leader, "curl -sS -m 10 --cacert /etc/frisket/ca.crt -o /dev/null -w '%{http_code}' https://api.test/admin"))
          assert out.strip() == "403", out
          assert upstream_saw("/admin") == "", upstream_saw("/admin")
          [r] = wait_log("request", name, lambda m: m["path"] == "/admin", "the refusal")
          assert r["decision"] == "refused" and r["reason"] == "out of scope" and r["status"] == 403, r

      with subtest("a credential file replaced by rename is picked up"):
          new_token = "real-" + secrets.token_hex(16)
          write_token(new_token)
          for _ in range(50):
              machine.succeed(as_workload(leader, "curl -sSf -m 10 --cacert /etc/frisket/ca.crt -o /dev/null https://api.test/v1/models"))
              if f"auth=Bearer {new_token}" in upstream_saw("upstream-request"):
                  break
              time.sleep(0.2)
          assert f"auth=Bearer {new_token}" in upstream_saw("upstream-request"), upstream_saw("upstream-request")
          token = new_token

      with subtest("an allowed name that is not intercepted is spliced, not terminated"):
          out = machine.succeed(as_workload(leader, "curl -sS -m 10 --cacert ${certs}/ca.crt https://allowed.test/"))
          assert out.strip() == "upstream-api-ok", out
          # Its certificate is the upstream's own: frisket's CA cannot verify it.
          status, out = machine.execute(as_workload(leader, "curl -sS -m 10 --cacert /etc/frisket/ca.crt https://allowed.test/"))
          assert status == 60, (status, out)
          spliced = [m for m in lines_of("egress", name) if m.get("name") == "allowed.test" and m["dst"].endswith(":443")]
          assert len(spliced) == 2 and all(m["decision"] == "accepted" for m in spliced), spliced
          assert [m for m in lines_of("request", name) if m.get("host") == "allowed.test"] == []

      with subtest("a name not on the allowlist is NXDOMAIN, without an upstream lookup"):
          # NXDOMAIN and not REFUSED, which musl takes as a hard failure and
          # stops walking its search list.
          out = machine.succeed(as_workload(leader, "dig +time=2 +tries=1 denied.test @127.0.0.1"))
          assert "status: NXDOMAIN" in out, out
          [d] = wait_log("dns", name, lambda m: m.get("name") == "denied.test", "the refusal")
          assert d["decision"] == "refused" and d["reason"] == "not allowed" and "upstream" not in d, d
          machine.fail(as_workload(leader, "curl -sS -m 5 http://denied.test/"))
          upstream.fail("journalctl -u dnsmasq -o cat | grep -q denied.test")

      with subtest("the host's own addresses are refused by structure"):
          for url in ["http://203.0.113.10/", "http://[2001:db8:113::10]/"]:
              machine.fail(as_workload(leader, f"curl -sS -m 5 -g {url}"))
          refused = [m for m in lines_of("egress", name) if m["dst"] in ("203.0.113.10:80", "[2001:db8:113::10]:80")]
          assert len(refused) == 2, refused
          assert all(m["decision"] == "refused" and m["reason"] == "structural: host-owned" for m in refused), refused

      with subtest("every connection and every query produced exactly one line"):
          # Connections and refused datagrams share one sequence per session,
          # so every number from 1 up must appear exactly once, whatever
          # handled it; a number missing is a connection nobody logged.
          conns = Counter(m["conn"] for msg in ["egress", "request", "tls", "connection", "datagram"]
                          for m in lines_of(msg, name))
          conns.update(m["conn"] for m in lines_of("dns", name) if "conn" in m)
          assert conns and set(conns.values()) == {1}, conns
          assert sorted(conns) == list(range(1, max(conns) + 1)), sorted(conns)
          # And queries have a sequence of their own, over both transports.
          queries = Counter(m["query"] for m in lines_of("dns", name))
          assert queries and set(queries.values()) == {1}, queries
          assert sorted(queries) == list(range(1, max(queries) + 1)), sorted(queries)
          # None of it says the credential.
          assert token not in machine.succeed("journalctl -u frisket.service -o cat --no-pager")

      release(name)

      with subtest("the `service` set: DNS and the service address are steered, the rest goes direct"):
          name, leader = hold("${networked}", "ip route show default | grep -q .")
          out = machine.succeed(as_workload(leader, "curl -sS -m 5 ${url4}"))
          assert "upstream-body" in out, out
          assert lines_of("egress", name) == [], lines_of("egress", name)
          out = machine.succeed(as_workload(leader, "dig +short +time=2 +tries=1 allowed.test @${upstream4}"))
          assert out.strip() == "${upstream4}", out
          [d] = wait_log("dns", name, lambda m: m["dst"] == "${upstream4}:53", "the steered query")
          assert d["decision"] == "resolved" and d["name"] == "allowed.test", d
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

      with subtest("a `service` policy allowing `*` resolves any name, and still intercepts its route's host"):
          name, leader = hold("${trusted}", "ip route show default | grep -q .")
          out = machine.succeed(as_workload(leader, "dig +short +time=2 +tries=1 unlisted.test @127.0.0.1"))
          assert out.strip() == "${upstream4}", out
          [d] = wait_log("dns", name, lambda m: m.get("name") == "unlisted.test", "the unlisted name")
          assert d["decision"] == "resolved" and d["upstream"] == "${upstream4}:53", d
          out = machine.succeed(as_workload(leader, "curl -sS -m 5 http://unlisted.test/"))
          assert "upstream-body" in out, out
          out = machine.succeed(as_workload(leader, "dig +short A api.test @127.0.0.1"))
          assert out.strip() == "192.0.2.2", out
          out = machine.succeed(as_workload(leader, "curl -sS -m 10 --cacert /etc/frisket/ca.crt https://api.test/v1/models"))
          assert out.strip() == "upstream-api-ok", out
          [r] = wait_log("request", name, lambda m: m["path"] == "/v1/models", "the request")
          assert r["decision"] == "allowed" and r["status"] == 200 and r["route"] == "api", r
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
