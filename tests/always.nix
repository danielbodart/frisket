# Always on the gateway's questions, end to end: frisket under flong, as
# nixosModules.flong runs it, with quoin's signer over a software TPM and
# quoin's courier, as quoin's nixosModules.signer and .policy run them,
# deployed as a host would: the signer trusting frisket.service as a policy
# signer and a login signer, the courier taking it as a peer, and frisket
# given their paths. A session's document marks its route
# `always`; the route asks about deleting a thing; the asker answers always.
# The session then deletes unasked, the workspace's chase.json and its .sig
# are written and verify with stock ssh-keygen, and a session launched from
# the document with that file's frisket section merged in, as the next
# launch would be, is asked nothing. A session whose document marks no route
# `always`, as strict's never does, is asked with no Always offered.
#
# The upstream is a second machine, since frisket refuses the host's own
# addresses by structure: an HTTPS server under a CA of its own, and the DNS
# server that names it.
{ self, flong, quoin }:
{ lib, hostPkgs, ... }:

let
  pkgs = hostPkgs;
  upstream4 = "203.0.113.20";
  upstream6 = "2001:db8:113::20";

  certs = pkgs.runCommand "frisket-always-certs" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out && cd $out
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
      -keyout ca.key -out ca.crt -subj /CN=frisket-always-ca \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout server.key -out server.csr -subj /CN=api.test
    printf '%s\n' 'subjectAltName=DNS:api.test' 'extendedKeyUsage=serverAuth' > ext
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -days 3650 -extfile ext -out server.crt
  '';

  https = pkgs.writeText "https.py" ''
    import http.server, socket, ssl
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            print(f"upstream-request {self.command} {self.path}", flush=True)
            body = b"upstream-ok\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        do_DELETE = do_GET
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

  script = name: text: "${pkgs.writeShellScript "frisket-always-${name}" ''
    set -euo pipefail
    ${text}
  ''}";
  hook = name: text: [ [ (script name text) ] ];
  mark = lib.mkOrder 100 (hook "mark" ''
    echo "$machine" > /tmp/last-session
  '');
  workspace = [ (script "workspace" "echo /home/dan/proj") ];

  # A session's document, version 2, as chase writes a tier's: the route
  # asks about writes, and `always` marks it as one whose answers a
  # project's file is merged into, for every session but strict's.
  document = name: always: builtins.toJSON {
    version = 2;
    inherit name;
    allow."api.test" = true;
    routes.api = {
      host = "api.test";
      upstream = "https://api.test";
      upstreamCA = "${certs}/ca.crt";
      credentialFile = "/srv/secrets/token";
      placeholder = "frisket-placeholder";
      paths = {
        "GET /v1/**".operation = { id = "read"; summary = "Read"; class = "read"; };
        "DELETE /v1/things/*".operation = { id = "delete-thing"; summary = "Delete Thing"; class = "write"; };
      };
      writes = "ask";
    } // lib.optionalAttrs always { inherit always; };
  };

  # Says each question in the journal, and answers always where it is
  # offered and the thing is "a", allow otherwise; says each notice too.
  asker = pkgs.writeShellScript "asker" ''
    q=$(${pkgs.coreutils}/bin/cat)
    printf '%s\n' "$q" | ${pkgs.util-linux}/bin/logger -t frisket-asker
    case $q in
      *'"kind":"notice"'*) exit 0 ;;
      *'"always":true'*'"path":"/v1/things/a"'* | *'"path":"/v1/things/a"'*'"always":true'*) echo always; exit 0 ;;
    esac
    exit 0
  '';
in
{
  name = "frisket-always";

  nodes.upstream = { ... }: {
    networking.interfaces.eth1.ipv4.addresses = [{ address = upstream4; prefixLength = 24; }];
    networking.interfaces.eth1.ipv6.addresses = [{ address = upstream6; prefixLength = 64; }];
    networking.firewall.enable = false;
    services.dnsmasq = {
      enable = true;
      resolveLocalQueries = false;
      settings = {
        listen-address = [ upstream4 ];
        bind-dynamic = true;
        no-resolv = true;
        # Both families, as a public name has: Go's resolver asks for both.
        address = [ "/api.test/${upstream4}" "/api.test/${upstream6}" ];
      };
    };
    systemd.services.upstream-https = {
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${https}";
    };
  };

  nodes.machine = { config, ... }: {
    imports = [ flong.nixosModules.default self.nixosModules.flong quoin.nixosModules.signer quoin.nixosModules.policy ];

    virtualisation.memorySize = 3072;
    virtualisation.diskSize = 4096;
    virtualisation.tpm.enable = true;

    networking.interfaces.eth1.ipv4.addresses = [{ address = "203.0.113.10"; prefixLength = 24; }];
    networking.interfaces.eth1.ipv6.addresses = [{ address = "2001:db8:113::10"; prefixLength = 64; }];
    networking.nameservers = [ upstream4 ];
    security.pki.certificateFiles = [ "${certs}/ca.crt" ];

    users.users.dan = {
      isNormalUser = true;
      uid = 1000;
      group = "users";
      linger = true;
      autoSubUidGidRange = false;
      subUidRanges = [{ startUid = 100000; count = 65536; }];
      subGidRanges = [{ startGid = 100000; count = 65536; }];
    };

    services.frisket = {
      user = "dan";
      group = "users";
      # A version 1 policy for the sessions to name; each is served the
      # document its policyFile says.
      policies.base.allow = [ "api.test" ];
      policyRoots = [ "/srv/policies" ];
      asker = "${asker}";
      always = {
        enable = true;
        signer = "/run/quoin-signer/agent";
        courier = "/run/quoin-courier/sock";
        allowedSigners = "/etc/quoin/allowed_signers";
        fileName = "chase.json";
      };
    };
    services.quoin.signer = {
      enable = true;
      forUser = "dan";
      loginSigners = [ "frisket.service" ];
      policySigners = [ "frisket.service" ];
    };
    services.quoin.policy = {
      fileName = "chase.json";
      courier = {
        enable = true;
        forUser = "dan";
        peers."frisket.service" = "dan";
      };
    };
    # The key is made in the TPM as the test runs, so its allowed signers
    # are written then.
    environment.etc."quoin/allowed_signers".source = lib.mkForce "/run/allowed_signers";

    systemd.tmpfiles.rules = [
      "d /srv/secrets 0700 dan users -"
      "d /srv/policies 0755 root root -"
      "d /home/dan/proj 0755 dan users -"
    ];

    containers.box = {
      autoStart = false;
      privateNetwork = true;
      config = { pkgs, ... }: {
        system.stateVersion = "24.05";
        users.users.dan = { isNormalUser = true; uid = 1000; group = "users"; home = "/home/dan"; };
        users.groups.users.gid = 100;
        environment.systemPackages = [ pkgs.curl ];
      };
    };

    # trusted: its route marked always. strict: not marked. next: trusted
    # with the project's file merged in, as its next launch would be.
    flong = lib.genAttrs [ "trusted" "strict" "next" ] (_: {
      container = "box";
      user = "dan";
      inherit workspace;
      command = [ "bash" "-c" ];
      postStart = mark;
    });
    services.frisket.flong = lib.genAttrs [ "trusted" "strict" "next" ] (name: {
      policy = "base";
      policyFile = "/srv/policies/${name}.json";
    });

    environment.etc."always-test/trusted.json".text = document "trusted" true;
    environment.etc."always-test/strict.json".text = document "strict" false;
    environment.systemPackages = [ pkgs.ssh-tpm-agent pkgs.openssh pkgs.curl pkgs.dnsutils ];
  };

  testScript = { nodes, ... }:
    let
      launchers = builtins.toJSON (lib.genAttrs [ "trusted" "strict" "next" ] (name: lib.getExe nodes.machine.flong.${name}.launcher));
      frisket = lib.getExe nodes.machine.services.frisket.package;
      quoinBin = "${quoin.packages.${pkgs.stdenv.hostPlatform.system}.quoin}/bin/quoin";
    in
    ''
      import json
      import shlex

      launchers = json.loads('${launchers}')

      def as_user(script):
          inner = "export PATH=/run/wrappers/bin:/run/current-system/sw/bin; cd /home/dan/proj; " + script
          return ("systemd-run -M dan@ --user --wait --pipe --quiet --collect "
                  f"--expand-environment=no -- /run/current-system/sw/bin/bash -c {shlex.quote(inner)} </dev/null")

      def delete(thing):
          return ("curl -sS -m 20 --cacert /etc/frisket/ca.crt -o /dev/null -w '%{http_code}\\n' -X DELETE "
                  f"-H 'Authorization: Bearer frisket-placeholder' https://api.test/v1/things/{thing}")

      def run(session, things):
          out = machine.succeed(as_user(f"{launchers[session]} " + shlex.quote("; ".join(delete(t) for t in things))))
          return out.split(), machine.succeed("cat /tmp/last-session").strip()

      def asked(session):
          out = machine.succeed("journalctl -t frisket-asker -o cat --no-pager")
          return [q for q in map(json.loads, out.splitlines()) if q.get("session") == session]

      def requests(session):
          out = machine.succeed("journalctl -u frisket.service -o cat --no-pager")
          lines = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
          return [l for l in lines if l.get("msg") == "request" and l.get("session") == session]

      def policy(name, doc):
          machine.succeed(f"printf '%s' {shlex.quote(json.dumps(doc))} > /srv/policies/{name}.json")

      start_all()
      upstream.wait_for_unit("upstream-https.service")
      upstream.wait_for_unit("dnsmasq.service")
      machine.wait_for_unit("multi-user.target")
      machine.wait_for_unit("frisket.service")
      machine.wait_for_unit("quoin-signer.socket")
      machine.wait_for_unit("quoin-courier.socket")
      machine.wait_for_unit("user@1000.service")
      # The upstream's name, from its DNS server, as frisket resolves it.
      machine.wait_until_succeeds("dig +short +time=1 +tries=1 api.test @${upstream4} | grep -qx ${upstream4}")
      machine.wait_until_succeeds("curl -sSf -m 2 --resolve api.test:443:${upstream4} https://api.test/")
      machine.succeed("echo real-token > /srv/secrets/token && chown dan:users /srv/secrets/token && chmod 0600 /srv/secrets/token")
      for name in ["trusted", "strict"]:
          machine.succeed(f"install -m 0644 /etc/always-test/{name}.json /srv/policies/{name}.json")

      with subtest("the daemon's settings offer Always through quoin's signer and courier"):
          settings = json.loads(machine.succeed("cat /etc/frisket/config.json"))
          assert settings["always"] == {
              "signer": "/run/quoin-signer/agent", "courier": "/run/quoin-courier/sock",
              "allowedSigners": "/etc/quoin/allowed_signers", "fileName": "chase.json", "home": "/home/dan",
          }, settings
          courier = json.loads(machine.succeed("cat /etc/quoin/courier.json"))
          assert courier["peers"]["frisket.service"] == "dan", courier
          signer = json.loads(machine.succeed("cat /etc/quoin/signer.json"))
          assert signer["policySigners"] == ["frisket.service"] and signer["loginSigners"] == ["frisket.service"], signer

      with subtest("the signer holds a TPM key the allowed signers name for policies"):
          # Started once, so its state directory is there.
          machine.succeed("systemctl start quoin-signer.service")
          machine.succeed("SSH_ASKPASS_REQUIRE=never ssh-tpm-keygen -f /root/id_ecdsa -C dan@machine </dev/null")
          machine.succeed("install -o ssh-signer -g ssh-signer -m 0600 /root/id_ecdsa.tpm /var/lib/quoin-signer/")
          machine.succeed("systemctl restart quoin-signer.service")
          key = machine.succeed("cat /root/id_ecdsa.pub").strip()
          machine.succeed(f"echo 'dan namespaces=\"quoin-policy:*\" {key}' > /run/allowed_signers")
          machine.succeed("${quoinBin} policy signers /etc/quoin/allowed_signers")

      with subtest("answered always, the session deletes that thing unasked, and is asked about another"):
          codes, name = run("trusted", ["a", "a", "b"])
          assert codes == ["200", "200", "200"], codes
          qs = asked(name)
          assert len(qs) == 2 and qs[1]["path"] == "/v1/things/b", qs
          q = qs[0]
          assert q["always"] and q["path"] == "/v1/things/a" and q["workspace"] == "/home/dan/proj", q
          assert q["diff"]["path"] == "~/proj/chase.json" and q["diff"]["old"] == "", q
          new = json.loads(q["diff"]["new"])
          assert new == {"version": 2, "frisket": {"routes": {"api": {"operations": {"DELETE /v1/things/a": "allow"}}}}}, new
          rules = [(r["path"], r["rule"]) for r in requests(name)]
          assert rules == [("/v1/things/a", "asked"), ("/v1/things/a", "always"), ("/v1/things/b", "asked")], rules

      with subtest("chase.json and its .sig are written, and verify with stock ssh-keygen"):
          machine.wait_until_succeeds("test -s /home/dan/proj/chase.json.sig")
          assert machine.succeed("cat /home/dan/proj/chase.json") == q["diff"]["new"]
          assert machine.succeed("stat -c %U /home/dan/proj/chase.json /home/dan/proj/chase.json.sig").split() == ["dan", "dan"]
          machine.succeed("ssh-keygen -Y verify -f /etc/quoin/allowed_signers -I dan -n 'quoin-policy:~/proj' "
                          "-s /home/dan/proj/chase.json.sig < /home/dan/proj/chase.json")
          machine.succeed("runuser -u dan -- ${quoinBin} policy verify /home/dan/proj/chase.json")
          out = machine.succeed("journalctl -u frisket.service -o cat --no-pager")
          [line] = [l for l in map(json.loads, (l for l in out.splitlines() if l.startswith("{"))) if l.get("msg") == "always"]
          assert line["outcome"] == "written" and line["rule"] == "DELETE /v1/things/a" and line["session"] == name, line
          out = machine.succeed("journalctl -u quoin-signer.service -o cat --no-pager")
          signed = [l for l in map(json.loads, (l for l in out.splitlines() if l.startswith("{")))
                    if l.get("msg") == "decision" and l.get("class") == "policy sign"]
          assert len(signed) == 1 and signed[0]["source"] == "always" and signed[0]["outcome"] == "sign", signed

      with subtest("the next launch, with the file's frisket section merged in, is asked nothing"):
          machine.succeed("${frisket} check -layer project -base /srv/policies/trusted.json -section frisket /home/dan/proj/chase.json")
          doc = json.loads(machine.succeed("cat /srv/policies/trusted.json"))
          doc["name"] = "next"
          doc["routes"]["api"]["operations"] = new["frisket"]["routes"]["api"]["operations"]
          policy("next", doc)
          codes, name = run("next", ["a"])
          assert codes == ["200"], codes
          assert asked(name) == [], asked(name)
          assert [r["rule"] for r in requests(name)] == ["path"], requests(name)

      with subtest("a session whose route is not marked always, as strict's never is, is offered none"):
          codes, name = run("strict", ["a"])
          assert codes == ["200"], codes
          [q] = asked(name)
          assert "always" not in q and "diff" not in q, q
          assert [r["rule"] for r in requests(name)] == ["asked"], requests(name)
    '';
}
