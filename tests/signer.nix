# frisket-signer as nixosModules.signer runs it, over a software TPM: two
# sshds with their own host keys, alpha (127.0.0.1) and beta (127.0.0.2),
# both in /etc/ssh/ssh_known_hosts; fakegalley as dan's galley.service; and
# the shapes the signer tells apart, built from renamed binaries, since a link
# is known by its comm: a tab (script as .kgx-wrapped, holding a pty, with
# bash on it), a claude (bash as claude) and frisket's main process (ssh as
# frisket, in a stand-in frisket.service with frisket's hardening).
{ self }:
{ lib, hostPkgs, ... }:

let
  pkgs = hostPkgs;
  system = pkgs.stdenv.hostPlatform.system;
  fakegalley = lib.getExe self.packages.${system}.fakegalley;
  agenttamper = self.packages.${system}.agenttamper;

  hostKeys = pkgs.runCommand "signer-test-host-keys" { nativeBuildInputs = [ pkgs.openssh ]; } ''
    mkdir $out
    for h in alpha beta; do
      ssh-keygen -q -t ed25519 -N "" -C $h -f $out/$h
      echo "$h $(cut -d' ' -f1,2 $out/$h.pub)" >> $out/known_hosts
    done
  '';

  shapes = pkgs.runCommand "signer-test-shapes" { } ''
    mkdir -p $out/bin $out/ssh $out/sh
    cp ${lib.getBin pkgs.util-linux}/bin/script $out/bin/.kgx-wrapped
    cp ${pkgs.bash}/bin/bash $out/bin/claude
    cp ${pkgs.openssh}/bin/ssh $out/ssh/frisket
    cp ${pkgs.bash}/bin/bash $out/sh/frisket
  '';

  betaConfig = pkgs.writeText "sshd_config_beta" ''
    ListenAddress 127.0.0.2
    HostKey /etc/ssh/beta_host_key
    AuthorizedKeysFile %h/.ssh/authorized_keys
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    UsePAM yes
    PidFile none
  '';
in
{
  name = "frisket-signer";

  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.signer ];
    virtualisation.tpm.enable = true;
    services.frisket.signer.enable = true;
    specialisation.ask.configuration.services.frisket.signer.terminal = lib.mkForce "ask";
    specialisation.hosts.configuration.services.frisket.signer.ssh.hosts.alpha = "allow";

    # A project's signed policy, through the courier. The key is made in the
    # TPM as the test runs, so the allowed signers are written then.
    services.frisket.policy = {
      fileName = "chase.json";
      courier.enable = true;
    };
    environment.etc."frisket/allowed_signers".source = lib.mkForce "/run/allowed_signers";

    users.users.dan = { isNormalUser = true; uid = 1000; group = "users"; linger = true; };

    networking.hosts."127.0.0.1" = [ "alpha" ];
    networking.hosts."127.0.0.2" = [ "beta" "beta.example" ];
    services.openssh = {
      enable = true;
      listenAddresses = [{ addr = "127.0.0.1"; port = 22; }];
      hostKeys = [{ path = "/etc/ssh/alpha_host_key"; type = "ed25519"; }];
      settings.PasswordAuthentication = false;
      settings.KbdInteractiveAuthentication = false;
    };
    systemd.services.sshd-beta = {
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig.ExecStart = "${pkgs.openssh}/bin/sshd -D -e -f ${betaConfig}";
    };
    environment.etc."ssh/alpha_host_key" = { source = "${hostKeys}/alpha"; mode = "0600"; };
    environment.etc."ssh/beta_host_key" = { source = "${hostKeys}/beta"; mode = "0600"; };
    environment.etc."ssh/ssh_known_hosts".source = lib.mkForce "${hostKeys}/known_hosts";

    systemd.tmpfiles.rules = [ "d /run/galley-ask 0755 dan users -" ];
    systemd.user.services.galley.serviceConfig = {
      ExecStart = "${fakegalley} -socket /run/galley-ask/dan.sock -script /run/fakegalley/script -log /run/fakegalley/log";
      Slice = "app.slice";
    };

    # frisket.service's own hardening, from nix/module.nix.
    systemd.services.frisket = {
      environment.SSH_AUTH_SOCK = "/run/frisket-signer/agent";
      serviceConfig = {
        Type = "oneshot";
        User = "dan";
        Group = "users";
        ExecStart = "${pkgs.runtimeShell} /run/frisket-standin";
        UMask = "0077";
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        PrivateTmp = true;
        PrivateDevices = true;
        PrivateIPC = true;
        DevicePolicy = "closed";
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        NoNewPrivileges = true;
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        KeyringMode = "private";
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" ];
        SystemCallErrorNumber = "EPERM";
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
      };
    };

    environment.systemPackages = [ pkgs.ssh-tpm-agent pkgs.tpm2-tools pkgs.socat pkgs.bubblewrap pkgs.git agenttamper ];
  };

  testScript = ''
    import json
    import shlex

    agent = "SSH_AUTH_SOCK=/run/frisket-signer/agent"
    env = f"-E {agent} -E SHELL=${pkgs.bash}/bin/bash -E PATH=/run/current-system/sw/bin"

    def as_dan(cmd):
        return f"runuser -u dan -- env {agent} {cmd}"

    def user_run(cmd):
        return f"systemd-run -M dan@ --user --wait --pipe --quiet --collect {env} -- {cmd} </dev/null"

    def galley(*script):
        machine.succeed(f"printf '%s\\n' {' '.join(map(shlex.quote, script))} > /run/fakegalley/script")
        machine.succeed("rm -f /run/galley-ask/dan.sock")
        machine.succeed("systemctl -M dan@ --user restart galley.service")
        machine.wait_until_succeeds("test -S /run/galley-ask/dan.sock")

    def events(kind):
        out = machine.succeed("cat /run/fakegalley/log")
        return [e for e in map(json.loads, out.splitlines()) if e["event"] == kind]

    def decisions():
        out = machine.succeed("journalctl -u frisket-signer.service -o cat")
        return [d for d in (json.loads(l) for l in out.splitlines() if l.startswith("{")) if d.get("msg") == "decision"]

    def journal_has(text):
        machine.succeed(f"journalctl -u frisket-signer.service -o cat | grep -F {shlex.quote(text)}")

    # A long-lived dan process fed lines through a FIFO: the tab types each
    # into bash on its pty, the claude runs each as bash would a script.
    n = 0
    def run(where, cmd):
        global n
        n += 1
        status = f"/run/{where}/status-{n}"
        line = f"{{ {cmd}; }} </dev/null; echo $? > {status}"
        machine.succeed(f"printf '%s\\n' {shlex.quote(line)} > /run/{where}/in")
        machine.wait_until_succeeds(f"test -s {status}")
        return int(machine.succeed(f"cat {status}"))

    def start(where, program):
        machine.succeed(f"install -d -o dan -g users -m 0700 /run/{where} && mkfifo -m 0600 /run/{where}/in && chown dan /run/{where}/in")
        inner = f"exec 3<>/run/{where}/in; exec {program} <&3 >/dev/null"
        machine.succeed(f"systemd-run -M dan@ --user --unit={where} --quiet {env} -- ${pkgs.runtimeShell} -c {shlex.quote(inner)}")
        machine.wait_until_succeeds(f"systemctl -M dan@ --user is-active {where}.service")

    def standin(script):
        machine.succeed(f"printf '%s\\n' {shlex.quote(script)} > /run/frisket-standin && chmod 0644 /run/frisket-standin")

    def source_is(src):
        machine.wait_until_succeeds("journalctl -u frisket-signer.service -o cat | grep '\"msg\":\"decision\"' "
                                    f"| tail -n1 | grep -qF '\"source\":\"{src}\"'")

    machine.wait_for_unit("frisket-signer.socket")
    machine.wait_for_unit("sshd.service")
    machine.wait_for_unit("sshd-beta.service")
    machine.wait_for_unit("user@1000.service")

    with subtest("with no key files the identities are empty and serve is up"):
        out = machine.fail(as_dan("ssh-add -l 2>&1"))
        assert "no identities" in out, out
        machine.succeed("systemctl is-active frisket-signer.service")

    with subtest("dan cannot open /dev/tpmrm0"):
        assert "tss" not in machine.succeed("id -nG dan").split()
        machine.fail("runuser -u dan -- ${pkgs.runtimeShell} -c ': <> /dev/tpmrm0'")

    with subtest("a key made by stock ssh-tpm-keygen loads"):
        machine.succeed("SSH_ASKPASS_REQUIRE=never ssh-tpm-keygen -f /root/id_ecdsa -C dan@machine </dev/null")
        machine.succeed("install -o ssh-signer -g ssh-signer -m 0600 /root/id_ecdsa.tpm /var/lib/frisket-signer/")
        machine.succeed("install -d -o dan -g users -m 0700 /home/dan/.ssh")
        machine.succeed("install -o dan -g users -m 0600 /root/id_ecdsa.pub /home/dan/.ssh/authorized_keys")
        machine.succeed("systemctl restart frisket-signer.service")
        out = machine.succeed(as_dan("ssh-add -l"))
        assert "dan@machine (ECDSA)" in out, out

    with subtest("frisket-signer-keygen writes a new key into new/"):
        machine.succeed("systemctl start frisket-signer-keygen.service")
        out = machine.succeed("ssh-keygen -l -f /var/lib/frisket-signer/new/id_ecdsa.pub")
        assert "(ECDSA)" in out, out
        machine.succeed("test \"$(stat -c %U /var/lib/frisket-signer/new/id_ecdsa.tpm)\" = ssh-signer")

    machine.succeed("install -d -o dan -g users -m 0755 /run/fakegalley")
    galley("answer 0")
    start("tab", "${shapes}/bin/.kgx-wrapped -qfc 'exec bash' /dev/null")
    start("claude", "${shapes}/bin/claude")
    machine.succeed("install -o dan -m 0644 /root/id_ecdsa.pub /run/claude/key.pub")

    with subtest("a terminal tab to a known host signs silently and the ECDSA login works"):
        asked = len(events("question"))
        assert run("tab", "ssh -n alpha true") == 0
        assert len(events("question")) == asked
        source_is("terminal")

    with subtest("kgx -- ssh shapes and systemd-run --user ssh are asked, warning, no time field"):
        asked = len(events("question"))
        kgx = "${shapes}/bin/.kgx-wrapped -qec"
        machine.succeed(user_run(f"{kgx} 'ssh -n alpha true' /dev/null"))
        machine.succeed(user_run(f"{kgx} 'bash -c \"ssh -n alpha true; true\"' /dev/null"))
        machine.succeed(user_run("/run/current-system/sw/bin/ssh -n alpha true"))
        qs = events("question")[asked:]
        assert len(qs) == 3, qs
        for q in qs:
            assert q["level"] == "warning" and q["kind"] == "question" and not q["fields"], q
            assert [b["label"] for b in q["buttons"]] == ["Refuse", "Allow once"], q

    with subtest("Allow once grants nothing, and Allow for 15 minutes makes the next sign silent"):
        asked = len(events("question"))
        assert run("claude", "ssh -n alpha true") == 0
        assert run("claude", "ssh -n alpha true") == 0
        assert len(events("question")) == asked + 2
        galley("ok 15 minutes")
        assert run("claude", "ssh -n alpha true") == 0
        q = events("question")[-1]
        assert q["kind"] == "forms" and q["title"] == "ssh to alpha", q
        assert run("claude", "ssh -n alpha true") == 0
        assert len(events("question")) == asked + 3
        source_is("grant")

    with subtest("ssh-keygen -Y sign -n git signs silently, -n file is asked, Allow once"):
        galley("answer 0")
        machine.succeed("echo hello > /run/claude/msg && chown dan /run/claude/msg")
        asked = len(events("question"))
        assert run("claude", "ssh-keygen -Y sign -f /run/claude/key.pub -n git /run/claude/msg") == 0
        assert len(events("question")) == asked
        source_is("sshsig")
        machine.succeed("rm /run/claude/msg.sig")
        assert run("claude", "ssh-keygen -Y sign -f /run/claude/key.pub -n file /run/claude/msg") == 0
        q = events("question")[-1]
        assert q["kind"] == "question" and q["title"] == "SSHSIG signature", q
        assert 'SSHSIG namespace "file"' in q["text"].split("\n"), q
        rows = q["table"]["rows"]
        assert rows[0][1] == "claude" and rows[-1][1].startswith("ssh-keygen -Y sign"), q
        assert q["table"]["summary"].startswith("claude ← ssh-keygen -Y sign"), q
        d = decisions()[-1]
        assert d["namespace"] == "file" and d["anchor"]["Comm"] == "ssh-keygen", d

    with subtest("a raw ssh-keygen -Y sign in a frisket-policy namespace is refused unasked"):
        machine.succeed("rm -f /run/claude/msg.sig")
        asked = len(events("question"))
        assert run("claude", "ssh-keygen -Y sign -f /run/claude/key.pub -n 'frisket-policy:~/Projects/foo' /run/claude/msg") != 0
        assert len(events("question")) == asked
        journal_has("a frisket-policy namespace is never signed raw")
        machine.succeed("test ! -e /run/claude/msg.sig")

    with subtest("ssh -A: the far-side sign is asked as forwarded, from a claude and from a tab"):
        for where in ("claude", "tab"):
            asked = len(events("question"))
            assert run(where, "ssh -n -A alpha '/run/current-system/sw/bin/ssh -n beta true'") == 0
            qs = [q for q in events("question")[asked:] if q["title"] == "ssh to beta"]
            assert len(qs) == 1 and "forwarded" in qs[0]["text"].split("\n"), qs

    with subtest("a sign for another session than the last bind is refused"):
        assert run("claude", "agenttamper") == 0
        journal_has("session id is not the last bind's")

    with subtest("an ssh killed while its question is up withdraws it"):
        galley("never")
        closed = len(events("close"))
        asked = len(events("question"))
        run("claude", "ssh -n beta true & echo $! > /run/claude/ssh.pid")
        machine.wait_until_succeeds(f"test $(grep -c '\"event\":\"question\"' /run/fakegalley/log) -gt {asked}")
        assert events("question")[-1]["title"] == "ssh to beta"
        machine.succeed("kill $(cat /run/claude/ssh.pid)")
        machine.wait_until_succeeds(f"test $(grep -c '\"event\":\"close\"' /run/fakegalley/log) -gt {closed}")
        machine.wait_until_succeeds("journalctl -u frisket-signer.service -o cat | grep -q '\"source\":\"hung up\"'")

    with subtest("frisket's main process signs without a question; a child exec'd in it is asked"):
        galley("answer 0")
        asked = len(events("question"))
        standin("exec ${shapes}/ssh/frisket -n alpha true")
        machine.succeed("systemctl start frisket.service")
        assert len(events("question")) == asked
        source_is("frisket")
        standin("exec ${shapes}/sh/frisket -c '${pkgs.openssh}/bin/ssh -n beta true; exit $?'")
        machine.succeed("systemctl start frisket.service")
        q = events("question")[-1]
        assert len(events("question")) == asked + 1 and q["title"] == "ssh to beta", q
        source_is("galley")

    with subtest("a cgroup move from dan's user@ session into frisket.service is refused"):
        standin("exec ${shapes}/ssh/frisket -n alpha sleep 600")
        machine.succeed("systemctl start --no-block frisket.service")
        machine.wait_until_succeeds("test -n \"$(cat /sys/fs/cgroup/system.slice/frisket.service/cgroup.procs)\"")
        assert run("claude", "echo $BASHPID > /sys/fs/cgroup/system.slice/frisket.service/cgroup.procs") != 0
        assert run("claude", "grep -q user@1000.service /proc/$BASHPID/cgroup") == 0
        machine.succeed("systemctl stop frisket.service")

    with subtest("with galley absent: frisket and a live grant sign, everything else is refused"):
        machine.succeed("systemctl -M dan@ --user stop galley.service")
        standin("exec ${shapes}/ssh/frisket -n alpha true")
        machine.succeed("systemctl start frisket.service")
        source_is("frisket")
        assert run("claude", "ssh -n alpha true") == 0
        source_is("grant")
        assert run("claude", "ssh -n beta true") != 0
        source_is("nobody")

    with subtest("a rebound galley socket outside galley.service is nobody, named by its cgroup"):
        galley("answer 0")
        machine.succeed("systemd-run -M dan@ --user --unit=thief --quiet -- "
                        "/run/current-system/sw/bin/socat UNIX-LISTEN:/run/galley-ask/dan.sock,fork,unlink-early,perm=0666 'SYSTEM:sleep 10'")
        machine.wait_until_succeeds("ss -xl | grep -q /run/galley-ask/dan.sock")
        assert run("claude", "ssh -n beta true") != 0
        source_is("nobody")
        d = decisions()[-1]
        assert "thief.service" in d["err"], d
        machine.succeed("systemctl -M dan@ --user stop thief.service")
        galley("answer 0")

    with subtest("terminal = ask asks a tab to a known host"):
        machine.succeed("/run/booted-system/specialisation/ask/bin/switch-to-configuration test")
        asked = len(events("question"))
        assert run("tab", "ssh -n alpha true") == 0
        q = events("question")[-1]
        assert len(events("question")) == asked + 1 and q["title"] == "ssh to alpha" and q["kind"] == "forms", q

    with subtest("ssh.hosts.alpha = allow: a claude's login to alpha is silent, beta and a forwarded sign to alpha are asked"):
        machine.succeed("/run/booted-system/specialisation/hosts/bin/switch-to-configuration test")
        machine.succeed("${lib.getExe self.packages.${system}.frisket-signer} check /etc/frisket-signer/config.json")
        asked = len(events("question"))
        assert run("claude", "ssh -n alpha true") == 0
        assert len(events("question")) == asked
        source_is("host")
        assert run("claude", "ssh -n beta true") == 0
        assert len(events("question")) == asked + 1 and events("question")[-1]["title"] == "ssh to beta"
        source_is("galley")
        asked = len(events("question"))
        assert run("claude", "ssh -n -A beta '/run/current-system/sw/bin/ssh -n alpha true'") == 0
        qs = [q for q in events("question")[asked:] if q["title"] == "ssh to alpha"]
        assert len(qs) == 1 and "forwarded" in qs[0]["text"].split("\n"), qs

    frisket = "${lib.getExe self.packages.${system}.frisket}"
    foo = "/home/dan/Projects/foo"
    verify = (f"ssh-keygen -Y verify -f /etc/frisket/allowed_signers -I dan -n 'frisket-policy:~/Projects/foo' "
              f"-s {foo}/chase.json.sig < {foo}/chase.json")

    def as_dan_in_foo(cmd):
        machine.succeed(f"cd {foo} && runuser -u dan -- {cmd}")

    with subtest("a claude in a repository is offered Always, which signs the rule into its chase.json"):
        key = " ".join(machine.succeed("cat /root/id_ecdsa.pub").split()[:2])
        machine.succeed(f"echo 'dan namespaces=\"frisket-policy:*\" {key}' > /run/allowed_signers")
        machine.succeed(f"{frisket} policy signers /etc/frisket/allowed_signers")
        machine.succeed(f"install -d -o dan -g users /home/dan/Projects {foo}")
        as_dan_in_foo("git init -q")
        assert run("claude", f"cd {foo}") == 0
        galley("always")
        asked = len(events("question"))
        assert run("claude", "ssh -n beta true") == 0
        assert len(events("question")) == asked + 1
        q = events("question")[-1]
        assert q["always"] and q["kind"] == "forms" and q["title"] == "ssh to beta", q
        assert q["diff"]["path"] == "~/Projects/foo/chase.json" and q["diff"]["old"] == "", q
        assert '"beta": "allow"' in q["diff"]["new"], q
        assert "Always allows beta from ~/Projects/foo, signed into its chase.json." in q["text"].split("\n"), q
        source_is("always")
        assert machine.succeed(f"cat {foo}/chase.json") == q["diff"]["new"]
        assert machine.succeed(f"stat -c %U {foo}/chase.json {foo}/chase.json.sig").split() == ["dan", "dan"]
        machine.succeed(verify)
        machine.succeed(f"runuser -u dan -- {frisket} policy verify {foo}/chase.json")
        journal_has('"msg":"always"')

    with subtest("the signed rule then signs the claude's login to beta unasked, as project"):
        asked = len(events("question"))
        assert run("claude", "ssh -n beta true") == 0
        assert len(events("question")) == asked
        source_is("project")
        d = decisions()[-1]
        assert d["project"] == foo and d["project_applies"], d

    widened = "\n".join(['{', '  "signer": {', '    "ssh": {', '      "hosts": {',
                          '        "*.example": "allow"', '      }', '    }', '  },', '  "version": 2', '}', ""])

    with subtest("chase.json edited by hand and not signed again is ignored, and Always not offered"):
        as_dan_in_foo("git add chase.json chase.json.sig")
        as_dan_in_foo("git -c user.name=dan -c user.email=dan@machine commit -q -m always")
        machine.succeed("cp ${hostKeys}/known_hosts /run/known_hosts && echo \"beta.example $(cut -d' ' -f1,2 ${hostKeys}/beta.pub)\" >> /run/known_hosts")
        machine.succeed("rm /etc/ssh/ssh_known_hosts && cp /run/known_hosts /etc/ssh/ssh_known_hosts")
        machine.succeed(f"printf '%s' {shlex.quote(widened)} | runuser -u dan -- tee {foo}/chase.json >/dev/null")
        machine.fail(verify)
        galley("answer 0")
        asked = len(events("question"))
        assert run("claude", "ssh -n beta.example true") == 0
        assert len(events("question")) == asked + 1
        q = events("question")[-1]
        assert not q["always"] and q["diff"] is None, q
        source_is("galley")
        journal_has('"msg":"project policy ignored"')

    with subtest("frisket policy sign shows the widening against the signed file and signs it"):
        asked = len(events("question"))
        assert run("tab", f"cd {foo} && {frisket} policy sign chase.json") == 0
        q = events("question")[-1]
        assert len(events("question")) == asked + 1 and q["title"] == "sign ~/Projects/foo/chase.json", q
        assert not q["always"] and [b["label"] for b in q["buttons"]] == ["Refuse", "Allow once"], q
        assert '"beta": "allow"' in q["diff"]["old"] and q["diff"]["new"] == widened, q
        d = decisions()[-1]
        assert d["class"] == "policy sign" and d["outcome"] == "sign", d
        machine.succeed(verify)
        asked = len(events("question"))
        assert run("claude", "ssh -n beta.example true") == 0
        assert len(events("question")) == asked
        source_is("project")

    with subtest("policy-sign from another user namespace, as a sandbox's would be, is refused unasked"):
        asked = len(events("question"))
        out = machine.fail(as_dan(f"bwrap --unshare-user --dev-bind / / -- {frisket} policy sign {foo}/chase.json 2>&1"))
        assert "another user namespace" in out, out
        assert len(events("question")) == asked
        journal_has("policy-sign: pid")

    with subtest("a cleared TPM: the key is listed, a sign fails as cleared, serve stays up"):
        pid = machine.succeed("systemctl show -P MainPID frisket-signer.service").strip()
        machine.succeed("tpm2_clear -T device:/dev/tpmrm0")
        assert "dan@machine (ECDSA)" in machine.succeed(as_dan("ssh-add -l"))
        assert run("tab", "ssh -n alpha true") != 0
        journal_has("TPM cleared or a different chip")
        assert machine.succeed("systemctl show -P MainPID frisket-signer.service").strip() == pid
        machine.succeed("systemctl is-active frisket-signer.service")
  '';
}
