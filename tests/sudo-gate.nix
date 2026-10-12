# frisket-sudo as nixosModules.sudoGate runs it, with fakegalley as dan's
# galley.service.
{ self }:
{ lib, hostPkgs, ... }:

let
  pkgs = hostPkgs;
  system = pkgs.stdenv.hostPlatform.system;
  fakegalley = lib.getExe self.packages.${system}.fakegalley;
  plugin = self.packages.${system}.frisket-sudo-plugin;
  password = "hunter2-frisket";

  clientKey = pkgs.runCommand "sudo-gate-test-client-key" { nativeBuildInputs = [ pkgs.openssh ]; } ''
    mkdir $out
    ssh-keygen -q -t ed25519 -N "" -C root -f $out/id
  '';

  claude = pkgs.runCommand "sudo-gate-test-claude" { } ''
    mkdir -p $out/bin
    cp ${pkgs.bash}/bin/bash $out/bin/claude
  '';

  askpass = pkgs.writeShellScript "askpass" ''
    touch /run/fakegalley/askpass-ran
    echo wrong
  '';

  nopasswd.security.sudo.extraRules = [{
    users = [ "dan" ];
    commands = [{ command = "/run/current-system/sw/bin/true"; options = [ "NOPASSWD" ]; }];
  }];

  latency = pkgs.writeText "gate-latency.py" ''
    import os, socket, sys, time

    def ask(kind):
        t = time.monotonic_ns()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect("/run/frisket-sudo/gate.sock")
        s.sendall(b"FSUD\x02" + kind + b"\0\0\0\0")
        r = s.recv(3)
        return s, (time.monotonic_ns() - t) / 1e6, r[:1]

    if sys.argv[1] == "cold":
        s, ms, r = ask(b"C")
        assert r == b"Y", r
        print(f"{ms:.1f}")
        sys.exit()
    cs, gs = [], []
    for _ in range(200):
        s, ms, r = ask(b"C")
        assert r == b"Y", r
        cs.append(ms)
        rd, wr = os.pipe()
        if os.fork() == 0:
            _, ms, r = ask(b"G")
            os.write(wr, f"{ms} {r.decode()}".encode())
            os._exit(0)
        os.wait()
        ms, r = os.read(rd, 64).decode().split()
        assert r == "Y", r
        gs.append(float(ms))
        s.close()
        os.close(rd)
        os.close(wr)
    cs.sort()
    gs.sort()
    print(f"C median {cs[100]:.2f} ms, max {cs[-1]:.2f} ms; G median {gs[100]:.2f} ms, max {gs[-1]:.2f} ms")
  '';

  # A terminal for a command, as script(1) gives one but read to the end:
  # script lost the whole of a command's output now and then under load,
  # where pty.spawn reads the terminal until it hangs up.
  ptyrun = pkgs.writeText "ptyrun.py" ''
    import os, pty, sys
    sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))
  '';

  sleeper = { wantedBy = [ "multi-user.target" ]; serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity"; };
in
{
  name = "frisket-sudo";

  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.sudoGate ];
    services.frisket.sudoGate.enable = true;
    services.frisket.sudoGate.danger."systemctl **".args."bar*" = "touches bar";

    specialisation.nopasswd.configuration = nopasswd;
    specialisation.misread.configuration = {
      imports = [ nopasswd ];
      environment.etc."sudo.conf".source = lib.mkForce
        (pkgs.writeText "sudo.conf" "Plugin frisket_audit ${plugin.misread}/lib/frisket_sudo.so user=dan\n");
    };

    users.users.dan = {
      isNormalUser = true;
      uid = 1000;
      group = "users";
      extraGroups = [ "wheel" ];
      linger = true;
      inherit password;
      openssh.authorizedKeys.keyFiles = [ "${clientKey}/id.pub" ];
    };
    users.users.bob = { isNormalUser = true; group = "users"; password = "bob"; };
    users.users.lp = { isSystemUser = true; group = "lp"; };
    users.groups.lp = { };

    services.openssh.enable = true;

    systemd.services.foo = sleeper;
    systemd.services.frisket = sleeper;

    systemd.tmpfiles.rules = [ "d /run/galley-ask 0755 dan users -" ];
    systemd.user.services.galley.serviceConfig = {
      ExecStart = "${fakegalley} -socket /run/galley-ask/dan.sock -script /run/fakegalley/script -log /run/fakegalley/log";
      Slice = "app.slice";
    };

    environment.systemPackages = [ pkgs.socat pkgs.gnutar pkgs.python3 ];
  };

  testScript = ''
    import json
    import shlex

    pw = "${password}"
    path = "/run/wrappers/bin:/run/current-system/sw/bin"
    galley_cgroup = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/galley.service"

    def clean_env(user, extra=""):
        return f"env -i HOME=/home/{user} USER={user} LOGNAME={user} SHELL=/run/current-system/sw/bin/bash PATH={path} {extra}"

    def notty(cmd, user="dan", extra=""):
        return machine.execute(f"setsid -w runuser -u {user} -- {clean_env(user, extra)} bash -c {shlex.quote(cmd)} </dev/null 2>&1")

    def tty(cmd, user="dan", feed=pw):
        inner = f"(sleep 2; printf '%s\\n' {shlex.quote(feed)}) | python3 ${ptyrun} bash -c {shlex.quote(cmd)}"
        return machine.execute(f"runuser -u {user} -- {clean_env(user, 'TERM=dumb')} bash -c {shlex.quote(inner)} 2>&1")

    def galley(*script):
        machine.succeed(f"printf '%s\\n' {' '.join(map(shlex.quote, script))} > /run/fakegalley/script")
        machine.succeed("rm -f /run/galley-ask/dan.sock")
        machine.succeed("systemctl -M dan@ --user restart galley.service")
        machine.wait_until_succeeds("test -S /run/galley-ask/dan.sock")

    def events(kind, log="/run/fakegalley/log"):
        out = machine.succeed(f"cat {log}")
        return [e for e in map(json.loads, out.splitlines()) if e["event"] == kind]

    def gate_log():
        out = machine.succeed("journalctl -u frisket-sudo.service -o cat")
        return [json.loads(l) for l in out.splitlines() if l.startswith("{")]

    def checkins():
        return len([d for d in gate_log() if d.get("msg") == "check-in"])

    def decisions():
        return [d for d in gate_log() if d.get("msg") == "decision" and "outcome" in d]

    def labels(q):
        return [f["label"] for f in q["fields"] or []]

    def is_dialog(q, time=True):
        want = ["Password for dan"] + (["Remember the password for this claude for", ""] if time else [])
        return q["kind"] == "forms" and labels(q) == want

    def is_question(q):
        return q["kind"] == "question" and not q["fields"]

    def wait_questions(n):
        machine.wait_until_succeeds(f"test $(grep -c '\"event\":\"question\"' /run/fakegalley/log) -ge {n}")

    def wait_closes(n):
        machine.wait_until_succeeds(f"test $(grep -c '\"event\":\"close\"' /run/fakegalley/log) -ge {n}")

    n = 0
    def run(where, cmd):
        global n
        n += 1
        status = f"/run/{where}/status-{n}"
        line = f"{{ {cmd}; }} </dev/null; echo $? > {status}"
        machine.succeed(f"printf '%s\\n' {shlex.quote(line)} > /run/{where}/in")
        machine.wait_until_succeeds(f"test -s {status}")
        return int(machine.succeed(f"cat {status}"))

    def start(where):
        machine.succeed(f"install -d -o dan -g users -m 0700 /run/{where} && mkfifo -m 0600 /run/{where}/in && chown dan /run/{where}/in")
        inner = f"exec 3<>/run/{where}/in; exec ${claude}/bin/claude <&3 >/dev/null"
        machine.succeed(f"systemd-run -M dan@ --user --unit={where} --quiet -E PATH={path} -- ${pkgs.runtimeShell} -c {shlex.quote(inner)}")
        machine.wait_until_succeeds(f"systemctl -M dan@ --user is-active {where}.service")

    def stop_gate():
        machine.succeed("systemctl stop frisket-sudo.socket frisket-sudo.service")

    def start_gate():
        machine.succeed("systemctl start frisket-sudo.socket")

    def kill_sudo(signal="KILL"):
        machine.succeed(f"pkill -{signal} -x sudo")

    gate_not_running = "frisket-sudo: gate not running (systemctl status frisket-sudo.socket); sudo in a terminal is not gated"

    machine.wait_for_unit("frisket-sudo.socket")
    machine.wait_for_unit("sshd.service")
    machine.wait_for_unit("user@1000.service")
    machine.succeed("install -d -o dan -g users -m 0755 /run/fakegalley")
    galley("ok " + pw + " 0")

    with subtest("C and G answer well inside their 250 ms, from a cold gate too"):
        cold = []
        for i in range(5):
            machine.succeed("systemctl stop frisket-sudo.service")
            cold.append(float(machine.succeed("python3 ${latency} cold")))
        warm = machine.succeed("python3 ${latency} warm").strip()
        print(f"gate latency: cold C {cold} ms; warm {warm}")
        assert max(cold) < 250, cold

    with subtest("sudo's auth stack is the helper, pam_unix, pam_deny"):
        auth = machine.succeed("grep '^auth' /etc/pam.d/sudo").splitlines()
        assert len(auth) == 3, auth
        assert "pam_exec.so seteuid quiet ${plugin}/bin/frisket-sudo-pam dan" in auth[0] and "sufficient" in auth[0], auth
        assert "pam_unix.so" in auth[1] and "pam_deny.so" in auth[2], auth
        machine.succeed("grep -qx 'Plugin frisket_audit ${plugin}/lib/frisket_sudo.so user=dan' /etc/sudo.conf")

    with subtest("with a tty the gate is never contacted and sudo prompts as stock"):
        asked, ins = len(events("question")), checkins()
        rc, out = tty("sudo -n id -u")
        print("tty sudo -n, never lectured:\n" + out)
        assert "a password is required" in out, out
        rc, out = tty("sudo id -u")
        assert "[sudo] password for dan" in out and "\n0" in out.replace("\r", ""), out
        assert len(events("question")) == asked and checkins() == ins

    with subtest("sudo -n with no tty gets the dialog and runs; the environment after env_reset"):
        asked = len(events("question"))
        rc, out = notty("sudo -n env", extra="TERM=dumb DISPLAY=:0 LANG=C.UTF-8 COLORTERM=truecolor XAUTHORITY=/home/dan/.Xauthority FOO=bar")
        assert rc == 0, out
        print("the environment sudo passes after env_reset:\n" + out)
        qs = events("question")[asked:]
        assert len(qs) == 1 and is_dialog(qs[0]) and qs[0]["uid"] == 952, qs

    start("claude-a")
    start("claude-b")
    galley("ok " + pw + " 15 minutes", "answer 0", "ok " + pw + " 0", "answer 0")

    with subtest("one dialog: the command runs, the window opens, the journal has no password"):
        asked = len(events("question"))
        assert run("claude-a", "sudo systemctl restart foo >/run/claude-a/err 2>&1") == 0
        qs = events("question")[asked:]
        assert len(qs) == 1, qs
        q = qs[0]
        assert q["uid"] == 952 and is_dialog(q) and q["level"] == "normal" and q["title"] == "sudo systemctl restart foo", q
        assert q["text"] == "/run/current-system/sw/bin/systemctl restart foo", q
        assert q["table"]["rows"][0][1] == "claude" and q["table"]["summary"] == "claude", q
        err = machine.succeed("cat /run/claude-a/err")
        assert "frisket-sudo: password remembered for this claude until" in err, err
        machine.fail(f"journalctl -o cat | grep -F {pw}")
        assert events("answer")[-1]["fields"][0] == len(pw)

    with subtest("inside the window: a new bash -c under the same claude gets a question; another claude the dialog"):
        asked = len(events("question"))
        assert run("claude-a", "bash -c 'sudo id -u'") == 0
        assert run("claude-b", "sudo id -u") == 0
        qs = events("question")[asked:]
        assert len(qs) == 2 and is_question(qs[0]) and is_dialog(qs[1]), qs
        assert [b["label"] for b in qs[0]["buttons"]] == ["Refuse", "Allow"], qs[0]
        assert qs[0]["table"]["rows"][0][1] == "claude", qs[0]

    with subtest("danger inside the window is a danger question with no password"):
        asked = len(events("question"))
        assert run("claude-a", "sudo systemctl stop frisket.service") == 0
        q = events("question")[asked]
        assert is_question(q) and q["level"] == "danger", q
        assert q["text"].split("\n")[0] == "touches a unit that guards this machine", q

    with subtest("pin: a thief in galley's cgroup is refused and the window is unchanged"):
        pinned = int(machine.succeed("systemctl -M dan@ --user show -P MainPID galley.service"))
        machine.succeed("printf 'answer 0\\n' > /run/fakegalley/thief")
        before = machine.succeed("stat -c %i /run/galley-ask/dan.sock").strip()
        thief = (f"echo $$ > /run/fakegalley/thief.pid && echo $$ > {galley_cgroup}/cgroup.procs && exec ${fakegalley} "
                 "-socket /run/galley-ask/dan.sock -script /run/fakegalley/thief -log /run/fakegalley/thief.log")
        machine.succeed(f"printf '%s\\n' {shlex.quote(thief)} > /run/fakegalley/thief.sh")
        machine.succeed("systemd-run -M dan@ --user --unit=thief --quiet -- ${pkgs.runtimeShell} /run/fakegalley/thief.sh")
        machine.wait_until_succeeds(f"test -S /run/galley-ask/dan.sock && test \"$(stat -c %i /run/galley-ask/dan.sock)\" != {before}")
        machine.succeed(f"grep -qx \"$(cat /run/fakegalley/thief.pid)\" {galley_cgroup}/cgroup.procs")
        for i in range(2):
            assert run("claude-a", "sudo id -u") != 0
            q = events("question", "/run/fakegalley/thief.log")[i]
            assert is_question(q), q
            d = decisions()[-1]
            assert d["source"] == "not the pinned galley" and d["pin_pid"] == pinned, d
        machine.succeed("kill $(cat /run/fakegalley/thief.pid)")

    with subtest("pin: a socket outside galley's cgroup is nobody to ask"):
        machine.succeed("systemd-run -M dan@ --user --unit=outsider --quiet -- "
                        "/run/current-system/sw/bin/socat UNIX-LISTEN:/run/galley-ask/dan.sock,fork,unlink-early,perm=0666 'SYSTEM:sleep 10'")
        machine.wait_until_succeeds("ss -xl | grep -q /run/galley-ask/dan.sock")
        assert run("claude-a", "sudo id -u 2>/run/claude-a/err") != 0
        assert "no one to ask; use a terminal" in machine.succeed("cat /run/claude-a/err")
        assert decisions()[-1]["source"] == "nobody"
        machine.succeed("systemctl -M dan@ --user stop outsider.service")

    with subtest("pin: galley restarted, the next sudo gets the dialog; a question hung up is withdrawn"):
        galley("ok " + pw + " 15 minutes", "never")
        asked, closed = len(events("question")), len(events("close"))
        assert run("claude-a", "sudo id -u") == 0
        assert is_dialog(events("question")[asked])
        run("claude-a", "sudo id -u & echo $! > /run/claude-a/sudo.pid")
        wait_questions(asked + 2)
        assert is_question(events("question")[asked + 1])
        kill_sudo()
        wait_closes(closed + 1)

    with subtest("never answered: sudo waits, and killing it withdraws the dialog"):
        galley("never")
        asked, closed = len(events("question")), len(events("close"))
        machine.succeed(f"setsid -f runuser -u dan -- {clean_env('dan')} sudo id -u </dev/null >/dev/null 2>&1")
        wait_questions(asked + 1)
        machine.sleep(3)
        machine.succeed("pgrep -x sudo")
        kill_sudo("TERM")
        machine.sleep(3)
        print("sudo after SIGTERM while its dialog is up: " + ("still waiting" if machine.execute("pgrep -x sudo")[0] == 0 else "gone"))
        machine.execute("pkill -KILL -x sudo")
        wait_closes(closed + 1)
        assert decisions()[-1]["source"] == "hung up"

    with subtest("a wrong password, then the right one: two dialogs, the second's time used"):
        galley("ok wrong 0", "ok " + pw + " 15 minutes")
        asked = len(events("question"))
        rc, out = notty("sudo id -u")
        assert rc == 0 and "password remembered for this claude until" in out, out
        qs = events("question")[asked:]
        assert len(qs) == 2 and all(is_dialog(q) for q in qs), qs
        assert qs[1]["text"].startswith("Wrong password, try again\n") and "Wrong password" not in qs[0]["text"], qs

    with subtest("danger outside a window: the dialog with a password and no time, and no window after"):
        galley("ok " + pw, "ok " + pw + " 0")
        asked = len(events("question"))
        rc, out = notty("sudo systemctl stop frisket.service && sudo id -u")
        assert rc == 0 and "remembered" not in out, out
        qs = events("question")[asked:]
        assert len(qs) == 2 and qs[0]["level"] == "danger" and is_dialog(qs[0], time=False) and is_dialog(qs[1]), qs

    galley("cancel")

    with subtest("a program outside the root-owned directories is danger, named by its path; cancel refuses"):
        machine.succeed("install -d -o dan -g users /home/dan/bin && printf '#!/bin/sh\\necho fake\\n' > /home/dan/bin/systemctl "
                        "&& chown dan /home/dan/bin/systemctl && chmod 0755 /home/dan/bin/systemctl")
        asked = len(events("question"))
        rc, out = notty("PATH=/home/dan/bin:$PATH sudo systemctl status")
        assert rc != 0 and "unable to log accept event" in out, out
        q = events("question")[asked]
        assert q["level"] == "danger" and "/home/dan/bin/systemctl" in q["text"].split("\n")[0], q
        assert decisions()[-1]["source"] == "cancelled"

    with subtest("sh -c is classified by its inner commands, and unreadable is danger"):
        asked = len(events("question"))
        notty("sudo sh -c 'systemctl stop sshd'")
        notty("sudo sh -c '\"$(printf x)\"'")
        qs = events("question")[asked:]
        assert len(qs) == 2 and all(q["level"] == "danger" for q in qs), qs
        assert qs[0]["text"].split("\n")[0] == "touches a unit that guards this machine", qs[0]
        assert qs[1]["text"].split("\n")[0] == "a shell command frisket cannot read", qs[1]

    with subtest("the host's danger rule from config.json is danger beside the catalogue's"):
        machine.succeed("${lib.getExe self.packages.${system}.frisket-sudo} check /etc/frisket-sudo/config.json")
        assert "-config /etc/frisket-sudo/config.json" in machine.succeed("systemctl show -P ExecStart frisket-sudo.service")
        asked = len(events("question"))
        notty("sudo systemctl restart bar.service")
        notty("sudo systemctl restart nftables.service")
        qs = events("question")[asked:]
        assert len(qs) == 2 and all(q["level"] == "danger" for q in qs), qs
        assert qs[0]["text"].split("\n")[0] == "touches bar", qs[0]
        assert qs[1]["text"].split("\n")[0] == "touches a unit that guards this machine", qs[1]

    with subtest("a preserved variable outside the allowlist is shown"):
        asked = len(events("question"))
        notty("sudo --preserve-env=FOO id -u", extra="FOO=bar")
        q = events("question")[asked]
        assert q["level"] == "normal" and any(l.startswith("FOO=") for l in q["text"].split("\n")), q

    galley("ok " + pw + " 0")

    with subtest("-S and -A are ignored: the askpass never runs and the dialog's password is checked"):
        rc, out = notty("echo wrong | sudo -S id -u")
        assert rc == 0, out
        rc, out = notty("sudo -A id -u", extra="SUDO_ASKPASS=${askpass}")
        assert rc == 0, out
        machine.fail("test -e /run/fakegalley/askpass-ran")

    with subtest("a same-parent ticket gives nothing: the second sudo is asked again"):
        asked = len(events("question"))
        rc, out = notty("sudo id -u && sudo id -u")
        assert rc == 0, out
        assert len(events("question")) == asked + 2

    with subtest("a same-parent ticket with the gate stopped in between is refused"):
        machine.succeed("rm -f /run/fakegalley/first /run/fakegalley/go /run/fakegalley/ticket.out")
        script = ("sudo id -u; touch /run/fakegalley/first; while ! test -e /run/fakegalley/go; do sleep 0.2; done; "
                  "sudo id -u; echo rc=$?")
        machine.succeed(f"setsid -f runuser -u dan -- {clean_env('dan')} bash -c {shlex.quote(script)} </dev/null >/run/fakegalley/ticket.out 2>&1")
        machine.wait_until_succeeds("test -e /run/fakegalley/first")
        stop_gate()
        machine.succeed("touch /run/fakegalley/go")
        machine.wait_until_succeeds("grep -q rc= /run/fakegalley/ticket.out")
        out = machine.succeed("cat /run/fakegalley/ticket.out")
        assert "rc=0" not in out and "frisket_audit: unable to log accept event: gate not running" in out, out
        start_gate()

    with subtest("-v and -l fail as stock with no check-in, and the next sudo is asked"):
        for flag in ["-v", "-nv", "-l", "--validate", "--vali", "--li"]:
            asked, ins = len(events("question")), checkins()
            rc, out = notty(f"sudo {flag}; echo rc=$?; sudo id -u")
            assert "rc=0" not in out and rc == 0, (flag, out)
            assert len(events("question")) == asked + 1 and checkins() == ins + 1, flag

    with subtest("-gwheel and -u lp check in and get the dialog, with and without a same-parent ticket"):
        asked, ins = len(events("question")), checkins()
        rc, out = notty("sudo -gwheel id -g && sudo -gwheel id -g && sudo -u lp id -u && sudo -u lp id -u")
        assert rc == 0, out
        qs = events("question")[asked:]
        assert len(qs) == 4 and all(is_dialog(q) for q in qs) and checkins() == ins + 4, qs

    with subtest("timestamp_type=tty: a no-tty sudo leaves no ticket for a tty sudo"):
        rc, out = notty("sudo id -u")
        assert rc == 0, out
        rc, out = tty("sudo id -u")
        assert "[sudo] password for dan" in out, out

    with subtest("another user is stock, with no check-in"):
        asked, ins = len(events("question")), checkins()
        rc, out = notty("sudo -n id -u", user="bob")
        assert rc != 0, out
        assert len(events("question")) == asked and checkins() == ins

    with subtest("a child of sudo running as another user gets no for G"):
        rc, out = notty("sudo -u bob env PAM_SERVICE=sudo PAM_USER=dan ${plugin}/bin/frisket-sudo-pam dan; echo rc=$?")
        assert "rc=1" in out, out

    with subtest("remote sudo -S is stock: no gate with nobody answering or the gate stopped; a wrong password fails"):
        galley("never")
        machine.succeed("install -m 0600 ${clientKey}/id /root/id")
        ssh = "ssh -i /root/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes dan@127.0.0.1"
        print("the links above the remote shell: " + machine.succeed(
            f"{ssh} 'p=$(ps -o ppid= -p $$); ps -o user=,comm= -p $p; ps -o user=,comm= -p $(ps -o ppid= -p $p)'"))
        remote = f"{ssh} \"/run/wrappers/bin/sudo -S -p ''' tar --version\""
        asked = len(events("question"))
        machine.succeed(f"printf '%s\\n' {pw} | {remote}")
        stop_gate()
        machine.succeed(f"printf '%s\\n' {pw} | {remote}")
        start_gate()
        machine.fail(f"printf 'wrong\\n' | {remote}")
        assert len(events("question")) == asked

    with subtest("detached remote sudo is gated locally"):
        asked = len(events("question"))
        machine.succeed(f"{ssh} 'setsid -f sh -c \"/run/wrappers/bin/sudo -S id\" </dev/null >/dev/null 2>&1' </dev/null")
        wait_questions(asked + 1)
        assert events("question")[asked]["kind"] == "forms"
        machine.sleep(2)
        machine.succeed("pgrep -x sudo")
        kill_sudo()

    with subtest("a NOPASSWD rule's command still gets the dialog"):
        galley("ok " + pw + " 0")
        machine.succeed("/run/booted-system/specialisation/nopasswd/bin/switch-to-configuration test")
        asked = len(events("question"))
        rc, out = notty("sudo true")
        assert rc == 0, out
        assert len(events("question")) == asked + 1

    with subtest("a no-tty sudo -l the policy allows reaches accept() and passes silently"):
        asked, ins = len(events("question")), checkins()
        rc, out = notty("sudo -l")
        assert rc == 0 and "frisket_audit" not in out and "frisket-sudo:" not in out, out
        assert len(events("question")) == asked and checkins() == ins

    with subtest("NOPASSWD with a plugin that misreads the mode is refused at accept"):
        machine.succeed("/run/booted-system/specialisation/misread/bin/switch-to-configuration test")
        asked, ins = len(events("question")), checkins()
        rc, out = notty("sudo true")
        assert rc != 0 and "gate not running" in out, out
        assert len(events("question")) == asked and checkins() == ins
        machine.succeed("/run/booted-system/bin/switch-to-configuration test")

    with subtest("gate socket stopped: no-tty sudo is refused with the message; tty and root sudo work"):
        stop_gate()
        rc, out = notty("sudo id -u")
        assert rc != 0 and gate_not_running in out, out
        rc, out = tty("sudo id -u")
        assert "\n0" in out.replace("\r", ""), out
        assert machine.succeed("/run/wrappers/bin/sudo id -u").strip() == "0"
        start_gate()

    def timed_notty(cmd):
        rc, out = notty(f"s=$(date +%s%N); {cmd}; echo rc=$? ms=$(( ($(date +%s%N) - s) / 1000000 ))")
        return out, int(out.rsplit("ms=", 1)[1])

    with subtest("a stuck gate fails a no-tty sudo fast; tty sudo works"):
        machine.succeed("systemctl start frisket-sudo.service")
        machine.succeed("kill -STOP $(systemctl show -P MainPID frisket-sudo.service)")
        out, ms = timed_notty("sudo id -u")
        print(f"no-tty sudo against a stuck gate: {ms} ms")
        assert "rc=0" not in out and gate_not_running in out and ms < 2000, out
        rc, out = tty("sudo id -u")
        assert "\n0" in out.replace("\r", ""), out
        machine.succeed("kill -CONT $(systemctl show -P MainPID frisket-sudo.service)")
        rc, out = notty("sudo id -u")
        assert rc == 0, out

    with subtest("a crash-looping gate keeps the socket up: no-tty sudo fails fast, tty sudo works"):
        stop_gate()
        machine.succeed("mkdir -p /run/systemd/system/frisket-sudo.service.d && "
                        "printf '[Service]\\nExecStart=\\nExecStart=/run/current-system/sw/bin/false\\n' > /run/systemd/system/frisket-sudo.service.d/crash.conf && "
                        "systemctl daemon-reload")
        start_gate()
        out, ms = timed_notty("sudo id -u")
        print(f"no-tty sudo against a crash-looping gate: {ms} ms")
        assert "rc=0" not in out and gate_not_running in out and ms < 2000, out
        machine.succeed("systemctl is-active frisket-sudo.socket")
        rc, out = tty("sudo id -u")
        assert "\n0" in out.replace("\r", ""), out
        stop_gate()
        machine.succeed("rm -r /run/systemd/system/frisket-sudo.service.d && systemctl daemon-reload && systemctl reset-failed frisket-sudo.service")
        start_gate()
        rc, out = notty("sudo id -u")
        assert rc == 0, out
  '';
}
