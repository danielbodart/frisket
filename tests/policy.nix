# frisket-policy as nixosModules.policy runs it: alice's courier, with a
# stand-in peer, policy-reader.service run as bob, in place of the signer or
# the gate. A process of alice's in a project directory, a policy file signed
# there by stock ssh-keygen, read by the peer; eve in the peer's unit and bob
# outside it refused; a write with a stale digest refused and one with the
# file's digest written.
#
# The key is made when the test runs, so the allowed signers file is too:
# /etc/frisket/allowed_signers points into /run rather than at the module's
# rendering, which the policy-module check builds and reads.
{ self }:
{ lib, hostPkgs, ... }:

let
  pkgs = hostPkgs;
  system = pkgs.stdenv.hostPlatform.system;
  frisket = self.packages.${system}.frisket;
  courier = self.packages.${system}.frisket-policy;
in
{
  name = "frisket-policy";

  nodes.machine = { ... }: {
    imports = [ self.nixosModules.policy ];
    services.frisket.policy = {
      fileName = "chase.json";
      courier = {
        enable = true;
        forUser = "alice";
        peers."policy-reader.service" = "bob";
      };
    };
    environment.etc."frisket/allowed_signers".source = lib.mkForce "/run/policy-test/allowed_signers";

    users.users.alice = { isNormalUser = true; uid = 1000; group = "users"; };
    users.users.bob = { isNormalUser = true; uid = 1001; group = "users"; };
    users.users.eve = { isNormalUser = true; uid = 1002; group = "users"; };

    environment.systemPackages = [ frisket courier pkgs.openssh ];
  };

  testScript = ''
    import base64
    import json
    import shlex

    def alice(cmd):
        return machine.succeed(f"runuser -u alice -- env HOME=/home/alice ${pkgs.runtimeShell} -c {shlex.quote(cmd)}")

    def peer(user, args, ok=True):
        cmd = f"systemd-run --wait --pipe --quiet --collect --unit=policy-reader -p User={user} -- ${courier}/bin/frisket-policy {args} 2>&1"
        return machine.succeed(cmd) if ok else machine.fail(cmd)

    def courier_log():
        out = machine.succeed("journalctl -u frisket-policy.service -o cat")
        return [json.loads(l) for l in out.splitlines() if l.startswith("{")]

    machine.wait_for_unit("frisket-policy.socket")
    machine.wait_for_unit("multi-user.target")

    with subtest("a policy signed by stock ssh-keygen verifies, by frisket and by ssh-keygen"):
        machine.succeed("install -d -m 0755 /run/policy-test")
        machine.succeed("ssh-keygen -q -t ed25519 -N ''' -C alice -f /run/policy-test/key")
        machine.succeed("chown alice /run/policy-test/key")
        machine.succeed("echo \"alice namespaces=\\\"frisket-policy:*\\\" $(cat /run/policy-test/key.pub)\" > /run/policy-test/allowed_signers")
        machine.succeed("frisket policy signers /etc/frisket/allowed_signers")
        alice("mkdir -p ~/proj/sub ~/elsewhere && cd ~/proj && echo '{\"signer\":{\"ssh\":{\"hosts\":{\"gateway\":\"allow\"}}}}' > chase.json")
        alice("cd ~/proj && frisket policy fmt chase.json && frisket policy fmt -check chase.json")
        alice("cd ~/proj && ssh-keygen -Y sign -f /run/policy-test/key -n 'frisket-policy:~/proj' chase.json")
        out = alice("frisket policy verify ~/proj/chase.json")
        assert "signed by alice in frisket-policy:~/proj" in out, out
        alice("ssh-keygen -Y verify -f /etc/frisket/allowed_signers -I alice -n 'frisket-policy:~/proj' -s ~/proj/chase.json.sig < ~/proj/chase.json")

    machine.succeed("systemd-run --unit=alice-work --uid=alice -p WorkingDirectory=/home/alice/proj/sub -- sleep 1000")
    machine.wait_until_succeeds("systemctl is-active alice-work.service")
    pid = int(machine.succeed("systemctl show -P MainPID alice-work.service"))
    machine.succeed("systemd-run --unit=alice-idle --uid=alice -p WorkingDirectory=/home/alice/elsewhere -- sleep 1000")
    machine.wait_until_succeeds("systemctl is-active alice-idle.service")
    idle = int(machine.succeed("systemctl show -P MainPID alice-idle.service"))

    with subtest("the allowed peer reads the policy above the process's working directory"):
        got = json.loads(peer("bob", f"read {pid}"))
        assert got["root"] == "/home/alice/proj" and got["namespace"] == "frisket-policy:~/proj", got
        assert base64.b64decode(got["bytes"]).decode() == machine.succeed("cat /home/alice/proj/chase.json"), got
        assert base64.b64decode(got["sig"]).decode() == machine.succeed("cat /home/alice/proj/chase.json.sig"), got
        digest = got["digest"]
        assert digest.startswith("sha256:"), got
        r = [e for e in courier_log() if e.get("msg") == "read"][-1]
        assert r["peer"] == "policy-reader.service" and r["outcome"] == "ok" and r["signed"], r

    with subtest("a process with no policy above it reads as none, and a stale start is refused"):
        got = json.loads(peer("bob", f"read {idle}"))
        assert "root" not in got, got
        out = peer("bob", f"read {pid} 1", ok=False)
        assert "not the process that started at 1" in out, out

    with subtest("a disallowed uid is refused, in the peer's unit and outside it"):
        out = peer("eve", f"read {pid}", ok=False)
        assert "refused: peer pid" in out and "is uid 1002, not 1001" in out, out
        out = machine.fail(f"runuser -u bob -- frisket-policy read {pid} 2>&1")
        assert "not a unit this courier serves" in out, out
        out = machine.fail(f"runuser -u alice -- frisket-policy read {pid} 2>&1")
        assert "not a unit this courier serves" in out, out

    with subtest("a write with a stale digest is refused, and one with the file's digest is written"):
        machine.succeed("install -d -o alice -m 0755 /run/policy-test/new")
        alice("cd /run/policy-test/new && echo '{\"signer\":{\"ssh\":{\"hosts\":{\"gateway\":\"allow\",\"nas\":\"allow\"}}}}' > chase.json && frisket policy fmt chase.json")
        alice("cd /run/policy-test/new && ssh-keygen -Y sign -f /run/policy-test/key -n 'frisket-policy:~/proj' chase.json")
        new = "-root /home/alice/proj -file /run/policy-test/new/chase.json -sig /run/policy-test/new/chase.json.sig"
        stale = "sha256:" + "0" * 64
        out = peer("bob", f"write -old {stale} {new}", ok=False)
        assert "changed since it was read" in out, out
        out = peer("bob", f"write -old ''' {new}", ok=False)
        assert "changed since it was read" in out, out
        assert "nas" not in machine.succeed("cat /home/alice/proj/chase.json")
        out = peer("eve", f"write -old {digest} {new}", ok=False)
        assert "refused" in out, out

        got = json.loads(peer("bob", f"write -old {digest} {new}"))
        assert got["root"] == "/home/alice/proj" and got["digest"] != digest, got
        machine.succeed("cmp /run/policy-test/new/chase.json /home/alice/proj/chase.json")
        machine.succeed("cmp /run/policy-test/new/chase.json.sig /home/alice/proj/chase.json.sig")
        assert machine.succeed("stat -c %U /home/alice/proj/chase.json /home/alice/proj/chase.json.sig").split() == ["alice", "alice"]
        assert machine.succeed("ls -A /home/alice/proj").split() == ["chase.json", "chase.json.sig", "sub"]
        out = alice("frisket policy verify ~/proj/chase.json")
        assert "signed by alice" in out, out

        out = peer("bob", f"write -old {digest} {new}", ok=False)
        assert "changed since it was read" in out, out
        w = [e for e in courier_log() if e.get("msg") == "write"]
        assert [e["outcome"] for e in w] == ["refuse", "refuse", "written", "refuse"], w

    with subtest("a write whose signature is for another project is refused"):
        got = json.loads(peer("bob", f"read {pid}"))
        out = peer("bob", f"write -old {got['digest']} -root /home/alice/elsewhere -file /run/policy-test/new/chase.json -sig /run/policy-test/new/chase.json.sig", ok=False)
        assert "does not verify in frisket-policy:~/elsewhere" in out, out
        machine.fail("test -e /home/alice/elsewhere/chase.json")

    with subtest("the courier runs as alice with no network"):
        unit = machine.succeed("systemctl show -p User,PrivateNetwork,RestrictAddressFamilies frisket-policy.service")
        assert "User=alice" in unit and "PrivateNetwork=yes" in unit and "AF_UNIX" in unit, unit
  '';
}
