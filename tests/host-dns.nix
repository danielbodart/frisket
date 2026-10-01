# `frisket dns` as a host runs it: socket-activated on 127.0.0.153:53 under
# a DynamicUser, with systemd-resolved sending it .internal and nothing else,
# by the frisket-dns link services.frisket.hostDNS.resolved makes.
# A project's name resolves through glibc to the address docker.Address
# gives, with no registry and nothing configured per project; a name under
# .internal that is no project's does not resolve; and frisket refuses a
# name outside .internal when asked directly, which resolved never does.
{ self }:
{ ... }:

{
  name = "frisket-host-dns";

  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    services.frisket.hostDNS.enable = true;
    environment.systemPackages = [ pkgs.dnsutils ];
  };

  testScript = ''
    machine.wait_for_unit("frisket-dns.socket")
    machine.wait_for_unit("systemd-resolved.service")
    machine.wait_for_unit("frisket-dns-link.service")

    # Through glibc and resolved, as a browser on the host asks.
    out = machine.succeed("getent ahostsv4 bodar.ts.bodar.internal")
    assert out.startswith("127.100.84.99 "), out
    out = machine.succeed("getent ahostsv4 Frisket.DanielBodart.internal")
    assert out.startswith("127.103.202.234 "), out
    machine.fail("getent ahostsv4 shop.internal")
    machine.fail("getent ahostsv4 docker.frisket.internal")

    # A name outside .internal is never sent to it: the link is no default
    # route, as resolved's global DNS= would be. With no upstream in the VM
    # the lookup fails, and frisket logs nothing of it.
    machine.fail("getent ahostsv4 example.com")
    machine.fail("journalctl -u frisket-dns.service | grep -q '\"name\":\"example.com\"'")

    # And after resolved restarts, which forgets what the link told it.
    machine.succeed("systemctl restart systemd-resolved.service")
    machine.wait_for_unit("frisket-dns-link.service")
    out = machine.succeed("getent ahostsv4 shop.example.internal")
    assert out.startswith("127.101.170.171 "), out

    # Asked directly: AAAA has no records, and outside .internal is refused.
    out = machine.succeed("dig +short @127.0.0.153 shop.example.internal A")
    assert out.strip() == "127.101.170.171", out
    out = machine.succeed("dig @127.0.0.153 shop.example.internal AAAA")
    assert "status: NOERROR" in out and "ANSWER: 0" in out, out
    out = machine.succeed("dig +tcp @127.0.0.153 nope.internal A")
    assert "status: NXDOMAIN" in out, out
    out = machine.succeed("dig @127.0.0.153 example.com A")
    assert "status: REFUSED" in out, out

    # Socket-activated, under a user made for it, holding no privilege.
    machine.succeed("systemctl is-active frisket-dns.service")
    user = machine.succeed("systemctl show -P User frisket-dns.service").strip()
    dynamic = machine.succeed("systemctl show -P DynamicUser frisket-dns.service").strip()
    assert dynamic == "yes", (user, dynamic)
    machine.succeed("journalctl -u frisket-dns.service | grep -q '\"name\":\"bodar.ts.bodar.internal\"'")
  '';
}
