# `frisket dns` as a host runs it: socket-activated on 127.0.0.153:53 under
# a DynamicUser, with systemd-resolved sending it .internal and nothing else.
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
    services.resolved.enable = true;
    environment.etc."systemd/resolved.conf.d/frisket.conf".text = ''
      [Resolve]
      DNS=127.0.0.153
      Domains=~internal
    '';
    environment.systemPackages = [ pkgs.dnsutils ];
  };

  testScript = ''
    machine.wait_for_unit("frisket-dns.socket")
    machine.wait_for_unit("systemd-resolved.service")

    # Through glibc and resolved, as a browser on the host asks.
    out = machine.succeed("getent ahostsv4 bodar.ts.bodar.internal")
    assert out.startswith("127.100.84.99 "), out
    out = machine.succeed("getent ahostsv4 Data-Lab.TripTease.internal")
    assert out.startswith("127.1.191.78 "), out
    machine.fail("getent ahostsv4 data-lab.internal")
    machine.fail("getent ahostsv4 docker.frisket.internal")

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
