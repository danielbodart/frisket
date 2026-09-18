package egress

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// DefaultHostMaxAge is how old the host's address list may be before a dial
// re-reads it. Short, because the list is not static: SLAAC temporary
// addresses rotate daily, a VPN coming up adds an interface, DHCP renews. A
// static list, or one read at startup, is a list of the addresses the host
// USED to have.
const DefaultHostMaxAge = time.Second

// HostAddrs is every address the host itself owns, read from the kernel at
// runtime and re-read when stale.
//
// "Owns" means what the kernel would deliver locally: every interface address,
// and every prefix in the local routing table -- which also catches AnyIP
// (`ip route add local 203.0.113.0/24 dev lo`), where a host answers for a
// whole prefix no interface lists. A sandbox that could reach any of these
// could reach every service the host binds to a non-loopback address, the
// host's global IPv6 address above all.
type HostAddrs struct {
	source func() ([]netip.Prefix, error)
	maxAge time.Duration
	now    func() time.Time

	mu   sync.Mutex
	pfx  []netip.Prefix
	at   time.Time
	read bool
}

// NewHostAddrs reads the live host. maxAge <= 0 means DefaultHostMaxAge.
func NewHostAddrs(maxAge time.Duration) *HostAddrs {
	if maxAge <= 0 {
		maxAge = DefaultHostMaxAge
	}
	return &HostAddrs{source: readHostPrefixes, maxAge: maxAge, now: time.Now}
}

// StaticHostAddrs is a fixed set, for tests: a synthetic "host-owned" address
// that is not really on any interface, so a test can show it is refused without
// depending on what the machine running the test happens to have.
func StaticHostAddrs(prefixes ...netip.Prefix) *HostAddrs {
	p := append([]netip.Prefix(nil), prefixes...)
	return &HostAddrs{source: func() ([]netip.Prefix, error) { return p, nil }, now: time.Now}
}

// HostAddrsFrom reads from an arbitrary source, re-read when older than maxAge
// (never, when maxAge <= 0). For tests that need a source which fails, or one
// that changes under them.
func HostAddrsFrom(source func() ([]netip.Prefix, error), maxAge time.Duration, now func() time.Time) *HostAddrs {
	if now == nil {
		now = time.Now
	}
	return &HostAddrs{source: source, maxAge: maxAge, now: now}
}

// Refresh re-reads the host's addresses now.
//
// On failure the previous list is DISCARDED and every lookup fails until a
// read succeeds, so Classify refuses everything with ReasonHostUnknown. Keeping
// the old list would be keeping a list of addresses the host used to have, at
// exactly the moment we cannot tell what changed; a refused connection is
// logged and retried, and an accepted one to the host is not recoverable.
func (h *HostAddrs) Refresh() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.refreshLocked()
}

func (h *HostAddrs) refreshLocked() error {
	raw, err := h.source()
	if err != nil {
		h.pfx, h.read = nil, false
		return fmt.Errorf("reading the host's own addresses: %w", err)
	}
	pfx := make([]netip.Prefix, 0, len(raw))
	for _, p := range raw {
		if !p.IsValid() {
			continue
		}
		a := p.Addr().WithZone("")
		bits := p.Bits()
		if a.Is4In6() {
			a, bits = a.Unmap(), max(bits-96, 0)
		}
		pfx = append(pfx, netip.PrefixFrom(a, bits).Masked())
	}
	h.pfx, h.at, h.read = pfx, h.now(), true
	return nil
}

// Contains reports whether the host owns a. An error means the answer is
// unknown and the caller must treat it as "yes".
func (h *HostAddrs) Contains(a netip.Addr) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// The lock is held across the re-read on purpose: concurrent dials wait for
	// one read instead of each doing their own, and none of them decides on
	// the stale list while the fresh one is being fetched.
	if !h.read || (h.maxAge > 0 && h.now().Sub(h.at) >= h.maxAge) {
		if err := h.refreshLocked(); err != nil {
			return false, err
		}
	}
	a = a.WithZone("").Unmap()
	for _, p := range h.pfx {
		if p.Contains(a) {
			return true, nil
		}
	}
	return false, nil
}

// Prefixes returns the current list, for the log and for tests.
func (h *HostAddrs) Prefixes() ([]netip.Prefix, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.read {
		if err := h.refreshLocked(); err != nil {
			return nil, err
		}
	}
	return append([]netip.Prefix(nil), h.pfx...), nil
}

// readHostPrefixes is the live source: interface addresses, each as a single
// address (NOT its subnet -- the rest of the subnet is other hosts, which the
// structural table or the allowlist decides about), plus every local and
// anycast route in the local table.
func readHostPrefixes() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("interface addresses: %w", err)
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	routes, err := localRoutes()
	if err != nil {
		return nil, err
	}
	return append(out, routes...), nil
}

// localRoutes dumps the routing tables and keeps what the kernel delivers to
// this host. Only the local table: a `local 0.0.0.0/0` route in a policy table
// is how TPROXY is set up, and it means "local for the packets that rule
// selects", not "the host owns the internet".
func localRoutes() ([]netip.Prefix, error) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("route dump: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, fmt.Errorf("route dump: %w", err)
	}
	return parseLocalRoutes(msgs)
}

// parseLocalRoutes reads the rtmsg header by offset rather than through
// unsafe: family(0) dst_len(1) src_len(2) tos(3) table(4) protocol(5) scope(6)
// type(7) flags(8..11).
func parseLocalRoutes(msgs []syscall.NetlinkMessage) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type == syscall.NLMSG_ERROR {
			return nil, fmt.Errorf("route dump: kernel returned an error message")
		}
		if m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < syscall.SizeofRtMsg {
			continue
		}
		dstLen, table, typ := int(m.Data[1]), uint32(m.Data[4]), m.Data[7]
		if typ != syscall.RTN_LOCAL && typ != syscall.RTN_ANYCAST {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(m)
		if err != nil {
			return nil, fmt.Errorf("route attributes: %w", err)
		}
		var dst netip.Addr
		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.RTA_TABLE:
				if len(a.Value) == 4 {
					// Host order: the kernel filled the struct.
					table = binary.NativeEndian.Uint32(a.Value)
				}
			case syscall.RTA_DST:
				if ip, ok := netip.AddrFromSlice(a.Value); ok {
					dst = ip
				}
			}
		}
		if table != syscall.RT_TABLE_LOCAL || !dst.IsValid() {
			continue
		}
		dst = dst.Unmap()
		if dstLen > dst.BitLen() {
			continue
		}
		out = append(out, netip.PrefixFrom(dst, dstLen).Masked())
	}
	return out, nil
}
