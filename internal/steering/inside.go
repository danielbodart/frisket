package steering

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/nsmount"
)

// What happens inside the session's namespace, in the helper steer and connect
// each enter it with (nsnet.Enter): one entry per step, and in there the links,
// addresses, rules and routes are netlink messages from the helper itself,
// where they were an `ip` apiece. Only the ruleset is still a program, nft,
// because it is nft's language that lib.steering writes it in, and one text
// is what keeps its ports and marks from drifting from the listeners'.

// The kinds of Step.
const (
	kindRule    = "rule"    // a rule sending Mark to Table, in V6's family
	kindRoute   = "route"   // a route to Prefix by Dev, in Table (0: main); Local makes it `local`
	kindAddress = "address" // Prefix on Dev
	kindDummy   = "dummy"   // a dummy interface called Dev
	kindUp      = "up"      // Dev set up
)

// Step is one change connect or steer makes to the namespace's links,
// addresses, rules or routes. String spells it as `ip` would.
type Step struct {
	Kind   string       `json:"kind"`
	Dev    string       `json:"dev,omitempty"`
	Prefix netip.Prefix `json:"prefix,omitzero"`
	Table  int          `json:"table,omitempty"`
	Mark   uint32       `json:"mark,omitempty"`
	V6     bool         `json:"v6,omitempty"`
	Local  bool         `json:"local,omitempty"`
	NoDAD  bool         `json:"nodad,omitempty"`
}

func (st Step) String() string {
	switch st.Kind {
	case kindRule:
		return fmt.Sprintf("rule add fwmark %d lookup %d", st.Mark, st.Table)
	case kindRoute:
		s := "route add "
		if st.Local {
			s += "local "
		}
		s += fmt.Sprintf("%s dev %s", st.Prefix, st.Dev)
		if st.Table != 0 {
			s += fmt.Sprintf(" table %d", st.Table)
		}
		return s
	case kindAddress:
		s := fmt.Sprintf("address add %s dev %s", st.Prefix, st.Dev)
		if st.NoDAD {
			s += " nodad"
		}
		return s
	case kindDummy:
		return fmt.Sprintf("link add %s type dummy", st.Dev)
	case kindUp:
		return fmt.Sprintf("link set %s up", st.Dev)
	}
	return st.Kind
}

// apply makes the step, in this thread's namespace. The netlink package's own
// functions open a socket per call on the calling thread, which in the helper
// is the one that entered.
func (st Step) apply() error {
	switch st.Kind {
	case kindRule:
		r := netlink.NewRule()
		r.Family = ipFamily(st.V6)
		r.Mark = st.Mark
		r.Table = st.Table
		return netlink.RuleAdd(r)
	case kindDummy:
		attrs := netlink.NewLinkAttrs()
		attrs.Name = st.Dev
		return netlink.LinkAdd(&netlink.Dummy{LinkAttrs: attrs})
	}
	link, err := netlink.LinkByName(st.Dev)
	if err != nil {
		return err
	}
	switch st.Kind {
	case kindUp:
		return netlink.LinkSetUp(link)
	case kindAddress:
		a := &netlink.Addr{IPNet: ipNet(st.Prefix)}
		if st.NoDAD {
			a.Flags = unix.IFA_F_NODAD
		}
		return netlink.AddrAdd(link, a)
	case kindRoute:
		// The scope and type ip gives the same command: a route with no
		// gateway is on the link, and a local one is the host's.
		r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipNet(st.Prefix), Table: st.Table, Scope: netlink.SCOPE_LINK}
		if st.Local {
			r.Type, r.Scope = unix.RTN_LOCAL, netlink.SCOPE_HOST
		}
		return netlink.RouteAdd(r)
	}
	return fmt.Errorf("no step %q", st.Kind)
}

func ipFamily(v6 bool) int {
	if v6 {
		return netlink.FAMILY_V6
	}
	return netlink.FAMILY_V4
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// The requests steer and connect make of the helper.
const (
	opApply   = "apply"   // make Steps, in order, stopping at the first that fails
	opRuleset = "ruleset" // load Ruleset with the nft at Nft
	opMount   = "mount"   // put CACert, and a bundle of Roots with it, at Dir in the mount namespace at Mntns
	opTable   = "table"   // is table inet Name loaded?
	opRules   = "rules"   // V6's family's rules, as []ruleInfo
	opRoutes  = "routes"  // V6's family's routes in Table, as []routeInfo
	opLinks   = "links"   // every interface's name
)

type request struct {
	Op      string `json:"op"`
	Steps   []Step `json:"steps,omitempty"`
	V6      bool   `json:"v6,omitempty"`
	Table   int    `json:"table,omitempty"`
	Name    string `json:"name,omitempty"`
	Nft     string `json:"nft,omitempty"`
	Ruleset string `json:"ruleset,omitempty"`
	Mntns   string `json:"mntns,omitempty"`
	Dir     string `json:"dir,omitempty"`
	CACert  []byte `json:"caCert,omitempty"`
	// Roots is the host's bundle by its path, read by the helper: it is half
	// a megabyte, and sent as JSON, decoding it was 6 ms (measured).
	Roots string `json:"roots,omitempty"`
	// Entered is a helper that nsenter put in the sandbox's user namespace,
	// whose tmpfs is made after entering the mount namespace
	// (nsmount.AttachEntered); root's is made before.
	Entered bool `json:"entered,omitempty"`
}

// ruleInfo is one policy-routing rule, as much of it as connect checks. Mask
// is the whole word when the rule has none.
type ruleInfo struct {
	Mark  uint32 `json:"mark"`
	Mask  uint32 `json:"mask"`
	Table int    `json:"table"`
}

// routeInfo is one route, as much of it as connect checks.
type routeInfo struct {
	Local   bool   `json:"local"`
	Default bool   `json:"default"`
	Dev     string `json:"dev"`
}

// Serve answers one request, inside the namespace: `frisket helper`'s
// requests (nsnet.RunHelper).
func Serve(raw json.RawMessage) (any, error) {
	var r request
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	switch r.Op {
	case opApply:
		for _, st := range r.Steps {
			if err := st.apply(); err != nil {
				return nil, fmt.Errorf("%s: %w", st, err)
			}
		}
		return nil, nil
	case opRuleset:
		return nil, loadRuleset(r.Nft, r.Ruleset)
	case opMount:
		files, err := caFiles(r.Roots, r.CACert)
		if err != nil {
			return nil, err
		}
		if r.Entered {
			return nil, nsmount.AttachEntered(r.Mntns, r.Dir, files)
		}
		return nil, nsmount.Attach(r.Mntns, r.Dir, files)
	case opTable:
		return nil, hasTable(r.Name)
	case opRules:
		return rules(r.V6)
	case opRoutes:
		return routes(r.V6, r.Table)
	case opLinks:
		return links()
	}
	return nil, fmt.Errorf("no request %q", r.Op)
}

// caFiles are what the sandbox is given: the session's CA, and the bundle of
// the host's roots with it.
func caFiles(roots string, cert []byte) ([]nsmount.File, error) {
	pem, err := os.ReadFile(roots)
	if err != nil {
		return nil, fmt.Errorf("the host's roots: %w", err)
	}
	bundle, err := intercept.Bundle(pem, cert)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", roots, err)
	}
	return []nsmount.File{{Name: CACertFile, Data: cert}, {Name: CABundleFile, Data: bundle}}, nil
}

// loadRuleset runs nft from inside, where the helper is: a child of this
// thread starts in its namespace, so no second entry is needed.
func loadRuleset(nft, ruleset string) error {
	// Resolved by the caller, on the host, before anything was entered: which
	// nft runs with the sandbox's capabilities is the host's to say.
	if !filepath.IsAbs(nft) {
		return fmt.Errorf("nft %q is not an absolute path", nft)
	}
	cmd := exec.Command(nft, "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s -f -: %w: %s", nft, err, strings.TrimSpace(errb.String()))
	}
	return nil
}

// hasTable asks nf_tables for table inet name: one message, answered with the
// table or with ENOENT.
func hasTable(name string) error {
	req := nl.NewNetlinkRequest(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETTABLE, 0)
	req.AddData(&nl.Nfgenmsg{NfgenFamily: unix.NFPROTO_INET, Version: nl.NFNETLINK_V0})
	req.AddData(nl.NewRtAttr(unix.NFTA_TABLE_NAME, nl.ZeroTerminated(name)))
	_, err := req.Execute(unix.NETLINK_NETFILTER, 0)
	if errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("no table inet %s", name)
	}
	return err
}

func rules(v6 bool) ([]ruleInfo, error) {
	rs, err := netlink.RuleList(ipFamily(v6))
	if err != nil {
		return nil, err
	}
	out := make([]ruleInfo, 0, len(rs))
	for _, r := range rs {
		mask := ^uint32(0)
		if r.Mask != nil {
			mask = *r.Mask
		}
		out = append(out, ruleInfo{Mark: r.Mark, Mask: mask, Table: r.Table})
	}
	return out, nil
}

func routes(v6 bool, table int) ([]routeInfo, error) {
	rs, err := netlink.RouteListFiltered(ipFamily(v6), &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	ls, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	names := map[int]string{}
	for _, l := range ls {
		names[l.Attrs().Index] = l.Attrs().Name
	}
	out := make([]routeInfo, 0, len(rs))
	for _, r := range rs {
		def := r.Dst == nil
		if !def {
			ones, _ := r.Dst.Mask.Size()
			def = ones == 0
		}
		out = append(out, routeInfo{Local: r.Type == unix.RTN_LOCAL, Default: def, Dev: names[r.LinkIndex]})
	}
	return out, nil
}

func links() ([]string, error) {
	ls, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		out = append(out, l.Attrs().Name)
	}
	return out, nil
}
