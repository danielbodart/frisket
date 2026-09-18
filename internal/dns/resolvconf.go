package dns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/danielbodart/frisket/internal/watch"
)

// HostResolvConf is where the host says its resolver is.
const HostResolvConf = "/etc/resolv.conf"

// ResolvConf is Upstream towards whichever servers the host's resolv.conf
// names now. A laptop changes network, and its resolver with it; an upstream
// read once at start would keep asking the old one for as long as frisket ran.
//
// The file is followed the way credential files are (internal/watch): its
// directory is watched, so a replacement by rename is seen, and where a watch
// cannot be trusted -- resolv.conf is a symlink, or the watch was lost -- the
// file's identity is checked on every query. Nothing else is consulted: the
// file is the host's answer, whoever wrote it.
//
// A query takes the servers current when it starts and keeps them to the end,
// retries and TCP fallback included; the next query takes whatever is current
// then. A file that names no server, or cannot be read or parsed, is not a
// change: the servers in use are kept, and the file's fault is logged.
type ResolvConf struct {
	path string
	base Upstream
	log  *slog.Logger

	// cur is nil until the file has once named a server.
	cur   atomic.Pointer[Upstream]
	watch *watch.File
}

// FollowResolvConf reads path now and follows it from then on. base is every
// field of the Upstream but its servers, which come from the file.
//
// A file that names no usable server now is not an error: queries fail until
// it does, as they would with no network. A directory that cannot be watched
// is, because that is configuration.
func FollowResolvConf(path string, base Upstream, log *slog.Logger) (*ResolvConf, error) {
	if log == nil {
		return nil, errors.New("dns: FollowResolvConf needs a logger")
	}
	base.Servers = nil
	r := &ResolvConf{path: path, base: base, log: log}
	w, err := watch.New(path, "dns upstream", r.load, log)
	if err != nil {
		return nil, fmt.Errorf("dns: %w", err)
	}
	r.watch = w
	return r, nil
}

// Exchange asks q of the servers the file names as the query starts.
func (r *ResolvConf) Exchange(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, Trace, error) {
	r.watch.Check()
	up := r.cur.Load()
	if up == nil {
		return nil, Trace{}, fmt.Errorf("no upstream DNS servers: %s has named none usable", r.path)
	}
	return up.Exchange(ctx, q)
}

// Servers is what the next query will be asked of.
func (r *ResolvConf) Servers() []netip.AddrPort {
	if up := r.cur.Load(); up != nil {
		return slices.Clone(up.Servers)
	}
	return nil
}

// Close stops following the file. Queries keep the servers last read.
func (r *ResolvConf) Close() error { return r.watch.Close() }

// load reads the file and publishes its servers if they changed, with one log
// line saying so. The watcher never calls it concurrently with itself, which
// is what makes Load-then-Store safe here.
func (r *ResolvConf) load() {
	prev := r.cur.Load()
	servers, err := readResolvConf(r.path)
	if err != nil {
		attrs := []any{"path", r.path, "error", err.Error()}
		if prev != nil {
			attrs = append(attrs, "outcome", "kept", "servers", addrs(prev.Servers))
		} else {
			attrs = append(attrs, "outcome", "none")
		}
		r.log.Error("dns upstream", attrs...)
		return
	}
	if prev != nil && slices.Equal(prev.Servers, servers) {
		return
	}
	next := r.base
	next.Servers = servers
	attrs := []any{"path", r.path, "outcome", "changed", "servers", addrs(servers)}
	if prev != nil {
		attrs = append(attrs, "previous", addrs(prev.Servers))
	}
	// Logged before it is published, so no query goes to a server the log
	// has not yet named.
	r.log.Info("dns upstream", attrs...)
	r.cur.Store(&next)
}

func readResolvConf(path string) ([]netip.AddrPort, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseResolvConf(string(b))
}

// ParseResolvConf returns the servers a resolv.conf's nameserver lines name,
// with :53 assumed. The file is the host's own, written by root, and this reads
// one keyword out of it. A nameserver that is not an address makes the whole
// file unusable rather than quietly shorter, and so does a file with none.
func ParseResolvConf(conf string) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for line := range strings.SplitSeq(conf, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		// A zone (fe80::1%eth0) names an interface on the host; netip keeps
		// it for the dial.
		ap, err := ParseServer(f[1])
		if err != nil {
			return nil, err
		}
		out = append(out, ap)
	}
	if len(out) == 0 {
		return nil, errors.New("names no nameserver")
	}
	return out, nil
}

// ParseServer is a DNS server as configured: an address, with :53 assumed, or
// address:port. Never a name: the resolver has no resolver to resolve it with.
func ParseServer(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("DNS server %q: want an address, or address:port", s)
	}
	return netip.AddrPortFrom(a, 53), nil
}

func addrs(servers []netip.AddrPort) []string {
	out := make([]string, len(servers))
	for i, s := range servers {
		out[i] = s.String()
	}
	return out
}
