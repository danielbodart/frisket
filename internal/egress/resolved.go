package egress

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

// Bounds on the resolved set. The TTL is clamped, not trusted: a zero TTL
// would refuse the connection a client makes immediately after the answer,
// and a week-long one would keep an address open long after the name moved
// away from it. The cap is the review's nit made concrete -- a client that
// resolves allowed names in a loop must not be able to pin the daemon's memory.
const (
	DefaultMinTTL      = time.Minute
	DefaultMaxTTL      = time.Hour
	DefaultResolvedCap = 4096
)

// ResolvedConfig bounds a Resolved set. Zero fields take the defaults.
type ResolvedConfig struct {
	MinTTL time.Duration
	MaxTTL time.Duration
	Cap    int
	// Now is the clock, injectable so expiry can be tested without sleeping.
	Now func() time.Time
}

// Entry is what the session's DNS said about one address.
type Entry struct {
	// Name is the allowed name that was asked for -- the question, not the
	// end of a CNAME chain, because the question is what the policy allowed.
	Name string
	// Query is the DNS query's sequence number in the session, so the query
	// and the connection it caused can be joined in the log.
	Query   uint64
	Expires time.Time
}

// Resolved is one session's set of addresses its DNS answered for allowed
// names: the egress allowlist. It is written by the DNS server and read at
// connect, and it is per session because an answer given to one sandbox is not
// a permission for another.
type Resolved struct {
	cfg ResolvedConfig

	mu    sync.Mutex
	index map[netip.Addr]*list.Element
	// order is least recently recorded first. Eviction takes the front: O(1),
	// where ottergate's rate limiter scans its whole map to evict one entry.
	order *list.List
}

type resolvedItem struct {
	addr  netip.Addr
	entry Entry
}

// NewResolved makes an empty set.
func NewResolved(cfg ResolvedConfig) *Resolved {
	if cfg.MinTTL <= 0 {
		cfg.MinTTL = DefaultMinTTL
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = DefaultMaxTTL
	}
	if cfg.MaxTTL < cfg.MinTTL {
		cfg.MaxTTL = cfg.MinTTL
	}
	if cfg.Cap <= 0 {
		cfg.Cap = DefaultResolvedCap
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Resolved{cfg: cfg, index: map[netip.Addr]*list.Element{}, order: list.New()}
}

// canonAddr is the one spelling an address is stored and looked up under.
// The DNS answer carries 1.2.3.4, the kernel may report ::ffff:1.2.3.4, and if
// those were two keys the allowlist would refuse its own answers -- or, the
// other way round, accept a spelling nobody resolved.
func canonAddr(a netip.Addr) netip.Addr { return a.WithZone("").Unmap() }

// Record notes that the session's DNS answered a for name, valid for ttl
// (clamped). Implements the dns package's Recorder.
func (r *Resolved) Record(name string, a netip.Addr, ttl time.Duration, query uint64) {
	if !a.IsValid() {
		return
	}
	a = canonAddr(a)
	ttl = min(max(ttl, r.cfg.MinTTL), r.cfg.MaxTTL)
	expires := r.cfg.Now().Add(ttl)

	r.mu.Lock()
	defer r.mu.Unlock()
	if el, ok := r.index[a]; ok {
		it := el.Value.(*resolvedItem)
		// The newest answer names the address, but an earlier, longer promise
		// to the client still stands: the client may be holding that answer.
		it.entry.Name, it.entry.Query = name, query
		if expires.After(it.entry.Expires) {
			it.entry.Expires = expires
		}
		r.order.MoveToBack(el)
		return
	}
	for r.order.Len() >= r.cfg.Cap {
		front := r.order.Front()
		delete(r.index, front.Value.(*resolvedItem).addr)
		r.order.Remove(front)
	}
	r.index[a] = r.order.PushBack(&resolvedItem{addr: a, entry: Entry{Name: name, Query: query, Expires: expires}})
}

// Lookup returns the entry for a if the session resolved it and it has not
// expired.
func (r *Resolved) Lookup(a netip.Addr) (Entry, bool) {
	if !a.IsValid() {
		return Entry{}, false
	}
	a = canonAddr(a)
	r.mu.Lock()
	defer r.mu.Unlock()
	el, ok := r.index[a]
	if !ok {
		return Entry{}, false
	}
	it := el.Value.(*resolvedItem)
	if !r.cfg.Now().Before(it.entry.Expires) {
		delete(r.index, a)
		r.order.Remove(el)
		return Entry{}, false
	}
	return it.entry, true
}

// Len is the number of addresses held, expired or not.
func (r *Resolved) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.order.Len()
}
