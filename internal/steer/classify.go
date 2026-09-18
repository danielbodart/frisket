package steer

import "net/netip"

// Decision is whether the kernel put a connection on this listener.
type Decision string

const (
	// Steered: the kernel redirected it, and the original destination is the
	// address the workload actually dialled.
	Steered Decision = "steered"
	// Unsteered: it arrived some other way, which means the workload connected
	// to the listener on purpose. Refused.
	Unsteered Decision = "unsteered"
)

// The reasons a connection is unsteered. They are strings because they are log
// fields first: a refusal that cannot be told apart from another refusal in the
// log is a refusal nobody can explain later.
const (
	// ReasonNoConntrack: the getsockopt failed. Usually ENOENT or ENOTCONN --
	// there is no NAT entry because nothing was translated.
	ReasonNoConntrack = "no conntrack entry"
	// ReasonOwnAddress: the original destination IS the listener. The workload
	// found the port and dialled it.
	ReasonOwnAddress = "listener's own address"
	// ReasonNoDestination: the lookup succeeded and produced nothing usable.
	// Should not happen; refused rather than guessed at.
	ReasonNoDestination = "no destination"
)

// Verdict is Classify's answer: the decision, and -- when it is a refusal --
// the reason, for the log.
type Verdict struct {
	Decision Decision
	Reason   string
}

// Steered reports whether the connection may proceed.
func (v Verdict) Steered() bool { return v.Decision == Steered }

// Classify decides whether a connection accepted on a listener bound to `bound`
// was steered here by the kernel.
//
// Unsteered is "the getsockopt failed" OR "the original destination is the
// listener's own address", and those are the only two shapes a direct
// connection can take. A workload inside the sandbox can reach the listener --
// it is a socket in its own namespace, on an address it can route to -- and if
// it does, it is trying to talk to frisket rather than through it. There is
// nothing to say to such a connection, and answering one would make the
// destination something the workload asserts instead of something the kernel
// recorded.
//
// The error is checked FIRST and can never be overridden. This is the same
// ordering ottergate gets wrong in its egress policy, where the allowlist is
// consulted before the structural refusal; here there is nothing that could
// promote a failed lookup to an acceptance, by construction.
//
// bound must be a concrete address. A wildcard listener makes the second test
// meaningless, which is why nsnet.Spec refuses one.
func Classify(bound, orig netip.AddrPort, lookupErr error) Verdict {
	if lookupErr != nil {
		return Verdict{Unsteered, ReasonNoConntrack}
	}
	if !orig.IsValid() {
		return Verdict{Unsteered, ReasonNoDestination}
	}
	if sameAddrPort(bound, orig) {
		return Verdict{Unsteered, ReasonOwnAddress}
	}
	return Verdict{Decision: Steered}
}

// sameAddrPort compares two addresses as addresses rather than as spellings:
// ::ffff:127.0.0.1 and 127.0.0.1 are the same host, and a zone is an interface
// name that says nothing about identity. Getting this wrong is a bypass -- the
// workload dials the listener in whichever spelling the comparison misses and
// is served as if the kernel had steered it.
func sameAddrPort(a, b netip.AddrPort) bool {
	return a.Port() == b.Port() && canon(a.Addr()) == canon(b.Addr())
}

func canon(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }
