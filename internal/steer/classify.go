package steer

import "net/netip"

// Decision is whether the ruleset put a connection or a datagram on this
// listener.
type Decision string

const (
	// Steered: the ruleset sent it here, and its destination is the address
	// the workload actually dialled.
	Steered Decision = "steered"
	// Unsteered: it arrived some other way, which means the workload reached
	// the listener on purpose. Refused.
	Unsteered Decision = "unsteered"
)

// The reasons something is unsteered. They are strings because they are log
// fields first: a refusal that cannot be told apart from another refusal in the
// log is a refusal nobody can explain later.
const (
	// ReasonOwnAddress: a connection's destination IS the listener. The
	// workload found the port and dialled it.
	ReasonOwnAddress = "listener's own address"
	// ReasonNoDestination: nothing usable came back from the kernel. Should
	// not happen; refused rather than guessed at.
	ReasonNoDestination = "no destination"
	// ReasonNotMarked: a datagram without the ruleset's mark. Every datagram
	// the ruleset steers carries it, and the workload cannot set one -- so a
	// datagram without it reached the listener some other way.
	ReasonNotMarked = "not marked by the ruleset"
	// ReasonBadControl: the kernel's control messages could not be read.
	ReasonBadControl = "unreadable control message"
)

// Verdict is Classify's answer: the decision, and -- when it is a refusal --
// the reason, for the log.
type Verdict struct {
	Decision Decision
	Reason   string
}

// Steered reports whether the connection may proceed.
func (v Verdict) Steered() bool { return v.Decision == Steered }

// Classify decides whether a TCP connection accepted on a listener bound to
// `bound`, whose accepted socket is bound to `dst`, was steered here.
//
// Under TPROXY the accepted socket's local address is where the client was
// going, so a steered connection has some other address -- 140.82.121.3:443,
// or 1.1.1.1:53 for TCP DNS -- and a connection that was never steered has the
// listener's own, because the client dialled 127.0.0.1:15001 itself. A
// workload inside the sandbox can reach the listener -- it is a socket in its
// own namespace, on an address it can route to -- and if it does, it is trying
// to talk to frisket rather than through it. There is nothing to say to such a
// connection, and answering one would make the destination something the
// workload chose instead of something the ruleset did.
//
// Sound only because no steered TCP connection can legitimately be FOR the
// listener's address: the ruleset steers loopback only on port 53, and the TCP
// listener is never on 53 (steering.Plan refuses it). bound must be a concrete
// address; a wildcard listener would match every loopback destination, which
// is why nsnet.Spec refuses one.
func Classify(bound, dst netip.AddrPort) Verdict {
	if !dst.IsValid() {
		return Verdict{Unsteered, ReasonNoDestination}
	}
	if sameAddrPort(bound, dst) {
		return Verdict{Unsteered, ReasonOwnAddress}
	}
	return Verdict{Decision: Steered}
}

// ClassifyDatagram decides whether a datagram was steered here, BY ITS MARK
// AND NOT BY ITS ADDRESS.
//
// The address test that works for TCP is wrong for UDP. A UDP listener must sit
// on the port the client dialled -- PKTINFO sets a reply's source address and
// not its port -- so it is bound to 127.0.0.1:53, and glibc's default
// nameserver IS 127.0.0.1:53: legitimate DNS arrives with the listener's own
// address (measured, v4 and v6). The mark is what the ruleset put on every
// packet it steered, delivered by SO_RCVMARK; the workload cannot set one
// (SO_MARK needs CAP_NET_ADMIN in the namespace's owner, which it is not). A
// datagram without it did not come through the ruleset, and is refused.
//
// want is the session's mark. Zero is what every unmarked packet carries, so a
// session whose mark is zero steers nothing.
func ClassifyDatagram(want uint32, r Received) Verdict {
	if want == 0 || !r.Marked || r.Mark != want {
		return Verdict{Unsteered, ReasonNotMarked}
	}
	if !r.Orig.IsValid() {
		return Verdict{Unsteered, ReasonNoDestination}
	}
	return Verdict{Decision: Steered}
}

// sameAddrPort compares two addresses as addresses rather than as spellings:
// ::ffff:127.0.0.1 and 127.0.0.1 are the same host, and a zone is an interface
// name that says nothing about identity. Getting this wrong is a bypass -- the
// workload dials the listener in whichever spelling the comparison misses and
// is served as if the ruleset had steered it.
func sameAddrPort(a, b netip.AddrPort) bool {
	return a.Port() == b.Port() && canon(a.Addr()) == canon(b.Addr())
}

func canon(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }
