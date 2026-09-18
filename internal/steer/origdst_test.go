package steer

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"pgregory.net/rapid"
)

func sockaddrIn(t *testing.T, addr string, port uint16) []byte {
	t.Helper()
	ap := netip.AddrPortFrom(netip.MustParseAddr(addr), port)
	var b [16]byte
	binary.NativeEndian.PutUint16(b[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(b[2:4], ap.Port())
	copy(b[4:8], ap.Addr().AsSlice())
	return b[:]
}

func TestParseSockaddr(t *testing.T) {
	got, err := parseSockaddr(sockaddrIn(t, "140.82.121.3", 443))
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddrPort("140.82.121.3:443"); got != want {
		t.Errorf("v4: got %v, want %v", got, want)
	}

	// Port holds the bytes the kernel wrote, which are already network order;
	// the round trip through NativeEndian.Uint16 is what putting a big-endian
	// pair into a host uint16 field looks like.
	sa := unix.RawSockaddrInet6{Family: unix.AF_INET6, Port: binary.NativeEndian.Uint16(bigEndian16(443))}
	sa.Addr = netip.MustParseAddr("2606:50c0:8000::153").As16()
	got, err = parseSockaddr(rawSockaddrInet6Bytes(sa))
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddrPort("[2606:50c0:8000::153]:443"); got != want {
		t.Errorf("v6: got %v, want %v", got, want)
	}
}

func TestParseSockaddrRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"family only", []byte{2, 0}},
		{"truncated v4", sockaddrIn(t, "1.2.3.4", 1)[:7]},
		{"truncated v6", rawSockaddrInet6Bytes(unix.RawSockaddrInet6{Family: unix.AF_INET6})[:20]},
		{"unknown family", func() []byte {
			b := sockaddrIn(t, "1.2.3.4", 1)
			binary.NativeEndian.PutUint16(b[0:2], 99)
			return b
		}()},
	} {
		if got, err := parseSockaddr(tc.in); err == nil {
			t.Errorf("%s: parseSockaddr accepted it and returned %v", tc.name, got)
		}
	}
}

// A v4-mapped destination must come out as the v4 address it is. Two spellings
// of one address is how a classifier, and later an allowlist, gets walked past.
func TestParseSockaddrUnmaps(t *testing.T) {
	sa := unix.RawSockaddrInet6{Family: unix.AF_INET6}
	sa.Addr = netip.MustParseAddr("::ffff:10.0.0.1").As16()
	got, err := parseSockaddr(rawSockaddrInet6Bytes(sa))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Addr().Is4() {
		t.Errorf("got %v, want the v4 address 10.0.0.1", got)
	}
}

// rawSockaddrInet6Bytes exists only so one parser serves both families; if it
// and parseSockaddr disagree about the layout, every v6 destination is wrong
// and nothing else notices.
func TestRawSockaddrInet6RoundTrips(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "addr")
		port := rapid.Uint16().Draw(t, "port")
		sa := unix.RawSockaddrInet6{Family: unix.AF_INET6, Addr: [16]byte(b)}
		sa.Port = binary.NativeEndian.Uint16(bigEndian16(port))
		got, err := parseSockaddr(rawSockaddrInet6Bytes(sa))
		if err != nil {
			t.Fatalf("parseSockaddr: %v", err)
		}
		want := netip.AddrPortFrom(netip.AddrFrom16([16]byte(b)).Unmap(), port)
		if got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
}

func bigEndian16(v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return b[:]
}

func FuzzParseSockaddr(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Add(make([]byte, 28))
	f.Add([]byte{2, 0, 1, 187, 127, 0, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := parseSockaddr(b)
		if err != nil {
			return
		}
		if !got.IsValid() {
			t.Fatalf("parseSockaddr(%v) succeeded with an invalid address %v", b, got)
		}
		if got.Addr().Is4In6() {
			t.Fatalf("parseSockaddr(%v) = %v, which is still v4-mapped", b, got)
		}
		if want := binary.BigEndian.Uint16(b[2:4]); got.Port() != want {
			t.Fatalf("port = %d, want %d", got.Port(), want)
		}
	})
}

func FuzzOriginalDstFromCmsg(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		// The kernel writes these, not the workload, so the property is only
		// that a malformed buffer is an error rather than a panic: frisket must
		// not be killable by a control message it failed to understand.
		if got, err := OriginalDstFromCmsg(b); err == nil && !got.IsValid() {
			t.Fatalf("OriginalDstFromCmsg(%v) succeeded with an invalid address", b)
		}
	})
}

// THE REFUSAL, FOR REAL. No nftables rule exists here, so nothing was
// redirected: a direct connection to the listener either has no conntrack entry
// or reports the listener's own address, and both are unsteered. This is the
// case a workload creates by finding frisket's port and dialling it.
func TestADirectConnectionIsNeverSteered(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	defer ln.Close()
	bound, err := boundAddrPort(ln.Addr())
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		c, err := net.DialTimeout("tcp4", ln.Addr().String(), 5*time.Second)
		if err == nil {
			time.Sleep(200 * time.Millisecond)
			_ = c.Close()
		}
	}()

	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	orig, lookupErr := OriginalDst(c.(*net.TCPConn))
	v := Classify(bound, orig, lookupErr)
	if v.Steered() {
		t.Fatalf("a connection dialled straight at %v was classified %+v (original destination %v, error %v)", bound, v, orig, lookupErr)
	}
	t.Logf("direct connection refused: %+v (original destination %v, error %v)", v, orig, lookupErr)
}
