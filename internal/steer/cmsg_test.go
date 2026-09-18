package steer

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
	"unsafe"

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

// sockaddrIn6 lays a sockaddr_in6 out the way the kernel writes one.
func sockaddrIn6(a [16]byte, port uint16) []byte {
	var b [28]byte
	binary.NativeEndian.PutUint16(b[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(b[2:4], port)
	copy(b[8:24], a[:])
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
	got, err = parseSockaddr(sockaddrIn6(netip.MustParseAddr("2606:50c0:8000::153").As16(), 443))
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
		{"truncated v6", sockaddrIn6([16]byte{}, 1)[:20]},
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
	got, err := parseSockaddr(sockaddrIn6(netip.MustParseAddr("::ffff:10.0.0.1").As16(), 53))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Addr().Is4() {
		t.Errorf("got %v, want the v4 address 10.0.0.1", got)
	}
}

func TestSockaddrIn6RoundTrips(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		b := rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "addr")
		port := rapid.Uint16().Draw(t, "port")
		got, err := parseSockaddr(sockaddrIn6([16]byte(b), port))
		if err != nil {
			t.Fatalf("parseSockaddr: %v", err)
		}
		if want := netip.AddrPortFrom(netip.AddrFrom16([16]byte(b)).Unmap(), port); got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
}

func cmsg(level, typ int, data []byte) []byte {
	b := make([]byte, unix.CmsgSpace(len(data)))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = int32(level), int32(typ)
	h.SetLen(unix.CmsgLen(len(data)))
	copy(b[unix.CmsgLen(0):], data)
	return b
}

func TestParseControlReadsTheDestinationAndTheMark(t *testing.T) {
	var mark [4]byte
	binary.NativeEndian.PutUint32(mark[:], 1)
	oob := append(cmsg(unix.SOL_IP, unix.IP_ORIGDSTADDR, sockaddrIn(t, "8.8.8.8", 53)), cmsg(unix.SOL_SOCKET, unix.SO_MARK, mark[:])...)
	r, err := ParseControl(oob)
	if err != nil {
		t.Fatal(err)
	}
	if want := (Received{Orig: netip.MustParseAddrPort("8.8.8.8:53"), Mark: 1, Marked: true}); r != want {
		t.Errorf("ParseControl = %+v, want %+v", r, want)
	}

	r, err = ParseControl(cmsg(unix.SOL_IPV6, unix.IPV6_ORIGDSTADDR, sockaddrIn6(netip.MustParseAddr("::1").As16(), 53)))
	if err != nil {
		t.Fatal(err)
	}
	if r.Orig != netip.MustParseAddrPort("[::1]:53") || r.Marked {
		t.Errorf("v6 without a mark: %+v", r)
	}
	if _, err := ParseControl(cmsg(unix.SOL_SOCKET, unix.SO_MARK, []byte{1})); err == nil {
		t.Error("a truncated SO_MARK was accepted")
	}
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

func FuzzParseControl(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		// The kernel writes these, not the workload, so the property is only
		// that a malformed buffer is an error rather than a panic: frisket must
		// not be killable by a control message it failed to understand.
		_, _ = ParseControl(b)
	})
}

// THE REFUSAL, FOR REAL, over TCP. No ruleset here, so nothing was steered: a
// connection dialled straight at the listener is accepted on a socket bound to
// the listener's own address, and that is unsteered. This is the case a
// workload creates by finding frisket's port and dialling it.
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
	dst := LocalDst(c.(*net.TCPConn))
	if v := Classify(bound, dst); v.Steered() {
		t.Fatalf("a connection dialled straight at %v was classified %+v (destination %v)", bound, v, dst)
	}
}

// And over UDP: a datagram sent straight to the socket carries a mark of zero
// -- SO_RCVMARK reports it anyway -- and is unsteered. Needs SO_RCVMARK to be
// settable here, which it is without privilege since the 2023 revert.
func TestADirectDatagramIsNeverSteered(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback to listen on: %v", err)
	}
	defer pc.Close()
	rc, err := pc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var serr error
	_ = rc.Control(func(fd uintptr) {
		if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVMARK, 1); serr == nil {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
		}
	})
	if serr != nil {
		t.Skipf("cannot ask for the mark here: %v", serr)
	}
	cl, err := net.DialUDP("udp4", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if _, err := cl.Write([]byte("direct")); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf, oob := make([]byte, 64), make([]byte, 256)
	_, oobn, _, _, err := pc.ReadMsgUDPAddrPort(buf, oob)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseControl(oob[:oobn])
	if err != nil {
		t.Fatal(err)
	}
	if !r.Marked || r.Mark != 0 {
		t.Errorf("a direct datagram's mark = %+v, want a reported zero", r)
	}
	if r.Orig.String() != pc.LocalAddr().String() {
		t.Errorf("a direct datagram's destination = %v, want the socket's own %v", r.Orig, pc.LocalAddr())
	}
	if v := ClassifyDatagram(1, r); v.Steered() || v.Reason != ReasonNotMarked {
		t.Errorf("a direct datagram was classified %+v", v)
	}
}
