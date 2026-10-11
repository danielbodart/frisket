package sudomsg

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func hostKey(t testing.TB, seed byte) []byte {
	t.Helper()
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)).Public())
	if err != nil {
		t.Fatal(err)
	}
	return pub.Marshal()
}

func example(t testing.TB) *Message {
	return &Message{
		Nonce:    bytes.Repeat([]byte{0xab}, NonceSize),
		HostKeys: [][]byte{hostKey(t, 1), hostKey(t, 2)},
		User:     "dan",
		RunAs:    "root",
		Cwd:      "/home/dan",
		Argv:     []string{"/run/current-system/sw/bin/systemctl", "stop", "sshd.service"},
		Level:    "danger",
		Reasons:  []string{"touches a unit that guards this machine", "LD_PRELOAD=/tmp/x.so"},
	}
}

func TestTheMessageEncodesToTheGoldenBytesAndParsesBackFieldForField(t *testing.T) {
	b, err := example(t).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "message.bin")
	if *update {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, want) {
		t.Fatalf("got\n%x\nwant\n%x", b, want)
	}
	if !bytes.HasPrefix(b, []byte("\x00\x00\x00\x0ffrisket-sudo-v1")) {
		t.Errorf("starts %x", b[:19])
	}
	m, err := Parse(want)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m, example(t)) {
		t.Errorf("parsed %+v", m)
	}
}

func TestAMessageThatDoesNotParseStrictlyIsRefused(t *testing.T) {
	good, err := example(t).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	enc := func(f func(*Message)) []byte {
		m := example(t)
		f(m)
		var b []byte
		b = append(b, prefix...)
		b = appendString(b, m.Nonce)
		b = appendList(b, m.HostKeys)
		b = appendString(b, []byte(m.User))
		b = appendString(b, []byte(m.RunAs))
		b = appendString(b, []byte(m.Cwd))
		b = appendList(b, byteSlices(m.Argv))
		b = appendString(b, []byte(m.Level))
		return appendList(b, byteSlices(m.Reasons))
	}
	for name, b := range map[string][]byte{
		"a short nonce":     enc(func(m *Message) { m.Nonce = m.Nonce[:31] }),
		"a long nonce":      enc(func(m *Message) { m.Nonce = append(m.Nonce, 0) }),
		"no host keys":      enc(func(m *Message) { m.HostKeys = nil }),
		"a bad key blob":    enc(func(m *Message) { m.HostKeys[1] = []byte("\x00\x00\x00\x07ssh-rsa") }),
		"an unknown level":  enc(func(m *Message) { m.Level = "normal" }),
		"a missing field":   good[:len(good)-4],
		"trailing bytes":    append(bytes.Clone(good), 0),
		"another magic":     append([]byte("\x00\x00\x00\x0ffrisket-sudo-v2"), good[19:]...),
		"a count past data": countPast(good),
		"empty":             nil,
	} {
		if m, err := Parse(b); err == nil {
			t.Errorf("%s: parsed %+v", name, m)
		}
	}
}

func countPast(good []byte) []byte {
	b := bytes.Clone(good)
	binary.BigEndian.PutUint32(b[len(prefix)+4+NonceSize:], 9)
	return b
}

func TestMarshalRefusesWhatParseWould(t *testing.T) {
	for name, f := range map[string]func(*Message){
		"a short nonce":    func(m *Message) { m.Nonce = m.Nonce[:1] },
		"no host keys":     func(m *Message) { m.HostKeys = nil },
		"an unknown level": func(m *Message) { m.Level = "normal" },
		"too long":         func(m *Message) { m.Argv = append(m.Argv, strings.Repeat("x", MaxSize)) },
	} {
		m := example(t)
		f(m)
		if _, err := m.Marshal(); err == nil {
			t.Errorf("%s: marshalled", name)
		}
	}
	m := example(t)
	m.Argv = []string{strings.Repeat("x", MaxSize)}
	if _, err := m.Marshal(); !errors.Is(err, ErrTooLong) {
		t.Errorf("got %v", err)
	}
}

func TestOnlyTheLengthPrefixedMagicHasIt(t *testing.T) {
	for _, b := range []string{"frisket-sudo-v1", "\x00\x00\x00\x10frisket-sudo-v1", "SSHSIG", "\x00\x00\x00\x0ffrisket-sudo-v"} {
		if HasMagic([]byte(b)) {
			t.Errorf("%q has the magic", b)
		}
	}
	if !HasMagic([]byte("\x00\x00\x00\x0ffrisket-sudo-v1")) {
		t.Error("the magic alone has no magic")
	}
}

func FuzzNoRemoteSudoMessageCrashesTheParser(f *testing.F) {
	good, err := example(f).Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(prefix))
	f.Add(binary.BigEndian.AppendUint32([]byte(prefix), NonceSize))
	f.Add(append([]byte(prefix), 0xff, 0xff, 0xff, 0xff))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Parse(b)
		if err != nil {
			return
		}
		again, err := m.Marshal()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("parsed %x, marshalled %x, %v", b, again, err)
		}
	})
}
