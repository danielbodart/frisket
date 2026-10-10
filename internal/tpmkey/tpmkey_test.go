package tpmkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
	"golang.org/x/crypto/ssh"
)

type swtpm struct {
	t    *testing.T
	dir  string
	sock string
	ln   *os.File
	cmd  *exec.Cmd
}

func startSwtpm(t *testing.T) *swtpm {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		if os.Getenv("FRISKET_REQUIRE_SWTPM") != "" {
			t.Fatalf("FRISKET_REQUIRE_SWTPM is set and there is no swtpm: %v", err)
		}
		t.Skipf("no swtpm: %v", err)
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	ln, err := l.File()
	l.Close()
	if err != nil {
		t.Fatal(err)
	}
	s := &swtpm{t: t, dir: dir, sock: sock, ln: ln}
	s.start()
	t.Cleanup(func() {
		s.stop()
		ln.Close()
	})
	return s
}

func (s *swtpm) start() {
	s.t.Helper()
	s.cmd = exec.Command("swtpm", "socket", "--tpm2",
		"--tpmstate", "dir="+s.dir,
		"--server", "type=unixio,fd=3",
		"--flags", "not-need-init,startup-clear")
	s.cmd.ExtraFiles = []*os.File{s.ln}
	if err := s.cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
}

func (s *swtpm) stop() {
	s.cmd.Process.Kill()
	s.cmd.Wait()
}

func (s *swtpm) restart() {
	s.stop()
	s.start()
}

func (s *swtpm) dial() transport.TPMCloser {
	s.t.Helper()
	tpm, err := linuxudstpm.Open(s.sock)
	if err != nil {
		s.t.Fatal(err)
	}
	return tpm
}

func (s *swtpm) tpm(opens *int) *TPM {
	return New(func() (transport.TPMCloser, error) {
		if opens != nil {
			*opens++
		}
		return linuxudstpm.Open(s.sock)
	})
}

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

func loadOne(t *testing.T, dir string) *Key {
	t.Helper()
	keys, err := Load(dir, discard())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("loaded %d keys, want 1", len(keys))
	}
	return keys[0]
}

func sign(t *testing.T, tp *TPM, k *Key) ([]byte, []byte, error) {
	t.Helper()
	data := make([]byte, 64)
	rand.Read(data)
	sum := sha256.Sum256(data)
	sig, err := tp.sign(k, sum[:])
	return sum[:], sig, err
}

func mustSign(t *testing.T, tp *TPM, k *Key) {
	t.Helper()
	sum, sig, err := sign(t, tp, k)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsaVerify(k, sum, sig) {
		t.Fatal("the signature does not verify")
	}
}

// stockKey makes a key as ssh-tpm-keygen's doCreateSSHKey does with its
// defaults: the owner hierarchy, an empty passphrase, a comment.
func stockKey(t *testing.T, s *swtpm, dir, name string, alg tpm2.TPMAlgID, bits int) {
	t.Helper()
	tpm := s.dial()
	defer tpm.Close()
	k, err := keyfile.NewLoadableKey(tpm, alg, bits, nil,
		keyfile.WithParent(tpm2.TPMRHOwner),
		keyfile.WithUserAuth([]byte("")),
		keyfile.WithDescription("dan@dan-blade"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), k.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAStockKeygenFileLoadsAndSigns(t *testing.T) {
	s := startSwtpm(t)
	dir := t.TempDir()
	stockKey(t, s, dir, "id_ecdsa.tpm", tpm2.TPMAlgECC, 256)

	k := loadOne(t, dir)
	if k.Comment != "dan@dan-blade" {
		t.Errorf("comment %q", k.Comment)
	}
	mustSign(t, s.tpm(nil), k)
}

func TestASignatureVerifiesWithTheKeysPublicKey(t *testing.T) {
	s := startSwtpm(t)
	dir := t.TempDir()
	tp := s.tpm(nil)
	if _, err := Generate(tp, dir, "dan@dan-desktop", false); err != nil {
		t.Fatal(err)
	}
	line, err := os.ReadFile(filepath.Join(dir, "id_ecdsa.pub"))
	if err != nil {
		t.Fatal(err)
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		t.Fatal(err)
	}
	if comment != "dan@dan-desktop" || pub.Type() != ssh.KeyAlgoECDSA256 {
		t.Fatalf("pub file %q", line)
	}

	k := loadOne(t, dir)
	signer, err := ssh.NewSignerFromSigner(k.Signer(tp))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("session id and userauth request")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify(data, sig); err != nil {
		t.Fatalf("the signature does not verify with the .pub: %v", err)
	}
}

func TestAFileThatDoesNotParseIsSkippedAndTheRestLoad(t *testing.T) {
	s := startSwtpm(t)
	dir := t.TempDir()
	stockKey(t, s, dir, "good.tpm", tpm2.TPMAlgECC, 256)
	stockKey(t, s, dir, "rsa.tpm", tpm2.TPMAlgRSA, 2048)
	os.WriteFile(filepath.Join(dir, "junk.tpm"), []byte("-----BEGIN TSS2 PRIVATE KEY-----\nnope\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "empty.tpm"), nil, 0o600)
	os.WriteFile(filepath.Join(dir, "good.pub"), []byte("not a key file"), 0o600)
	good, err := os.ReadFile(filepath.Join(dir, "good.tpm"))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*keyfile.TPMKey){
		"passphrase.tpm":  func(k *keyfile.TPMKey) { k.EmptyAuth = false },
		"endorsement.tpm": func(k *keyfile.TPMKey) { k.Parent = tpm2.TPMRHEndorsement },
	} {
		k, err := keyfile.Decode(good)
		if err != nil {
			t.Fatal(err)
		}
		change(k)
		os.WriteFile(filepath.Join(dir, name), k.Bytes(), 0o600)
	}

	var log bytes.Buffer
	keys, err := Load(dir, slog.New(slog.NewJSONHandler(&log, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || filepath.Base(keys[0].Path) != "good.tpm" {
		t.Fatalf("loaded %v, want only good.tpm", keys)
	}
	for _, name := range []string{"rsa.tpm", "junk.tpm", "empty.tpm", "passphrase.tpm", "endorsement.tpm"} {
		if strings.Count(log.String(), name) != 1 {
			t.Errorf("want one log line for %s:\n%s", name, log.String())
		}
	}
	if strings.Contains(log.String(), "good.pub") {
		t.Errorf("a file not named *.tpm was looked at:\n%s", log.String())
	}
	mustSign(t, s.tpm(nil), keys[0])
}

func TestNoKeysIsNotAnError(t *testing.T) {
	keys, err := Load(t.TempDir(), discard())
	if err != nil || len(keys) != 0 {
		t.Fatalf("got %v, %v", keys, err)
	}
}

func TestAClearedTPMSaysClearedNotCorrupt(t *testing.T) {
	s := startSwtpm(t)
	dir := t.TempDir()
	tp := s.tpm(nil)
	if _, err := Generate(tp, dir, "", false); err != nil {
		t.Fatal(err)
	}
	k := loadOne(t, dir)
	mustSign(t, tp, k)

	tpm := s.dial()
	_, err := tpm2.Clear{AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHLockout, Auth: tpm2.PasswordAuth(nil)}}.Execute(tpm)
	tpm.Close()
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = sign(t, tp, k)
	if !errors.Is(err, ErrCleared) {
		t.Fatalf("got %v, want %v", err, ErrCleared)
	}
	if !strings.Contains(err.Error(), "TPM cleared or a different chip") {
		t.Errorf("error text %q", err)
	}
}

func TestLockoutIsNamedAndNotRetried(t *testing.T) {
	s := startSwtpm(t)
	dir := t.TempDir()
	var opens int
	tp := s.tpm(&opens)
	if _, err := Generate(tp, dir, "", false); err != nil {
		t.Fatal(err)
	}
	k := loadOne(t, dir)
	mustSign(t, tp, k)

	tpm := s.dial()
	h := tp.loaded[k]
	h.Auth = tpm2.PasswordAuth([]byte("wrong"))
	sum := sha256.Sum256([]byte("x"))
	var err error
	for range 100 {
		_, err = tpm2.Sign{
			KeyHandle:  h,
			Digest:     tpm2.TPM2BDigest{Buffer: sum[:]},
			InScheme:   tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgECDSA, Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256})},
			Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
		}.Execute(tpm)
		if !errors.Is(err, tpm2.TPMRCAuthFail) {
			break
		}
	}
	tpm.Close()
	if !errors.Is(err, tpm2.TPMRCLockout) {
		t.Fatalf("wrong passwords ended with %v, want lockout", err)
	}

	before := opens
	_, _, err = sign(t, tp, k)
	if !errors.Is(err, ErrLockout) {
		t.Fatalf("got %v, want %v", err, ErrLockout)
	}
	if opens != before {
		t.Errorf("the TPM was opened again %d times; lockout must not be retried", opens-before)
	}
}

func TestNoDAFlagSetsTheAttribute(t *testing.T) {
	s := startSwtpm(t)
	tp := s.tpm(nil)
	for _, noDA := range []bool{false, true} {
		dir := t.TempDir()
		if _, err := Generate(tp, dir, "", noDA); err != nil {
			t.Fatal(err)
		}
		k := loadOne(t, dir)
		pub, err := k.tk.Pubkey.Contents()
		if err != nil {
			t.Fatal(err)
		}
		if pub.ObjectAttributes.NoDA != noDA {
			t.Errorf("noDA %v wrote NoDA %v", noDA, pub.ObjectAttributes.NoDA)
		}
	}
}

func TestTheCachedParentIsRebuiltAfterATPMRestart(t *testing.T) {
	s := startSwtpm(t)
	dir := t.TempDir()
	tp := s.tpm(nil)
	if _, err := Generate(tp, dir, "", false); err != nil {
		t.Fatal(err)
	}
	k := loadOne(t, dir)
	mustSign(t, tp, k)
	s.restart()
	mustSign(t, tp, k)
}

func TestSigningDoesNotLeakFileDescriptorsOrTransientObjects(t *testing.T) {
	s := startSwtpm(t)
	dir := t.TempDir()
	tp := s.tpm(nil)
	if _, err := Generate(tp, dir, "", false); err != nil {
		t.Fatal(err)
	}
	k := loadOne(t, dir)
	mustSign(t, tp, k)
	fds := countFDs(t)
	for i := range 100 {
		if i == 50 {
			s.restart()
		}
		mustSign(t, tp, k)
	}
	if got := countFDs(t); got != fds {
		t.Errorf("%d descriptors after 100 signs, %d before", got, fds)
	}
	tpm := s.dial()
	defer tpm.Close()
	rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapHandles, Property: uint32(tpm2.TPMHTTransient) << 24, PropertyCount: 64}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	handles, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		t.Fatal(err)
	}
	if len(handles.Handle) != 2 {
		t.Errorf("%d transient objects loaded, want the parent and the key", len(handles.Handle))
	}
}

func countFDs(t *testing.T) int {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(fds)
}

func ecdsaVerify(k *Key, sum, sig []byte) bool { return ecdsa.VerifyASN1(k.Public, sum, sig) }
