package courier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielbodart/frisket/internal/peer"
	"github.com/danielbodart/frisket/projpolicy"
	"golang.org/x/crypto/ssh"
)

type harness struct {
	t       *testing.T
	home    string
	socket  string
	signer  ssh.Signer
	s       *Server
	peers   chan *peer.Requester
	cgroups map[string]uint64
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir, err := os.MkdirTemp("", "courier")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(k)
	h := &harness{
		t: t, home: filepath.Join(dir, "home"), socket: filepath.Join(dir, "sock"), signer: signer,
		peers: make(chan *peer.Requester, 4), cgroups: map[string]uint64{"frisket-signer.service": 11, "frisket-sudo.service": 12},
	}
	line := `dan namespaces="frisket-policy:*" ` + string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	signers, err := projpolicy.ParseAllowedSigners([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	h.s = &Server{
		Name: "chase.json", Home: h.home, UID: os.Getuid(),
		Signers: func() (*projpolicy.AllowedSigners, error) { return signers, nil },
		Peers:   map[string]int{"frisket-signer.service": 951, "frisket-sudo.service": 952},
		Log:     slog.New(slog.NewJSONHandler(io.Discard, nil)),
		who:     func(*net.UnixConn) (*peer.Requester, error) { return <-h.peers, nil },
		unitCgroup: func(unit string) (uint64, error) {
			if ino, ok := h.cgroups[unit]; ok {
				return ino, nil
			}
			return 0, os.ErrNotExist
		},
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: h.socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go h.s.Serve(ln)
	return h
}

// as queues the next connection's peer.
func (h *harness) as(uid int, cgroup uint64) *harness {
	h.peers <- &peer.Requester{PeerUID: uid, CgroupID: cgroup, Chain: []peer.Link{{Pid: 4242, Cgroup: "/system.slice/x.service"}}}
	return h
}

func (h *harness) signer951() *harness { return h.as(951, 11) }

func (h *harness) mkdir(rel string) string {
	p := filepath.Join(h.home, rel)
	if err := os.MkdirAll(p, 0o755); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *harness) sign(root string, b []byte) []byte {
	ns, err := projpolicy.Namespace(root, h.home)
	if err != nil {
		h.t.Fatal(err)
	}
	sig, err := projpolicy.Sign(rand.Reader, h.signer, ns, b)
	if err != nil {
		h.t.Fatal(err)
	}
	return sig
}

func (h *harness) put(root string, b []byte, signed bool) {
	if err := os.WriteFile(filepath.Join(root, "chase.json"), b, 0o644); err != nil {
		h.t.Fatal(err)
	}
	if signed {
		if err := os.WriteFile(filepath.Join(root, "chase.json.sig"), h.sign(root, b), 0o644); err != nil {
			h.t.Fatal(err)
		}
	}
}

// sleeper is a process of this user's whose working directory is dir.
func sleeper(t *testing.T, dir string) (int, uint64) {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Skip("no sleep: ", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd.Process.Pid, startOf(t, cmd.Process.Pid)
}

func startOf(t *testing.T, pid int) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	start, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return start
}

var body = []byte("{\n  \"signer\": {\n    \"ssh\": {\n      \"hosts\": {\n        \"gateway\": \"allow\"\n      }\n    }\n  }\n}\n")

func TestReadIsThePolicyAboveTheAnchorsWorkingDirectory(t *testing.T) {
	h := newHarness(t)
	root := h.mkdir("Projects/foo")
	h.put(root, body, true)
	pid, start := sleeper(t, h.mkdir("Projects/foo/src/deep"))

	got, err := Read(context.Background(), h.signer951().socket, pid, start)
	if err != nil {
		t.Fatal(err)
	}
	if got.Root != root || got.Namespace != "frisket-policy:~/Projects/foo" || string(got.Bytes) != string(body) ||
		got.Digest != projpolicy.Digest(body) || got.Sig == nil {
		t.Fatalf("got %+v", got)
	}
	if _, err := projpolicy.Verify(got.Bytes, got.Sig, got.Namespace, mustSigners(t, h), "", timeNow()); err != nil {
		t.Errorf("what was read does not verify: %v", err)
	}

	// From the sudo gate too, and with no signature beside it.
	other := h.mkdir("Projects/bar")
	h.put(other, body, false)
	pid, start = sleeper(t, other)
	got, err = Read(context.Background(), h.as(952, 12).socket, pid, start)
	if err != nil || got.Root != other || got.Sig != nil {
		t.Fatalf("unsigned: %+v, %v", got, err)
	}

	// No policy file up to home is no root, and no error.
	pid, start = sleeper(t, h.mkdir("Scratch"))
	got, err = Read(context.Background(), h.signer951().socket, pid, start)
	if err != nil || got.Root != "" || got.Bytes != nil {
		t.Fatalf("none: %+v, %v", got, err)
	}
}

func TestReadWithNoFileIsTheRepositoryTheAnchorIsIn(t *testing.T) {
	h := newHarness(t)
	repo := h.mkdir("Projects/baz")
	h.mkdir("Projects/baz/.git")
	pid, start := sleeper(t, h.mkdir("Projects/baz/src"))
	got, err := Read(context.Background(), h.signer951().socket, pid, start)
	if err != nil || got.Root != repo || got.Namespace != "frisket-policy:~/Projects/baz" || got.Digest != "" || got.Bytes != nil {
		t.Fatalf("got %+v, %v", got, err)
	}

	// A worktree's .git is a file.
	wt := h.mkdir("Projects/wt")
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pid, start = sleeper(t, wt)
	if got, err := Read(context.Background(), h.signer951().socket, pid, start); err != nil || got.Root != wt {
		t.Fatalf("worktree: %+v, %v", got, err)
	}

	// A policy file above the repository is the project's, not the repository.
	h.put(h.mkdir("Projects"), body, true)
	pid, start = sleeper(t, repo)
	if got, err := Read(context.Background(), h.signer951().socket, pid, start); err != nil || got.Root != filepath.Dir(repo) || got.Digest == "" {
		t.Fatalf("file above: %+v, %v", got, err)
	}
}

func TestReadRefusesAReusedPidAndAProcessOutsideHome(t *testing.T) {
	h := newHarness(t)
	root := h.mkdir("Projects/foo")
	h.put(root, body, true)
	pid, start := sleeper(t, root)
	if _, err := Read(context.Background(), h.signer951().socket, pid, start+1); err == nil || !strings.Contains(err.Error(), "not the process") {
		t.Errorf("another start: %v", err)
	}
	if _, err := Read(context.Background(), h.signer951().socket, pid, 0); err == nil {
		t.Error("no start was accepted")
	}
	pid, start = sleeper(t, os.TempDir())
	got, err := Read(context.Background(), h.signer951().socket, pid, start)
	if err != nil || got.Root != "" {
		t.Errorf("outside home: %+v, %v", got, err)
	}
}

func TestOnlyTheServedUnitsAsTheirUsersArePeers(t *testing.T) {
	h := newHarness(t)
	root := h.mkdir("Projects/foo")
	h.put(root, body, true)
	pid, start := sleeper(t, root)
	for name, who := range map[string][2]uint64{
		"the gate's uid in the signer's unit": {952, 11},
		"the signer's uid in no unit served":  {951, 99},
		"the user's own uid":                  {uint64(os.Getuid()), 99},
		"no cgroup":                           {951, 0},
	} {
		_, err := Read(context.Background(), h.as(int(who[0]), who[1]).socket, pid, start)
		if err == nil || !strings.HasPrefix(err.Error(), "refused: ") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestWriteIsACompareAndSwapOnTheOldDigest(t *testing.T) {
	h := newHarness(t)
	root := h.mkdir("Projects/foo")
	ctx := context.Background()

	// A first file, where there was none.
	got, err := Write(ctx, h.signer951().socket, root, "", body, h.sign(root, body))
	if err != nil || got.Digest != projpolicy.Digest(body) || got.Namespace != "frisket-policy:~/Projects/foo" {
		t.Fatalf("first: %+v, %v", got, err)
	}
	p, err := projpolicy.Load(root, h.home, "chase.json", mustSigners(t, h))
	if err != nil || !p.Verified {
		t.Fatalf("written: %+v, %v", p, err)
	}

	next, _ := projpolicy.Format([]byte(`{"signer": {"ssh": {"hosts": {"gateway": "allow", "nas": "allow"}}}}`))
	if _, err := Write(ctx, h.signer951().socket, root, "", next, h.sign(root, next)); err == nil || !strings.Contains(err.Error(), ErrChanged.Error()) {
		t.Errorf("a stale digest: %v", err)
	}
	if _, err := Write(ctx, h.signer951().socket, root, projpolicy.Digest([]byte("{}\n")), next, h.sign(root, next)); err == nil || !strings.Contains(err.Error(), ErrChanged.Error()) {
		t.Errorf("another digest: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "chase.json")); string(b) != string(body) {
		t.Errorf("a refused write changed the file: %s", b)
	}
	if _, err := Write(ctx, h.signer951().socket, root, projpolicy.Digest(body), next, h.sign(root, next)); err != nil {
		t.Fatal(err)
	}
	if p, _ := projpolicy.Load(root, h.home, "chase.json", mustSigners(t, h)); !p.Verified || string(p.Bytes) != string(next) {
		t.Errorf("second: %+v", p)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 2 {
		t.Errorf("left behind: %v", entries)
	}
}

func TestWriteRefusesWhatWouldNotVerify(t *testing.T) {
	h := newHarness(t)
	root := h.mkdir("Projects/foo")
	other := h.mkdir("Projects/bar")
	ctx := context.Background()
	for name, c := range map[string]struct {
		root    string
		b, sig  []byte
		message string
	}{
		"another project's signature": {root, body, h.sign(other, body), "does not verify"},
		"another file's signature":    {root, body, h.sign(root, []byte("{}\n")), "does not verify"},
		"no signature":                {root, body, nil, "needs bytes and sig"},
		"not canonical":               {root, []byte(`{"b":1}`), h.sign(root, []byte(`{"b":1}`)), "not canonical"},
		"outside home":                {os.TempDir(), body, h.sign(os.TempDir(), body), "not under"},
		"relative":                    {"Projects/foo", body, body, "not absolute"},
		"unclean":                     {root + "/../foo", body, body, "not absolute and clean"},
	} {
		_, err := Write(ctx, h.signer951().socket, c.root, "", c.b, c.sig)
		if err == nil || !strings.Contains(err.Error(), c.message) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "chase.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused write left a file: %v", err)
	}
	h.signer951()
	if _, err := Call(ctx, h.socket, Request{Op: "delete", Root: root}); err == nil || !strings.Contains(err.Error(), "unknown op") {
		t.Errorf("unknown op: %v", err)
	}
}

func mustSigners(t *testing.T, h *harness) *projpolicy.AllowedSigners {
	t.Helper()
	s, err := h.s.Signers()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func timeNow() time.Time { return time.Now() }
