package peer

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

const roleClient = "frisket-test-peer-client"

func TestMain(m *testing.M) {
	if len(os.Args) > 3 && os.Args[1] == roleClient {
		c, err := net.Dial("unix", os.Args[2])
		if err != nil {
			os.Exit(2)
		}
		if os.Args[3] == "stay" {
			_, _ = c.Read(make([]byte, 1))
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func accept(t *testing.T, mode string) (*net.UnixConn, *exec.Cmd) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cmd := exec.Command(os.Args[0], roleClient, path, mode)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, cmd
}

func TestADeadPidfdIsNeverRoot(t *testing.T) {
	c, cmd := accept(t, "exit")
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if r, err := FromConn(c); err == nil {
		t.Errorf("a reaped peer resolved to %+v", r)
	}

	c, cmd = accept(t, "stay")
	r, err := FromConn(c)
	c.Close()
	_ = cmd.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if r.PeerUID != os.Getuid() || len(r.Chain) < 2 || r.Chain[0].Pid != cmd.Process.Pid ||
		r.Chain[1].Pid != os.Getpid() || r.PPid != os.Getpid() || r.Chain[0].UID != os.Getuid() || r.CgroupID == 0 {
		t.Errorf("a live peer resolved to %+v", r)
	}
}

func TestAPeerProcIsItsPidAndParentWithTheirStarttimes(t *testing.T) {
	c, cmd := accept(t, "exit")
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if p, err := ProcOf(c); err == nil {
		t.Errorf("a reaped peer resolved to %+v", p)
	}

	c, cmd = accept(t, "stay")
	p, err := ProcOf(c)
	if err != nil {
		t.Fatal(err)
	}
	self, err := readStat("/proc/self")
	if err != nil {
		t.Fatal(err)
	}
	if p.UID != os.Getuid() || p.Pid != cmd.Process.Pid || p.PPid != os.Getpid() || p.PPidStart != self.Start || !Alive(p.Pid, p.Start) {
		t.Errorf("a live peer resolved to %+v", p)
	}
	c.Close()
	_ = cmd.Wait()
	if Alive(p.Pid, p.Start) {
		t.Error("a reaped peer is alive")
	}
}

func TestOnlyFrisketsMainProcessIsTrusted(t *testing.T) {
	cgroupRoot = t.TempDir()
	t.Cleanup(func() { cgroupRoot = "/sys/fs/cgroup" })
	unit := filepath.Join(cgroupRoot, "system.slice", "frisket.service")
	other := filepath.Join(cgroupRoot, "system.slice", "frisket-asker.service")
	for _, d := range []string{unit, other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ino := func(p string) uint64 {
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil {
			t.Fatal(err)
		}
		return st.Ino
	}
	main := func() *Requester {
		return &Requester{Chain: []Link{{Pid: 700, PPid: 1, Comm: "frisket", UID: 1000}}, PeerUID: 1000, PPid: 1, CgroupID: ino(unit)}
	}
	if !main().IsMainOf("frisket.service", 1000) {
		t.Fatal("frisket's main process is not trusted")
	}
	for name, change := range map[string]func(*Requester){
		"another comm":   func(r *Requester) { r.Chain[0].Comm = "frisket-asker" },
		"a ppid not 1":   func(r *Requester) { r.PPid = 700 },
		"another cgroup": func(r *Requester) { r.CgroupID = ino(other) },
		"no cgroup":      func(r *Requester) { r.CgroupID = 0 },
		"another uid":    func(r *Requester) { r.PeerUID = 1001 },
		"no chain":       func(r *Requester) { r.Chain = nil },
	} {
		r := main()
		change(r)
		if r.IsMainOf("frisket.service", 1000) {
			t.Errorf("%s is trusted", name)
		}
	}
	r := main()
	if err := os.Mkdir(unit+".new", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(unit); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(unit+".new", unit); err != nil {
		t.Fatal(err)
	}
	if r.IsMainOf("frisket.service", 1000) {
		t.Error("a process from the unit's previous cgroup is trusted")
	}
}

// From H2, dan-desktop: systemd --user, the terminal server, a tab's shell
// and the claude running in it.
var (
	pid1     = Link{Pid: 1, Sid: 1, Start: 1, Comm: "systemd", Cmdline: []string{"/run/current-system/systemd/lib/systemd/systemd"}}
	userRoot = Link{Pid: 2698, PPid: 1, Sid: 2698, Start: 2202, UID: 1000, Comm: "systemd", Cmdline: []string{"/run/current-system/systemd/lib/systemd/systemd", "--user"}}
	kgx      = Link{Pid: 1068980, PPid: 2698, Sid: 1068980, Start: 13380097, UID: 1000, Comm: ".kgx-wrapped", Cmdline: []string{"/nix/store/4vzf3ircwl51kzril8i4n14f9zavh3j4-gnome-console-50.0/bin/kgx", "--gapplication-service"}}
	tab      = Link{Pid: 1488983, PPid: 1068980, Sid: 1488983, TTY: 34820, Start: 21892052, UID: 1000, Comm: "bash", Cmdline: []string{"/run/current-system/sw/bin/bash"}}
	claude   = Link{Pid: 1492425, PPid: 1488983, Sid: 1488983, TTY: 34820, Start: 21894930, UID: 1000, Comm: ".claude-unwrapp", Cmdline: []string{"/nix/store/slw0881b3fw1bsyapahmaq2z5y5favjw-claude-code-2.1.291/bin/claude"}}
)

var nextPid = 3000000

func spawn(parent Link, comm string, cmdline ...string) Link {
	nextPid++
	return Link{Pid: nextPid, PPid: parent.Pid, Sid: parent.Sid, TTY: parent.TTY, Start: parent.Start + 1, UID: 1000, Comm: comm, Cmdline: cmdline}
}

// chain lists links leaf first, each spawned under the one after it.
func chain(top []Link, below ...[]string) []Link {
	links := append([]Link(nil), top...)
	for _, b := range below {
		links = append([]Link{spawn(links[0], b[0], b[1:]...)}, links...)
	}
	return links
}

var above = []Link{tab, kgx, userRoot, pid1}

func anchorOf(r *Requester) string {
	if r.Anchor == nil {
		return "<nil>"
	}
	return r.Anchor.Comm
}

func TestTheClaudeChainAnchorsOnClaude(t *testing.T) {
	bashTool := spawn(claude, "bash", "/run/current-system/sw/bin/bash", "-c", "git push")
	bashTool.Sid, bashTool.TTY = bashTool.Pid, 0
	links := chain(append([]Link{bashTool, claude}, above...), []string{"git", "git", "push"}, []string{"ssh", "ssh", "git@github.com"})
	r := FromLinks(links)
	if r.Anchor == nil || r.Anchor.Pid != claude.Pid || r.Cut || r.SessionRoot || r.Terminal {
		t.Errorf("anchor %s, cut %v, session root %v, terminal %v", anchorOf(r), r.Cut, r.SessionRoot, r.Terminal)
	}
}

func TestGitsSigningProgramIsShownThroughButStillTheAnchor(t *testing.T) {
	bashTool := spawn(claude, "bash", "/run/current-system/sw/bin/bash", "-c", "git commit -S -m x")
	bashTool.Sid, bashTool.TTY = bashTool.Pid, 0
	sign := []string{"ssh-keygen", "ssh-keygen", "-Y", "sign", "-n", "git", "-f", "/home/dan/.ssh/id_ecdsa.pub", "/tmp/.git_signing_buffer_x"}
	r := FromLinks(chain(append([]Link{bashTool, claude}, above...), []string{"git", "git", "commit", "-S", "-m", "x"}, sign))
	if anchorOf(r) != "ssh-keygen" || r.Shown == nil || r.Shown.Pid != claude.Pid || r.Cut || r.SessionRoot || r.Terminal {
		t.Errorf("anchor %s, shown %v, cut %v, session root %v, terminal %v", anchorOf(r), r.Shown, r.Cut, r.SessionRoot, r.Terminal)
	}

	r = FromLinks(chain(above, []string{"git", "git", "commit", "-S"}, sign))
	if anchorOf(r) != "ssh-keygen" || r.Shown == nil || r.Shown.Pid != tab.Pid || r.Terminal {
		t.Errorf("from a tab: anchor %s, shown %v, terminal %v", anchorOf(r), r.Shown, r.Terminal)
	}

	r = FromLinks(chain([]Link{userRoot, pid1}, sign))
	if anchorOf(r) != "ssh-keygen" || r.SessionRoot || r.Shown == nil || r.Shown.Pid != userRoot.Pid {
		t.Errorf("under systemd --user: anchor %s, shown %v, session root %v", anchorOf(r), r.Shown, r.SessionRoot)
	}

	for _, other := range [][]string{
		{"ssh-keygen", "ssh-keygen", "-Y", "verify", "-n", "git"},
		{"ssh-keygen", "ssh-keygen", "-l", "-f", "sign"},
		{"ssh-keygen-x", "ssh-keygen", "-Y", "sign"},
	} {
		r := FromLinks(chain([]Link{claude, tab, kgx, userRoot, pid1}, other))
		if r.Shown != r.Anchor || anchorOf(r) != other[0] {
			t.Errorf("%q: anchor %s, shown %v", other[1:], anchorOf(r), r.Shown)
		}
	}
}

func TestEveryOtherChainIsShownFromItsAnchor(t *testing.T) {
	for _, links := range [][]Link{
		chain(above, []string{"ssh", "ssh", "server"}),
		chain([]Link{claude, tab, kgx, userRoot, pid1}, []string{"git", "git", "push"}, []string{"ssh", "ssh", "git@github.com"}),
		chain([]Link{kgx, userRoot, pid1}, []string{"ssh", "ssh", "server"}),
	} {
		if r := FromLinks(links); r.Shown != r.Anchor {
			t.Errorf("anchor %s, shown %v", anchorOf(r), r.Shown)
		}
	}
}

func TestAScriptRunFromATabAnchorsOnTheTabsShell(t *testing.T) {
	r := FromLinks(chain(above, []string{"bash", "bash", "deploy.sh"}, []string{"ssh", "ssh", "server"}))
	if r.Anchor == nil || r.Anchor.Pid != tab.Pid || r.Cut || r.SessionRoot || r.Terminal {
		t.Errorf("anchor %s, cut %v, session root %v, terminal %v", anchorOf(r), r.Cut, r.SessionRoot, r.Terminal)
	}
}

func TestATabShellRunningSshIsATerminal(t *testing.T) {
	for _, below := range [][][]string{
		{{"ssh", "ssh", "server"}},
		{{"git", "git", "push"}, {"ssh", "ssh", "git@github.com"}},
		{{"rsync", "rsync", "-a", "x", "server:"}, {"ssh", "ssh", "server", "rsync"}},
	} {
		r := FromLinks(chain(above, below...))
		if !r.Terminal || r.Anchor == nil || r.Anchor.Pid != tab.Pid || r.Cut || r.SessionRoot {
			t.Errorf("%v: anchor %s, cut %v, session root %v, terminal %v", below, anchorOf(r), r.Cut, r.SessionRoot, r.Terminal)
		}
	}

	login := tab
	login.Cmdline = []string{"-bash"}
	if r := FromLinks(chain([]Link{login, kgx, userRoot, pid1}, []string{"ssh", "ssh", "server"})); !r.Terminal {
		t.Error("a login shell's ssh is not a terminal")
	}

	for name, change := range map[string]func(*Link){
		"a shell with arguments": func(l *Link) { l.Cmdline = append(l.Cmdline, "-c", "ssh server") },
		"a shell not leading":    func(l *Link) { l.Sid = kgx.Pid },
		"a shell with no tty":    func(l *Link) { l.TTY = 0 },
		"a shell on a vt":        func(l *Link) { l.TTY = 4<<8 | 2 },
		"zsh":                    func(l *Link) { l.Comm = "zsh" },
	} {
		s := tab
		change(&s)
		if r := FromLinks(chain([]Link{s, kgx, userRoot, pid1}, []string{"ssh", "ssh", "server"})); r.Terminal {
			t.Errorf("%s is a terminal", name)
		}
	}

	server := kgx
	server.PPid, server.Start = pid1.Pid, 3000
	if r := FromLinks(chain([]Link{tab, server, pid1}, []string{"ssh", "ssh", "server"})); r.Terminal {
		t.Error("a terminal server whose parent is not systemd --user is a terminal")
	}
}

func TestACommandLaunchedThroughTheTerminalServerIsNotATerminal(t *testing.T) {
	top := []Link{kgx, userRoot, pid1}
	for _, below := range [][][]string{
		{{"ssh", "ssh", "server"}},
		{{"bash", "bash", "-c", "ssh server"}, {"ssh", "ssh", "server"}},
		{{"git", "git", "push"}, {"ssh", "ssh", "git@github.com"}},
	} {
		links := chain(top, below...)
		links[len(below)-1].Sid, links[len(below)-1].TTY = links[len(below)-1].Pid, 34821
		r := FromLinks(links)
		if r.Terminal || !r.SessionRoot || anchorOf(r) != ".kgx-wrapped" {
			t.Errorf("kgx -- %v: anchor %s, session root %v, terminal %v", below[0][1:], anchorOf(r), r.SessionRoot, r.Terminal)
		}
	}
}

func TestAnAgentCommandIsNeverATerminal(t *testing.T) {
	bashTool := spawn(claude, "bash", "/run/current-system/sw/bin/bash")
	bashTool.Sid = bashTool.Pid
	r := FromLinks(chain(append([]Link{bashTool, claude}, above...), []string{"ssh", "ssh", "server"}))
	if r.Terminal {
		t.Error("claude's ssh is a terminal")
	}
	if r.Anchor == nil || r.Anchor.Pid != claude.Pid {
		t.Errorf("anchor %s, want claude", anchorOf(r))
	}
}

func TestASystemdUserRootAndAReparentedSshAreNeverGrantable(t *testing.T) {
	for name, links := range map[string][]Link{
		"systemd-run --user ssh": chain([]Link{userRoot, pid1}, []string{"ssh", "ssh", "server"}),
		"a reparented ssh -f":    chain([]Link{userRoot, pid1}, []string{"ssh", "ssh", "-f", "server"}),
		"ssh under pid 1":        chain([]Link{pid1}, []string{"ssh", "ssh", "server"}),
	} {
		if r := FromLinks(links); !r.SessionRoot && !r.Cut {
			t.Errorf("%s: anchor %s is grantable", name, anchorOf(r))
		}
	}

	ssh := spawn(claude, "ssh", "ssh", "server")
	full := append([]Link{ssh, claude}, above...)
	for name, links := range map[string][]Link{
		"a chain with no pid 1":           full[:len(full)-1],
		"a chain past the depth":          chain(full, repeat([]string{"bash", "bash", "x"}, depth)...),
		"a parent that is not the parent": {ssh, tab, kgx, userRoot, pid1},
		"a parent younger than its child": {ssh, func() Link { c := claude; c.Start = ssh.Start + 1; return c }(), tab, kgx, userRoot, pid1},
	} {
		if r := FromLinks(links); !r.Cut {
			t.Errorf("%s is not cut", name)
		}
	}
}

func repeat(b []string, n int) [][]string {
	out := make([][]string, n)
	for i := range out {
		out[i] = b
	}
	return out
}
