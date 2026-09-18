package dns

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The resolvers the test's resolv.conf files name. Nothing listens on them: the
// Upstream's Dial sends each to a fake resolver on loopback, which answers
// with an address of its own so an answer says which one was asked.
const (
	resolverOne = "198.51.100.1"
	resolverTwo = "198.51.100.2"
	answerOne   = "192.0.2.1"
	answerTwo   = "192.0.2.2"
)

type resolvers struct {
	one, two *udpUpstream
	base     Upstream
}

// startResolvers starts both fake resolvers. hold, if not nil, is waited on by
// the first before it answers.
func startResolvers(t *testing.T, hold chan struct{}) *resolvers {
	t.Helper()
	r := &resolvers{
		one: startUDPUpstream(t, func(q dnsmessage.Message, reply func([]byte)) {
			if hold != nil {
				<-hold
			}
			reply(answer(q, answerOne, nil))
		}),
		two: startUDPUpstream(t, func(q dnsmessage.Message, reply func([]byte)) {
			reply(answer(q, answerTwo, nil))
		}),
	}
	to := map[string]string{
		resolverOne + ":53": r.one.addr.String(),
		resolverTwo + ":53": r.two.addr.String(),
	}
	r.base = Upstream{
		Timeout: 5 * time.Second,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			real, ok := to[address]
			if !ok {
				t.Errorf("dialled %s, which no resolv.conf here names", address)
				real = address
			}
			return (&net.Dialer{}).DialContext(ctx, network, real)
		},
	}
	return r
}

// replaceFile writes content the way resolvconf and NetworkManager do: a
// temporary file in the same directory, then a rename over the old name.
func replaceFile(t *testing.T, path, content string) {
	t.Helper()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		t.Fatal(err)
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// realDir is t.TempDir with its symlinks resolved, so a TMPDIR reached through
// a link does not quietly put every test here into polling mode.
func realDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func follow(t *testing.T, path string, base Upstream, j *journal) *ResolvConf {
	t.Helper()
	r, err := FollowResolvConf(path, base, slog.New(slog.NewJSONHandler(j, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// ask asks for example.test and returns the address answered and the server
// that answered it.
func ask(t *testing.T, r *ResolvConf) (string, string) {
	t.Helper()
	m, tr, err := r.Exchange(context.Background(), question("example.test.", dnsmessage.TypeA))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return onlyA(t, m), tr.Server.String()
}

func serversAre(r *ResolvConf, want ...string) func() bool {
	return func() bool { return slices.Equal(addrs(r.Servers()), want) }
}

// The file is replaced by rename, which is how resolvconf, NetworkManager and
// systemd-resolved all write it. Twice, because the second rename is the one a
// watch on the file itself would miss.
func TestResolvConfFollowsReplacementByRename(t *testing.T) {
	res := startResolvers(t, nil)
	path := filepath.Join(realDir(t), "resolv.conf")
	replaceFile(t, path, "# first network\nnameserver "+resolverOne+"\n")
	j := &journal{}
	r := follow(t, path, res.base, j)

	if a, srv := ask(t, r); a != answerOne || srv != resolverOne+":53" {
		t.Fatalf("before any change: %s from %s", a, srv)
	}
	replaceFile(t, path, "nameserver "+resolverTwo+"\n")
	eventually(t, "the second resolver", serversAre(r, resolverTwo+":53"))
	if a, srv := ask(t, r); a != answerTwo || srv != resolverTwo+":53" {
		t.Fatalf("after the first rename: %s from %s", a, srv)
	}
	replaceFile(t, path, "nameserver "+resolverOne+"\n")
	eventually(t, "the first resolver again", serversAre(r, resolverOne+":53"))
	if a, _ := ask(t, r); a != answerOne {
		t.Fatalf("after the second rename: %s", a)
	}
	if r.watch.Polling() {
		t.Fatal("fell back to polling on an ordinary directory; the watch is not what picked the change up")
	}

	// One line per change, each naming what it changed to and from.
	lines := j.linesOf(t, "dns upstream")
	if len(lines) != 3 {
		t.Fatalf("want one line per change, got %d: %v", len(lines), lines)
	}
	last := lines[2]
	if last["outcome"] != "changed" || last["path"] != path ||
		!slices.Equal(anyStrings(last["servers"]), []string{resolverOne + ":53"}) ||
		!slices.Equal(anyStrings(last["previous"]), []string{resolverTwo + ":53"}) {
		t.Fatalf("change line: %v", last)
	}
}

// A rewrite that names the same servers is no change, and says nothing.
func TestResolvConfRewrittenUnchangedIsSilent(t *testing.T) {
	res := startResolvers(t, nil)
	path := filepath.Join(realDir(t), "resolv.conf")
	replaceFile(t, path, "nameserver "+resolverOne+"\n")
	j := &journal{}
	r := follow(t, path, res.base, j)
	replaceFile(t, path, "search example\nnameserver "+resolverOne+"\n")
	// A change that IS one, after it, so there is something to wait for.
	replaceFile(t, path, "nameserver "+resolverTwo+"\n")
	eventually(t, "the change", serversAre(r, resolverTwo+":53"))
	if n := len(j.linesOf(t, "dns upstream")); n != 2 {
		t.Fatalf("want the initial line and the one change, got %d", n)
	}
}

// A file with no server in it -- NetworkManager's, offline -- or one that
// cannot be parsed is not a new upstream: the last good one is kept, and the
// file's fault is logged.
func TestResolvConfThatCannotBeUsedKeepsTheLastGood(t *testing.T) {
	res := startResolvers(t, nil)
	path := filepath.Join(realDir(t), "resolv.conf")
	replaceFile(t, path, "nameserver "+resolverOne+"\n")
	j := &journal{}
	r := follow(t, path, res.base, j)

	for i, bad := range []string{"# Generated by NetworkManager\n", "nameserver resolver.example\n"} {
		replaceFile(t, path, bad)
		eventually(t, "the error line", func() bool {
			n := 0
			for _, l := range j.linesOf(t, "dns upstream") {
				if l["level"] == "ERROR" {
					n++
				}
			}
			return n == i+1
		})
		if a, srv := ask(t, r); a != answerOne || srv != resolverOne+":53" {
			t.Fatalf("after %q: %s from %s", bad, a, srv)
		}
	}
	for _, l := range j.linesOf(t, "dns upstream") {
		if l["level"] == "ERROR" && (l["outcome"] != "kept" ||
			!slices.Equal(anyStrings(l["servers"]), []string{resolverOne + ":53"}) || l["error"] == "") {
			t.Fatalf("an unusable file must say what was kept, and why: %v", l)
		}
	}

	replaceFile(t, path, "nameserver "+resolverTwo+"\n")
	eventually(t, "recovery", serversAre(r, resolverTwo+":53"))
	if a, _ := ask(t, r); a != answerTwo {
		t.Fatalf("after recovery: %s", a)
	}
}

// A query in flight keeps the upstream it started with; the next one takes the
// new one.
func TestResolvConfQueryInFlightKeepsItsUpstream(t *testing.T) {
	hold := make(chan struct{})
	res := startResolvers(t, hold)
	path := filepath.Join(realDir(t), "resolv.conf")
	replaceFile(t, path, "nameserver "+resolverOne+"\n")
	r := follow(t, path, res.base, &journal{})

	type result struct {
		m   *dnsmessage.Message
		tr  Trace
		err error
	}
	first := make(chan result, 1)
	go func() {
		m, tr, err := r.Exchange(context.Background(), question("example.test.", dnsmessage.TypeA))
		first <- result{m, tr, err}
	}()
	eventually(t, "the first query to reach the first resolver", func() bool { return len(res.one.queries()) == 1 })

	replaceFile(t, path, "nameserver "+resolverTwo+"\n")
	eventually(t, "the change", serversAre(r, resolverTwo+":53"))
	if a, srv := ask(t, r); a != answerTwo || srv != resolverTwo+":53" {
		t.Fatalf("the query after the change: %s from %s", a, srv)
	}

	close(hold)
	got := <-first
	if got.err != nil {
		t.Fatalf("the query in flight: %v", got.err)
	}
	if a, srv := onlyA(t, got.m), got.tr.Server.String(); a != answerOne || srv != resolverOne+":53" {
		t.Fatalf("the query in flight: %s from %s", a, srv)
	}
	if n := len(res.two.queries()); n != 1 {
		t.Fatalf("the second resolver was asked %d times, want once", n)
	}
}

// resolv.conf as a symlink -- systemd-resolved's stub file -- is checked on
// every query, because its target changes in a directory nobody watches. Both
// ways it changes are seen at once, with no event to wait for: the link
// pointed elsewhere, and the target replaced by rename where it lives.
func TestResolvConfThroughASymlinkIsCheckedOnUse(t *testing.T) {
	res := startResolvers(t, nil)
	root := realDir(t)
	for _, d := range []string{"etc", "run1", "run2"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target1 := filepath.Join(root, "run1", "resolv.conf")
	target2 := filepath.Join(root, "run2", "resolv.conf")
	replaceFile(t, target1, "nameserver "+resolverOne+"\n")
	replaceFile(t, target2, "nameserver "+resolverTwo+"\n")
	link := filepath.Join(root, "etc", "resolv.conf")
	if err := os.Symlink(target1, link); err != nil {
		t.Fatal(err)
	}
	j := &journal{}
	r := follow(t, link, res.base, j)
	if !r.watch.Polling() {
		t.Fatal("a symlinked resolv.conf must be checked on use")
	}
	if a, _ := ask(t, r); a != answerOne {
		t.Fatalf("through the link: %s", a)
	}

	// The link swapped, as ln -sf does it: a new link renamed over the old.
	tmp := link + ".tmp"
	if err := os.Symlink(target2, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, link); err != nil {
		t.Fatal(err)
	}
	if a, _ := ask(t, r); a != answerTwo {
		t.Fatalf("after the link was swapped: %s", a)
	}

	// The target replaced where it lives.
	replaceFile(t, target2, "nameserver "+resolverOne+"\n")
	if a, _ := ask(t, r); a != answerOne {
		t.Fatalf("after the target was replaced: %s", a)
	}

	var said bool
	for _, l := range j.linesOf(t, "dns upstream watch") {
		said = said || (l["mode"] == "polling" && l["level"] == "WARN")
	}
	if !said {
		t.Fatal("falling back to polling must be logged")
	}
}

// A regular file replaced by a symlink is noticed, and from then on checked
// on use -- or a later change to the link's target would be missed.
func TestResolvConfBecomingASymlinkIsCheckedOnUse(t *testing.T) {
	res := startResolvers(t, nil)
	root := realDir(t)
	if err := os.Mkdir(filepath.Join(root, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "resolv.conf")
	replaceFile(t, path, "nameserver "+resolverOne+"\n")
	r := follow(t, path, res.base, &journal{})
	if r.watch.Polling() {
		t.Fatal("an ordinary file must be watched")
	}

	target := filepath.Join(root, "run", "resolv.conf")
	replaceFile(t, target, "nameserver "+resolverTwo+"\n")
	tmp := path + ".tmp"
	if err := os.Symlink(target, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the link", serversAre(r, resolverTwo+":53"))
	if !r.watch.Polling() {
		t.Fatal("a file that became a symlink must be checked on use from then on")
	}
	replaceFile(t, target, "nameserver "+resolverOne+"\n")
	if a, _ := ask(t, r); a != answerOne {
		t.Fatalf("after the target was replaced: %s", a)
	}
}

// With no usable file at start -- a laptop booting before its network is up --
// frisket starts, queries fail, and the first usable file is picked up.
func TestResolvConfMissingAtStartIsPickedUpLater(t *testing.T) {
	res := startResolvers(t, nil)
	path := filepath.Join(realDir(t), "resolv.conf")
	j := &journal{}
	r := follow(t, path, res.base, j)
	if _, _, err := r.Exchange(context.Background(), question("example.test.", dnsmessage.TypeA)); err == nil {
		t.Fatal("a query with no resolver answered")
	}
	if l := j.linesOf(t, "dns upstream"); len(l) != 1 || l[0]["outcome"] != "none" || l[0]["level"] != "ERROR" {
		t.Fatalf("no resolver at start must be logged loudly: %v", l)
	}
	replaceFile(t, path, "nameserver "+resolverOne+"\n")
	eventually(t, "the file to appear", serversAre(r, resolverOne+":53"))
	if a, _ := ask(t, r); a != answerOne {
		t.Fatalf("after the file appeared: %s", a)
	}
}

func TestParseResolvConf(t *testing.T) {
	got, err := ParseResolvConf("# comment\nnameserver 203.0.113.20\nsearch example\n" +
		"nameserver ::1\nnameserver\n  nameserver fe80::1%eth0 \noptions edns0\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.20:53"),
		netip.MustParseAddrPort("[::1]:53"),
		netip.MustParseAddrPort("[fe80::1%eth0]:53"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("ParseResolvConf = %v, want %v", got, want)
	}
	for _, bad := range []string{"", "# offline\nsearch example\n", "nameserver 203.0.113.20\nnameserver resolver.example\n"} {
		if got, err := ParseResolvConf(bad); err == nil {
			t.Errorf("ParseResolvConf(%q) = %v; want an error", bad, got)
		}
	}
}

func anyStrings(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}
