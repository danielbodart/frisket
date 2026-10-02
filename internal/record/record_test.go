package record

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type journal struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (j *journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.buf.Write(p)
}

func (j *journal) lines(t *testing.T) []map[string]any {
	t.Helper()
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []map[string]any
	for l := range strings.SplitSeq(j.buf.String(), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %q", l)
		}
		if m["msg"] == "record" {
			out = append(out, m)
		}
	}
	return out
}

func newRecorder(t *testing.T, def Answer, sink *Sink) (*Recorder, *journal) {
	t.Helper()
	j := &journal{}
	r, err := New(Config{Policy: "p", Default: def, Sink: sink, Log: slog.New(slog.NewJSONHandler(j, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, j
}

func subject(session string) Line {
	return Line{Session: session, Kind: KindHTTP, Route: "api", Method: "POST", Host: "api.example.test", Path: "/v2/x", Would: "refuse", Rule: "out of scope"}
}

func never(t *testing.T) Asking {
	return func(context.Context) (Answer, string, error) {
		t.Error("a person was asked, with a default to answer")
		return Refuse, "", nil
	}
}

// A default answers every subject, with nobody asked; the first time a
// subject comes up it is written down, and after that the session's answer
// stands, unwritten. Another session's same subject is its own.
func TestADefaultAnswersEachSubjectAndIsWrittenOnce(t *testing.T) {
	r, j := newRecorder(t, Ask, nil)
	for range 3 {
		if res := r.Decide(context.Background(), subject("s1"), "k", never(t)); res.Answer != Ask {
			t.Fatalf("%+v", res)
		}
	}
	if res := r.Decide(context.Background(), subject("s2"), "k", never(t)); res.Answer != Ask || res.Source != SourceDefault {
		t.Fatalf("another session: %+v", res)
	}
	lines := j.lines(t)
	if len(lines) != 2 {
		t.Fatalf("%d lines, want one per session", len(lines))
	}
	l := lines[0]
	for k, v := range map[string]any{"session": "s1", "policy": "p", "kind": "http", "route": "api", "method": "POST",
		"path": "/v2/x", "would": "refuse", "rule": "out of scope", "answer": "ask", "source": "default"} {
		if l[k] != v {
			t.Errorf("%s = %v, want %v", k, l[k], v)
		}
	}
}

// A person's answer stands for the session, a refusal as much as an
// admission; the want of one does not, and they are asked again.
func TestAPersonsAnswerStandsAndTheWantOfOneDoesNot(t *testing.T) {
	r, j := newRecorder(t, "", nil)
	var asked atomic.Int32
	failing := func(context.Context) (Answer, string, error) {
		asked.Add(1)
		return Refuse, "asking failed", errors.New("no display")
	}
	if res := r.Decide(context.Background(), subject("s"), "k", failing); res.Answer != Refuse || res.Source != SourceUnanswered || res.Err == nil {
		t.Fatalf("%+v", res)
	}
	refusing := func(context.Context) (Answer, string, error) { asked.Add(1); return Refuse, "", nil }
	for range 2 {
		if res := r.Decide(context.Background(), subject("s"), "k", refusing); res.Answer != Refuse || res.Reason != "" {
			t.Fatalf("%+v", res)
		}
	}
	if asked.Load() != 2 {
		t.Fatalf("asked %d times, want twice: once failing, once answered", asked.Load())
	}
	lines := j.lines(t)
	if len(lines) != 2 || lines[0]["source"] != SourceUnanswered || lines[0]["reason"] != "asking failed" || lines[1]["source"] != SourceHuman {
		t.Fatalf("lines %v", lines)
	}
}

// Two at once about one subject wait for one answer: a person is never put
// the same question twice over.
func TestOneSubjectIsAskedOnceThoughTwoWait(t *testing.T) {
	r, _ := newRecorder(t, "", nil)
	release := make(chan struct{})
	var asked atomic.Int32
	ask := func(context.Context) (Answer, string, error) {
		asked.Add(1)
		<-release
		return Allow, "", nil
	}
	var wg sync.WaitGroup
	results := make(chan Result, 2)
	for range 2 {
		wg.Go(func() { results <- r.Decide(context.Background(), subject("s"), "k", ask) })
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)
	for res := range results {
		if res.Answer != Allow {
			t.Fatalf("%+v", res)
		}
	}
	if asked.Load() != 1 {
		t.Fatalf("asked %d times", asked.Load())
	}
}

// A hard refusal and a DNS name are written once per session.
func TestHardRefusalsAndNamesAreWrittenOnce(t *testing.T) {
	r, j := newRecorder(t, Allow, nil)
	for range 2 {
		r.Hard(Line{Session: "s", Kind: KindEgress, Address: "192.0.2.9:443", Port: 443, Rule: "not resolved by this session"}, "address 192.0.2.9:443", "not resolved by this session")
		r.Resolved("s", "unlisted.example.test")
	}
	lines := j.lines(t)
	if len(lines) != 2 {
		t.Fatalf("%d lines, want 2", len(lines))
	}
	if l := lines[0]; l["source"] != SourceHard || l["answer"] != "refuse" || l["would"] != "refuse" || l["reason"] != "not resolved by this session" {
		t.Errorf("hard line %v", l)
	}
	if l := lines[1]; l["kind"] != KindDNS || l["name"] != "unlisted.example.test" || l["source"] != SourceTelemetry || l["would"] != "refuse" {
		t.Errorf("dns line %v", l)
	}
}

// answers is a person answering in turn, counting the questions.
func answers(asked *atomic.Int32, as ...Answer) Asking {
	return func(context.Context) (Answer, string, error) {
		n := asked.Add(1)
		return as[min(int(n), len(as))-1], "", nil
	}
}

// A person's ask is a question each time, as a grant's would be; an answer
// that differs from the one remembered replaces it and is written down, and
// a person's allow then stands.
func TestAnAskIsAskedAgainAndAChangedAnswerIsWritten(t *testing.T) {
	r, j := newRecorder(t, "", nil)
	var asked atomic.Int32
	ask := answers(&asked, Ask, Ask, Allow)
	for i, want := range []Answer{Ask, Ask, Allow, Allow} {
		if res := r.Decide(context.Background(), subject("s"), "k", ask); res.Answer != want {
			t.Fatalf("%d: %+v, want %s", i, res, want)
		}
	}
	if asked.Load() != 3 {
		t.Fatalf("asked %d times, want 3", asked.Load())
	}
	lines := j.lines(t)
	if len(lines) != 2 || lines[0]["answer"] != "ask" || lines[1]["answer"] != "allow" || lines[1]["source"] != SourceHuman {
		t.Fatalf("lines %v", lines)
	}
}

// DecideEach puts every one to a person, whatever the last answer, and
// writes the subject down once while the answer does not change; a default
// still answers each, unasked.
func TestDecideEachAsksAPersonEveryTime(t *testing.T) {
	r, j := newRecorder(t, "", nil)
	var asked atomic.Int32
	for range 3 {
		if res := r.DecideEach(context.Background(), subject("s"), "k", answers(&asked, Allow)); res.Answer != Allow {
			t.Fatalf("%+v", res)
		}
	}
	if asked.Load() != 3 || len(j.lines(t)) != 1 {
		t.Fatalf("asked %d times, %d lines", asked.Load(), len(j.lines(t)))
	}
	d, dj := newRecorder(t, Allow, nil)
	for range 2 {
		if res := d.DecideEach(context.Background(), subject("s"), "k", never(t)); res.Answer != Allow {
			t.Fatalf("%+v", res)
		}
	}
	if len(dj.lines(t)) != 1 {
		t.Fatalf("%d lines", len(dj.lines(t)))
	}
}

// A subject on the local network is the default's like any other: nobody
// is asked, and the line says lan.
func TestTheLocalNetworkIsAnsweredByTheDefault(t *testing.T) {
	r, j := newRecorder(t, Allow, nil)
	lan := Line{Session: "s", Kind: KindEgress, Name: "nas.lan", Port: 445, LAN: true, Would: "refuse", Rule: "structural: private"}
	if res := r.Decide(context.Background(), lan, "nas.lan:445 lan", never(t)); res.Answer != Allow || res.Source != SourceDefault {
		t.Fatalf("%+v", res)
	}
	if l := j.lines(t); len(l) != 1 || l[0]["source"] != SourceDefault || l[0]["lan"] != true || l[0]["answer"] != "allow" {
		t.Fatalf("lines %v", l)
	}
}

// A name refused at DNS, unlooked-up, is written once, as telemetry.
func TestAnUnresolvedNameIsWrittenOnce(t *testing.T) {
	r, j := newRecorder(t, Refuse, nil)
	for range 2 {
		r.Unresolved("s", "unlisted.example.test")
	}
	if l := j.lines(t); len(l) != 1 || l[0]["kind"] != KindDNS || l[0]["answer"] != "refuse" || l[0]["source"] != SourceTelemetry ||
		l[0]["reason"] != ReasonNotLookedUp {
		t.Fatalf("lines %v", l)
	}
}

// A session's hard refusals and DNS names are bounded apart from what it
// decides: past maxNoise they reach the journal alone, and a subject
// decided after them is in the sink all the same.
func TestNoiseIsBoundedApartFromWhatIsDecided(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.jsonl")
	sink, err := OpenSink(path)
	if err != nil {
		t.Fatal(err)
	}
	r, j := newRecorder(t, Allow, sink)
	for i := range maxNoise + 10 {
		r.Resolved("s", fmt.Sprintf("n%d.example.test", i))
	}
	r.Decide(context.Background(), subject("s"), "k", never(t))
	if got := len(j.lines(t)); got != maxNoise+11 {
		t.Fatalf("%d journal lines", got)
	}
	in := sinkLines(t, path)
	if len(in) != maxNoise+1 || in[len(in)-1]["source"] != SourceDefault {
		t.Fatalf("%d sink lines, last %v", len(in), in[len(in)-1])
	}
}

// Nor do they fill the sink past half its bound, which is kept for
// answered subjects' lines.
func TestNoiseFillsHalfTheSinkAtMost(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.jsonl")
	sink, err := openSink(path, 4000)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := newRecorder(t, Allow, sink)
	for i := range 100 {
		r.Hard(Line{Session: "s", Kind: KindEgress, Address: fmt.Sprintf("192.0.2.%d:443", i)}, fmt.Sprint(i), "not resolved by this session")
	}
	if fi, _ := os.Stat(path); fi.Size() > 2000 {
		t.Fatalf("noise filled %d bytes of 4000", fi.Size())
	}
	r.Decide(context.Background(), subject("s"), "k", never(t))
	in := sinkLines(t, path)
	if in[len(in)-1]["source"] != SourceDefault {
		t.Fatalf("last line %v", in[len(in)-1])
	}
}

func sinkLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("not JSON: %q", sc.Text())
		}
		out = append(out, m)
	}
	return out
}

func TestAnswersAreReadInAnyCase(t *testing.T) {
	for in, want := range map[string]Answer{"Allow": Allow, " ASK\n": Ask, "refuse": Refuse} {
		if a, ok := ParseAnswer(in); !ok || a != want {
			t.Errorf("%q: %v %v", in, a, ok)
		}
	}
	for _, in := range []string{"", "yes", "allow always", "allow\nask"} {
		if _, ok := ParseAnswer(in); ok {
			t.Errorf("%q read as an answer", in)
		}
	}
	if _, err := New(Config{Default: "always", Log: slog.New(slog.DiscardHandler)}); err == nil {
		t.Error("a default that is no answer was taken")
	}
}

// The sink is a file of its own: created 0600, appended to, one JSON line
// per line, and bounded -- past the bound, one line says so and the rest
// is dropped, and a sink opened full stays full.
func TestTheSinkIsAppendedToAndBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.jsonl")
	if err := CheckSinkPath(path, dir); err != nil {
		t.Fatal(err)
	}
	sink, err := openSink(path, 600)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := newRecorder(t, Allow, sink)
	for i := range 10 {
		r.Decide(context.Background(), subject("s"), string(rune('a'+i)), never(t))
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("not JSON: %q", sc.Text())
		}
		lines = append(lines, m)
	}
	if len(lines) < 2 || lines[0]["kind"] != "http" || lines[0]["answer"] != "allow" {
		t.Fatalf("lines %v", lines)
	}
	last := lines[len(lines)-1]
	if last["truncated"] != true {
		t.Fatalf("last line %v, want truncated", last)
	}
	for _, l := range lines[:len(lines)-1] {
		if l["truncated"] != nil {
			t.Fatal("two truncated lines")
		}
	}
	if fi.Size() > 600+200 {
		t.Fatalf("%d bytes, past the bound and its one line", fi.Size())
	}
	sink2, err := openSink(path, 600)
	if err != nil {
		t.Fatal(err)
	}
	defer sink2.Close()
	if err := sink2.Write(subject("s")); err != nil {
		t.Fatal(err)
	}
	if fi2, _ := os.Stat(path); fi2.Size() != fi.Size() {
		t.Fatal("a full sink was written to again")
	}
}

func TestASinkIsAFileOfItsOwnInTheRecordDir(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"rel.jsonl", dir + "/../x.jsonl", dir + "/sub/x.jsonl", dir + "/.hidden", "/elsewhere/x.jsonl", dir + "/"} {
		if err := CheckSinkPath(p, dir); err == nil {
			t.Errorf("%s: accepted", p)
		}
	}
	if err := CheckSinkPath(dir+"/x.jsonl", ""); err == nil {
		t.Error("accepted by a daemon that keeps no records")
	}
	if err := CheckSinkShape("/anywhere/x.jsonl"); err != nil {
		t.Error(err)
	}
	// Not through a link, and not a file another can read.
	if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSink(filepath.Join(dir, "link")); err == nil {
		t.Error("opened through a link")
	}
	open := filepath.Join(dir, "open")
	if err := os.WriteFile(open, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSink(open); err == nil {
		t.Error("opened a file others can read")
	}
	// Nor another name for a file of the daemon's user's own.
	elsewhere := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(elsewhere, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(elsewhere, filepath.Join(dir, "linked.jsonl")); err != nil {
		t.Skipf("no hard link across temp dirs here: %v", err)
	}
	if _, err := OpenSink(filepath.Join(dir, "linked.jsonl")); err == nil {
		t.Error("opened a hard link")
	}
}
