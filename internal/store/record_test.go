package store

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/danielbodart/frisket/internal/control"
	"github.com/danielbodart/frisket/internal/dns"
	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/record"
	"github.com/danielbodart/frisket/policy"
)

type yes struct{}

func (yes) Ask(context.Context, intercept.Question) (record.Answer, error) { return record.Allow, nil }

// A recording document holds together only with what it needs: a default
// that is an answer, an asker to put subjects to when it has none, and a
// sink in the daemon's record directory.
func TestARecordingDocumentIsHeldToWhatItNeeds(t *testing.T) {
	dir := t.TempDir()
	build := func(r *policy.Record, d Deps) error {
		p := valid(t)
		p.Record = r
		s, err := NewStore(&Config{}, d)
		if err != nil {
			return err
		}
		defer s.Close()
		_, release, err := s.Open(writeDocument(t, "p", p))
		if err == nil {
			release()
		}
		return err
	}
	withDir := deps(t, &counting{})
	withDir.RecordDir = dir
	withAsker := withDir
	withAsker.Asker = yes{}
	for name, tc := range map[string]struct {
		r    *policy.Record
		d    Deps
		fail string
	}{
		"a default":                      {&policy.Record{Default: "allow"}, withDir, ""},
		"a sink in the record directory": {&policy.Record{Default: "ask", Sink: dir + "/s.jsonl"}, withDir, ""},
		"no default, with an asker":      {&policy.Record{}, withAsker, ""},
		"no default, no asker":           {&policy.Record{}, withDir, "no asker"},
		"a default that is no answer":    {&policy.Record{Default: "always"}, withDir, "default"},
		"a default in capitals":          {&policy.Record{Default: "Allow"}, withDir, "default"},
		"a sink elsewhere":               {&policy.Record{Default: "allow", Sink: "/tmp/s.jsonl"}, withDir, "not directly in"},
		"a sink with no record dir":      {&policy.Record{Default: "allow", Sink: dir + "/s.jsonl"}, deps(t, &counting{}), "keeps no records"},
	} {
		err := build(tc.r, tc.d)
		switch {
		case tc.fail == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.fail != "" && (err == nil || !strings.Contains(err.Error(), tc.fail)):
			t.Errorf("%s: %v, want %q", name, err, tc.fail)
		}
	}
	// Checked away from the daemon, a sink is held to its shape alone.
	p := valid(t)
	p.Record = &policy.Record{Sink: "/var/lib/frisket/records/s.jsonl"}
	if err := check(t, "p", p); err != nil {
		t.Errorf("checked: %v", err)
	}
	p.Record.Sink = "relative.jsonl"
	if err := check(t, "p", p); err == nil {
		t.Error("checked: a relative sink")
	}
}

// A recording session's DNS resolves a name off the allowlist, and the sink
// has it, as a name resolved for telemetry; a session under the same
// document without the block still answers it NXDOMAIN.
func TestARecordingSessionsNamesReachTheSink(t *testing.T) {
	dir := t.TempDir()
	up := &answering{}
	d := deps(t, up)
	d.RecordDir = dir
	p := valid(t)
	sink := filepath.Join(dir, "s.jsonl")
	p.Record = &policy.Record{Default: "allow", Sink: sink}
	s, err := NewStore(&Config{}, d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	pol, release, err := s.Open(writeDocument(t, "p", p))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	svc := []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	h, err := pol.Handlers(control.Session{Name: "s", Policy: "/p.json", Service: svc}, nil, slog.New(slog.NewJSONHandler(&journal{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if m := ask(t, h, "denied.test."); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatalf("a recording session's name off the allowlist: %+v", m)
	}
	f, err := os.Open(sink)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatal("nothing in the sink")
	}
	var l map[string]any
	if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
		t.Fatal(err)
	}
	if l["kind"] != "dns" || l["name"] != "denied.test" || l["session"] != "s" || l["policy"] != "p" || l["source"] != "telemetry" {
		t.Fatalf("sink line %v", l)
	}
}

// answering answers every name with one address.
type answering struct{}

func (answering) Exchange(_ context.Context, q dnsmessage.Question) (*dnsmessage.Message, dns.Trace, error) {
	return &dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{q},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: [4]byte{198, 51, 100, 7}},
		}},
	}, dns.Trace{}, nil
}
