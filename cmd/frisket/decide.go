package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/danielbodart/frisket/execrule"
	"github.com/danielbodart/frisket/internal/intercept"
	"github.com/danielbodart/frisket/internal/sshroute"
	"github.com/danielbodart/frisket/internal/store"
	"github.com/danielbodart/frisket/policy"
)

// decideCommands answers each line of in, a command, as the document's SSH
// route of that name decides it: one line each on out, the answer -- allow,
// ask or refuse, the words a document's rules are written in -- a tab, and
// the rule that gave it. It is how whoever writes a route's rules tests them
// as commands, by frisket's own reading of a command rather than a copy of
// it: chase writes its whole catalogue of commands this way. The document
// is checked first, by the caller, as a session opening it would be, so
// that no rules are answered that no session would be given.
func decideCommands(path, name string, in io.Reader, out io.Writer) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	doc, err := policy.Load(b)
	if err != nil {
		return fmt.Errorf("policy %s: %w", path, err)
	}
	// What the route is clear of is no part of how it decides, and the
	// document has been held to that already.
	routes, err := sshroute.Compile(doc.Policy.SSH, sshroute.Reserved{})
	if err != nil {
		return fmt.Errorf("policy %s: %w", path, err)
	}
	var rules *execrule.Rules
	for i, r := range routes {
		if r.Name == name {
			// Compiled again, by execrule alone: what this answers is what
			// a consumer importing it is answered, as well as what the
			// route decides.
			if rules, err = execrule.Compile(doc.Policy.SSH[i]); err != nil {
				return fmt.Errorf("policy %s: ssh route %s: %w", path, name, err)
			}
		}
	}
	if rules == nil {
		return fmt.Errorf("policy %s: no SSH route %q", path, name)
	}
	w := bufio.NewWriter(out)
	s := bufio.NewScanner(in)
	// A command arrives in one SSH packet, which OpenSSH bounds at 256KiB.
	s.Buffer(nil, 256<<10)
	for s.Scan() {
		d := rules.Decide(s.Text())
		fmt.Fprintf(w, "%s\t%s\n", d.Outcome, d.Rule)
	}
	if err := s.Err(); err != nil {
		return err
	}
	return w.Flush()
}

// decideRequests answers each line of in, METHOD and a path with any
// query, as the document's route of that name decides it before reading
// its body: one line each on out, the answer, the reason and the
// operation, tab-separated, and for a request whose body or Docker daemon
// still decides it, what does after them. It is how whoever writes a
// route's operations tests them, by frisket's own reading of a request.
func decideRequests(path, name string, in io.Reader, out io.Writer) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	doc, err := policy.Load(b)
	if err != nil {
		return fmt.Errorf("policy %s: %w", path, err)
	}
	scope, err := store.RouteScope(doc, name)
	if err != nil {
		return fmt.Errorf("policy %s: %w", path, err)
	}
	w := bufio.NewWriter(out)
	s := bufio.NewScanner(in)
	s.Buffer(nil, 64<<10)
	for s.Scan() {
		method, target, ok := strings.Cut(s.Text(), " ")
		if !ok {
			return fmt.Errorf("%q is not METHOD /path", s.Text())
		}
		a, err := intercept.Answer(scope, method, target)
		if err != nil {
			return fmt.Errorf("%q: %w", s.Text(), err)
		}
		op := a.Operation
		if op == "" {
			op = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s", a.Outcome, a.Reason, op)
		if a.Deferred != "" {
			fmt.Fprintf(w, "\t%s decides", a.Deferred)
		}
		fmt.Fprintln(w)
	}
	if err := s.Err(); err != nil {
		return err
	}
	return w.Flush()
}

// warnUnreachable says on w each pattern in a version 2 document at path
// that can never match: it builds, and decides nothing.
func warnUnreachable(path string, w io.Writer) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if v, err := policy.Version(b); err != nil || v != 2 {
		return
	}
	d, err := policy.DecodeV2(b)
	if err != nil {
		return
	}
	for _, n := range policy.Unreachable(d) {
		fmt.Fprintf(w, "frisket check: %s: never matches: %s\n", path, n)
	}
}

// checkLayer checks a layer of the kind named over base, and the document
// they merge into as a session's would be checked.
func checkLayer(kind, base, section, path string, deps func() (store.Deps, error)) error {
	if kind != "project" {
		return fmt.Errorf("-layer %q: project is the one layer checked so", kind)
	}
	if base == "" {
		return errors.New("-layer project: -base names the document it is merged over")
	}
	lb, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if section != "" {
		var top map[string]json.RawMessage
		if err := json.Unmarshal(lb, &top); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		sec, ok := top[section]
		if !ok {
			return fmt.Errorf("%s: no %q section", path, section)
		}
		lb = sec
	}
	bb, err := os.ReadFile(base)
	if err != nil {
		return err
	}
	merged, err := policy.CheckProjectLayer(lb, bb)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	d, err := deps()
	if err != nil {
		return err
	}
	if err := store.CheckDocument(merged, d); err != nil {
		return fmt.Errorf("%s merged over %s: %w", path, base, err)
	}
	return nil
}
