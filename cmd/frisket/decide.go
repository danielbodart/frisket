package main

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/danielbodart/frisket/execrule"
	"github.com/danielbodart/frisket/internal/sshroute"
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
	var doc policy.Document
	if err := policy.Decode(b, &doc); err != nil {
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
