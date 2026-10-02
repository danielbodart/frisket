package execrule

import (
	"errors"
	"fmt"
	"strings"

	"github.com/danielbodart/frisket/policy"
)

// The words of a pattern that are not literal.
const (
	anyWord  = "*"
	anyWords = "**"
)

// rule is one compiled ExecRule: a command rule, or an arg rule, which may
// have a command pattern as well.
type rule struct {
	// name is what the log and errors call the rule: its pattern, and an
	// arg rule's glob in brackets, which no pattern can hold.
	name string
	// command says whether the rule has a command pattern; one with no
	// command is an arg rule for every simple command.
	command bool
	words   []string
	// tail is a pattern ending "**": its words before that, then any number
	// more, none included.
	tail bool
	// literal is how many of its words are literal: what makes one rule
	// more specific than another.
	literal int
	// arg is an arg rule's glob, matched against each word after the
	// command's first.
	arg       string
	outcome   Outcome
	operation *policy.Operation
}

// compileRule reads an ExecRule. A pattern is words separated by single
// spaces, so that a pattern has one spelling and two rules that look
// different are different.
func compileRule(e policy.ExecRule) (rule, error) {
	r := rule{name: e.Command, outcome: Allow}
	if e.Arg != "" {
		r.name = strings.TrimPrefix(e.Command+" [arg "+e.Arg+"]", " ")
	}
	switch {
	case e.Ask && e.Refuse:
		return rule{}, fmt.Errorf("exec rule %q both asks and refuses", r.name)
	case e.Ask:
		r.outcome = Ask
	case e.Refuse:
		r.outcome = Refuse
	}
	if e.Command == "" && e.Arg == "" {
		return rule{}, errors.New("exec rule with no command and no arg")
	}
	if e.Command != "" {
		if err := r.compileCommand(e.Command); err != nil {
			return rule{}, fmt.Errorf("exec rule %q: %w", r.name, err)
		}
	}
	if e.Arg != "" {
		if err := checkGlob(e.Arg); err != nil {
			return rule{}, fmt.Errorf("exec rule %q: arg %w", r.name, err)
		}
		if r.outcome == Allow {
			// A command is admitted by its command rule or not at all: an
			// arg rule that admitted would admit whatever else the
			// command's words said.
			return rule{}, fmt.Errorf("exec rule %q: an arg rule only asks or refuses", r.name)
		}
		r.arg = e.Arg
	}
	o, err := operation(e.Operation)
	if err != nil {
		return rule{}, fmt.Errorf("exec rule %q: %w", r.name, err)
	}
	r.operation = o
	return r, nil
}

func (r *rule) compileCommand(pattern string) error {
	r.command = true
	ws := strings.Split(pattern, " ")
	for i, w := range ws {
		switch {
		case w == "":
			return errors.New("words are separated by one space, with none before or after")
		case w == anyWords:
			if i != len(ws)-1 {
				return fmt.Errorf("%q is only the last word", anyWords)
			}
			r.tail = true
			ws = ws[:i]
		case w == anyWord:
		default:
			for j := 0; j < len(w); j++ {
				if !plainByte(w[j]) {
					return fmt.Errorf("word %q is not %q, %q or plain: letters, digits and _@%%+=:,./-", w, anyWord, anyWords)
				}
			}
			switch w[0] {
			case '=':
				return fmt.Errorf("word %q begins =, which zsh reads as a command's path, and no command it would match is readable", w)
			case '%':
				return fmt.Errorf("word %q begins %%, which fish may read as a process, and no command it would match is readable", w)
			}
			if i == 0 {
				if why := unreadableFirst(w); why != "" {
					return fmt.Errorf("its first word %q %s, and no command it would match is readable", w, why)
				}
			}
			r.literal++
		}
	}
	if len(ws) > 0 && ws[0] == "env" && (len(ws) > 1 || r.tail) {
		// env with a command is decided as the command, and env with an
		// option is unreadable: only env alone is ever env.
		return errors.New(`"env" is only ever alone: env with a command is decided as that command`)
	}
	r.words = ws
	return nil
}

// checkGlob holds an arg glob to bytes a readable word can hold, and to
// something narrower than every word.
func checkGlob(g string) error {
	for i := 0; i < len(g); i++ {
		if !quotedByte(g[i]) {
			return fmt.Errorf("%q: printable ASCII but ' \\ and !, which no readable word holds", g)
		}
	}
	switch {
	case strings.Contains(g, "**"):
		return fmt.Errorf("%q: a * never crosses a /, so ** says no more than *", g)
	case strings.Trim(g, "*") == "":
		return fmt.Errorf("%q matches every word: that is unmatched's to say", g)
	}
	return nil
}

// operation is a rule's operation: an id and a summary, and a class of the
// three if any, as a path rule's must be.
func operation(o *policy.Operation) (*policy.Operation, error) {
	if o == nil {
		return nil, nil
	}
	if o.ID == "" || o.Summary == "" {
		return nil, errors.New("an operation needs an id and a summary")
	}
	switch o.Class {
	case "", "read", "write", "guarded":
	default:
		return nil, fmt.Errorf("operation %s: class %q: read, write or guarded", o.ID, o.Class)
	}
	return &policy.Operation{ID: o.ID, Summary: o.Summary, Description: o.Description, Class: o.Class, Category: o.Category}, nil
}

// matches is whether the rule's pattern matches a simple command's words:
// each word as the pattern says, and no more words than it has unless it
// ends "**".
func (r rule) matches(cmd []string) bool {
	if len(cmd) < len(r.words) || !r.tail && len(cmd) != len(r.words) {
		return false
	}
	for i, w := range r.words {
		if w != anyWord && w != cmd[i] {
			return false
		}
	}
	return true
}

// argMatches is whether an arg rule's glob matches any of a simple command's
// arguments, or its assignments: the word whole, what follows its first = --
// `--key=id_rsa`, `KUBECONFIG=/root/.kube/config` -- and each /-separated
// part of either. That catches a path to a secret spelt plainly,
// `/root/.ssh/id_ed25519` or `--file=/root/.ssh/x`, wherever it is in a
// word; it does not catch one a command finds for itself.
func (r rule) argMatches(c Simple) bool {
	for _, w := range append(c.Words[1:len(c.Words):len(c.Words)], c.Assignments...) {
		forms := []string{w}
		if _, v, ok := strings.Cut(w, "="); ok {
			forms = append(forms, v)
		}
		for _, f := range forms {
			if glob(r.arg, f) {
				return true
			}
			if strings.Contains(f, "/") {
				for p := range strings.SplitSeq(f, "/") {
					if glob(r.arg, p) {
						return true
					}
				}
			}
		}
	}
	return false
}

// glob is whether s matches g, whose * is any run of bytes but /, and whose
// every other byte is itself.
func glob(g, s string) bool {
	px, sx := 0, 0
	// Where to go back to when what follows the last * does not match: that
	// * taking one more byte.
	starPx, starSx := -1, -1
	for px < len(g) || sx < len(s) {
		if px < len(g) {
			switch c := g[px]; {
			case c == '*':
				starPx, starSx = px, sx
				px++
				continue
			case sx < len(s) && s[sx] == c:
				px++
				sx++
				continue
			}
		}
		// A * never takes a /, and since every / must then be matched by
		// one of g's own, no * before the last one taking more would help.
		if starPx >= 0 && starSx < len(s) && s[starSx] != '/' {
			starSx++
			px, sx = starPx+1, starSx
			continue
		}
		return false
	}
	return true
}
