package execrule

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/danielbodart/frisket/policy"
)

// Outcome is what a route's rules say about a command. The zero value
// refuses, so a Decision nobody filled in admits nothing.
type Outcome int

const (
	Refuse Outcome = iota
	Ask
	Allow
)

// String is the outcome in the words a document's rules are written in.
func (o Outcome) String() string {
	switch o {
	case Allow:
		return "allow"
	case Ask:
		return "ask"
	}
	return "refuse"
}

// strictness orders outcomes: admitting, then asking, then refusing.
func strictness(o Outcome) int {
	switch o {
	case Allow:
		return 0
	case Ask:
		return 1
	}
	return 2
}

// RuleUnmatched is a Decision's Rule when no rule decided: the command, or
// a simple command in it, matched no command rule, or it was unreadable.
const RuleUnmatched = "unmatched"

// Decision is what a route's rules say about one command. Rule is the rule
// that decided -- its pattern, an arg rule's glob after it as "[arg .ssh]"
// -- or RuleUnmatched, and Operation its operation, if it has one.
// Operations are every operation the command's simple commands were decided
// by, where there are more than one. Every operation is the rules' own copy.
type Decision struct {
	Outcome    Outcome
	Rule       string
	Operation  *policy.Operation
	Operations []*policy.Operation
}

// Rules are a route's exec rules, env names and unmatched, compiled.
// Compile is the only way to make them, but for the zero value, which is
// none of either and unmatched "refuse".
type Rules struct {
	rules     []rule
	env       []string
	unmatched Outcome
}

// Compile reads a route's Exec, Env and Unmatched, and refuses what frisket
// would refuse to load: a rule that is not one, a rule listed twice, an env
// name that is not one, or listed twice, and a route that refuses every
// command. The rest of the route is no part of how it decides, and is
// neither read nor checked.
func Compile(route policy.SSHRoute) (*Rules, error) {
	r := &Rules{}
	switch route.Unmatched {
	case "", "ask":
		r.unmatched = Ask
	case "refuse":
		r.unmatched = Refuse
	default:
		return nil, fmt.Errorf("unmatched %q: ask or refuse", route.Unmatched)
	}
	env, err := checkEnv(route.Env)
	if err != nil {
		return nil, err
	}
	r.env = env
	seen := map[string]bool{}
	admits := r.unmatched == Ask
	for _, e := range route.Exec {
		ru, err := compileRule(e)
		if err != nil {
			return nil, err
		}
		if seen[ru.name] {
			return nil, fmt.Errorf("exec rule %q is listed twice", ru.name)
		}
		seen[ru.name] = true
		// An arg rule only tightens, so it neither admits nor asks about
		// anything a command rule or unmatched did not.
		admits = admits || ru.arg == "" && ru.outcome != Refuse
		r.rules = append(r.rules, ru)
	}
	if !admits {
		return nil, errors.New(`no rule admits or asks, and unmatched is "refuse": a route that refuses every command`)
	}
	return r, nil
}

// unsafeEnv are names no route may list, nor a prefix that covers one:
// each changes, for every command, what program runs or what code is in it
// -- PATH which ls, LD_PRELOAD and its kin what is linked into it, glibc's
// GCONV_PATH a module it loads, and the shell's own BASH_ENV, ENV, IFS,
// SHELLOPTS and BASHOPTS what a script it is does. With one of them listed,
// a rule for `ls` would admit any program at all. Beside them are the
// names glibc reads, in every program, as where to load data it trusts or
// how to run: LOCPATH its locales, NLSPATH its message catalogs, which hold
// printf formats, and GLIBC_TUNABLES, which ld.so parses before the program
// starts -- each among the names glibc itself takes from a setuid
// program's environment, and LOCPATH no locale, whatever its name says. A
// name ending _ stands for every name it begins.
//
// It is not every dangerous name, and could not be: a name one program
// reads as code -- LESSOPEN, PAGER, GIT_SSH_COMMAND, PYTHONPATH,
// NODE_OPTIONS -- is safe for every other. The names are the boundary, and
// whoever writes them lists only what changes nothing that matters: a
// locale, a timezone, a terminal's width.
var unsafeEnv = []string{
	"PATH", "LD_", "DYLD_", "GCONV_PATH", "BASH_ENV", "ENV", "IFS", "SHELLOPTS", "BASHOPTS",
	"LOCPATH", "NLSPATH", "GLIBC_TUNABLES",
}

// maxEnv bounds a route's env names, as every list in a document is
// bounded somewhere: each is matched against each assignment.
const maxEnv = 64

// checkEnv reads a route's env names: each a name a shell assigns, or one's
// start and a trailing *.
func checkEnv(names []string) ([]string, error) {
	if len(names) > maxEnv {
		return nil, fmt.Errorf("env: %d names, more than %d", len(names), maxEnv)
	}
	for i, n := range names {
		p, wild := strings.CutSuffix(n, "*")
		switch {
		case !identifier(p):
			return nil, fmt.Errorf("env[%d] %q: a name of letters, digits and _, not starting with a digit, or the start of one and a trailing *", i, n)
		case slices.Contains(names[:i], n):
			return nil, fmt.Errorf("env[%d] %q is listed twice", i, n)
		}
		for _, u := range unsafeEnv {
			uw := strings.HasSuffix(u, "_")
			if !wild && (n == u || uw && strings.HasPrefix(n, u)) ||
				wild && (strings.HasPrefix(u, p) || uw && strings.HasPrefix(p, u)) {
				what := u
				if uw {
					what += "*"
				}
				return nil, fmt.Errorf("env[%d] %q names %s, which changes what any command runs: no rule could say what such a command is", i, n, what)
			}
		}
	}
	return slices.Clone(names), nil
}

// Decide is the rules' answer for command: each simple command decided on
// its own, and the strictest of them deciding the whole, the first between
// equals -- `cd /etc && ls` is admitted only if both are, and `ls | sh` is
// whatever sh is. Every simple command runs or might, whatever joins it to
// the rest, so none is excused by an operator. A command that is not
// readable is unmatched.
func (r *Rules) Decide(command string) Decision {
	cmds, ok := r.Parse(command)
	if !ok {
		return Decision{Outcome: r.unmatched, Rule: RuleUnmatched}
	}
	var (
		d   Decision
		ops []*policy.Operation
	)
	for i, c := range cmds {
		outcome, by := r.decideSimple(c)
		if i == 0 || strictness(outcome) > strictness(d.Outcome) {
			d = Decision{Outcome: outcome, Rule: RuleUnmatched}
			if by != nil {
				d.Rule, d.Operation = by.name, by.operation
			}
		}
		// By id: an operation with several patterns is a rule for each,
		// each with its own copy of it, and is one operation all the same.
		if by != nil && by.operation != nil && !slices.ContainsFunc(ops, func(o *policy.Operation) bool {
			return o.ID == by.operation.ID
		}) {
			ops = append(ops, by.operation)
		}
	}
	if len(ops) > 1 {
		d.Operations = ops
	}
	return d
}

// decideSimple is the rules' answer for one simple command, and the rule
// that gave it, nil for unmatched. The command rule with the most literal
// words decides -- `systemctl status *` over `systemctl **` -- and between
// rules as literal as each other, the stricter: refusing beats asking, and
// asking beats admitting. Then every arg rule that matches can only make
// that stricter: an argument naming a secret refuses a command a rule
// admits, and one no rule matches. The first arg rule as strict as the
// answer is what gave it, though it changed nothing: the argument is the
// more particular reason, and a question or a log line that named only
// `cp **`, or unmatched, would hide the secret it was about.
func (r *Rules) decideSimple(c Simple) (Outcome, *rule) {
	var by *rule
	for i := range r.rules {
		ru := &r.rules[i]
		if ru.arg != "" || !ru.matches(c.Words) {
			continue
		}
		if by == nil || ru.literal > by.literal ||
			ru.literal == by.literal && strictness(ru.outcome) > strictness(by.outcome) {
			by = ru
		}
	}
	outcome := r.unmatched
	if by != nil {
		outcome = by.outcome
	}
	for i := range r.rules {
		ru := &r.rules[i]
		if ru.arg == "" || ru.command && !ru.matches(c.Words) || !ru.argMatches(c) {
			continue
		}
		if s := strictness(ru.outcome); s > strictness(outcome) ||
			s == strictness(outcome) && (by == nil || by.arg == "") {
			outcome, by = ru.outcome, ru
		}
	}
	return outcome, by
}
