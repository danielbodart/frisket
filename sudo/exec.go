package sudo

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/danielbodart/frisket/execrule"
	"github.com/danielbodart/frisket/policy"
)

// Rule is what the gate answers for the commands one exec pattern matches,
// run as RunAs ("" is root): "allow" runs it with no question and no
// password, "ask" puts a plain Allow/Refuse question with no password, and
// "refuse" refuses it. Answered by the host's settings and a project's
// signed chase.json alike, as sudo.exec.<pattern>.
type Rule struct {
	RunAs  string `json:"runAs,omitempty"`
	Answer string `json:"answer"`
}

// UnmarshalJSON reads a rule with its keys spelt exactly: encoding/json
// would take "runas" or "Answer" for a field, and a project's layer, merged
// key by key, would then hold two spellings of one setting.
func (r *Rule) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	if m == nil {
		return errors.New("a rule is a JSON object")
	}
	*r = Rule{}
	for k, v := range m {
		var dst *string
		switch k {
		case "runAs":
			dst = &r.RunAs
		case "answer":
			dst = &r.Answer
		default:
			return fmt.Errorf("unknown field %q: a rule has runAs and answer", k)
		}
		if err := json.Unmarshal(v, dst); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
	}
	return nil
}

// Answers a rule may give.
const (
	Allow  = "allow"
	Ask    = "ask"
	Refuse = "refuse"
)

// ExecRules are exec rules compiled, a set for each user they run as.
// The zero value, and nil, match nothing.
type ExecRules struct {
	byRunAs map[string]*execrule.Rules
	// never is the pattern of the rule Compile adds to every set so that
	// one holding only refusals and arg rules compiles: its first word is
	// no absolute path, so it matches no command the gate decides.
	never string
}

// never is that rule's pattern.
const never = "frisket-sudo-no-command"

var loginName = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

// CheckExec reads rules as CompileExec does, and says what is wrong.
func CheckExec(rules map[string]Rule) error {
	_, err := CompileExec(rules)
	return err
}

// CompileExec reads exec rules keyed by execrule's rule name: a command
// pattern whose first word is a program's absolute, clean path (the gate
// decides the resolved command, so any other first word could never
// match), then words, "*" for one and a last "**" for any number; and
// optionally " [arg GLOB]" after it, an arg rule, which only asks or
// refuses. A literal pattern beats a pattern, a narrower one a wider one,
// and an arg rule only makes the answer stricter.
func CompileExec(rules map[string]Rule) (*ExecRules, error) {
	sets := map[string][]policy.ExecRule{}
	for _, key := range slices.Sorted(maps.Keys(rules)) {
		r := rules[key]
		command, arg := policy.RuleName(key)
		first, _, _ := strings.Cut(command, " ")
		switch {
		case command == "":
			return nil, fmt.Errorf("exec.%s: no command pattern: a rule names the program it is for", key)
		case !filepath.IsAbs(first) || filepath.Clean(first) != first:
			return nil, fmt.Errorf("exec.%s: %q is not a program's absolute, clean path, so the rule could never match: the gate decides the resolved command, /run/current-system/sw/bin/systemctl, not systemctl", key, first)
		case r.RunAs != "" && !loginName.MatchString(r.RunAs):
			return nil, fmt.Errorf("exec.%s.runAs: %q is not a user's name", key, r.RunAs)
		}
		e := policy.ExecRule{Command: command, Arg: arg, Operation: &policy.Operation{ID: "sudo-exec", Summary: key}}
		switch r.Answer {
		case Allow:
		case Ask:
			e.Ask = true
		case Refuse:
			e.Refuse = true
		default:
			return nil, fmt.Errorf("exec.%s.answer: %q is not allow, ask or refuse", key, r.Answer)
		}
		runAs := r.RunAs
		if runAs == "" {
			runAs = "root"
		}
		sets[runAs] = append(sets[runAs], e)
	}
	out := &ExecRules{byRunAs: map[string]*execrule.Rules{}, never: never}
	for runAs, set := range sets {
		// Unmatched refuses, so that an arg rule that asks never makes a
		// command no command rule matches any less asked than unmatched:
		// unmatched, for the gate, is its password, stricter than a
		// question. The rule that never matches is there for a set with no
		// rule that admits, which execrule would refuse as refusing every
		// command.
		r, err := execrule.Compile(policy.SSHRoute{Exec: append(set, policy.ExecRule{Command: never}), Unmatched: "refuse"})
		if err != nil {
			return nil, fmt.Errorf("exec: %w", err)
		}
		out.byRunAs[runAs] = r
	}
	return out, nil
}

// Match is the rule that decides a command, if one does.
type Match struct {
	Answer string
	// Pattern is the deciding rule's key, as the settings name it.
	Pattern string
}

// Decide is the rules' answer for the resolved command, words[0] the
// program's absolute path, run as runAs: ok false when no rule for that
// user matches it, which is the gate's to decide as it would with no rules.
// A rule for another user never matches.
func (e *ExecRules) Decide(runAs string, words []string) (Match, bool) {
	if e == nil || runAs == "" || len(words) == 0 {
		return Match{}, false
	}
	r := e.byRunAs[runAs]
	if r == nil {
		return Match{}, false
	}
	d := r.DecideWords(words)
	if d.Rule == execrule.RuleUnmatched || d.Rule == e.never || d.Operation == nil {
		return Match{}, false
	}
	return Match{Answer: d.Outcome.String(), Pattern: d.Operation.Summary}, true
}
