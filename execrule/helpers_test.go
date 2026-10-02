package execrule

// decide is rules' answer for command under unmatched, with no env names
// listed.
func decide(rules []rule, unmatched Outcome, command string) Decision {
	return (&Rules{rules: rules, unmatched: unmatched}).Decide(command)
}

// parse is command's simple commands' words, with no env names listed.
func parse(command string) ([][]string, bool) {
	cmds, ok := (&Rules{}).Parse(command)
	if !ok {
		return nil, false
	}
	out := make([][]string, len(cmds))
	for i, c := range cmds {
		out[i] = c.Words
	}
	return out, true
}
