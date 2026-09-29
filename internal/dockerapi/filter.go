package dockerapi

import "slices"

// MergeFilter judges a list's `filters` query value and narrows it to the
// project. raw is the value as the query gave it, "" when there is none. Each
// key must be one of the allowed names: `before` and `since` name other containers,
// and whether they are found would say whether those exist. Each value is
// moby's object of string to bool or its older array of strings, and comes
// out as the object, every term true, since moby ignores the bool: false is
// not a negation. Then `frisket.project=<project>` is added to the label
// terms, which moby ANDs for containers, volumes, networks and events, so the
// merge can only narrow what the list returns. A value it refuses is a
// *Refusal.
func MergeFilter(raw string, allowed []string, project string) (string, error) {
	merged := map[string]map[string]bool{}
	if raw != "" {
		tree, err := Read([]byte(raw))
		if err != nil {
			return "", &Refusal{Reason: ReasonQuery, Detail: "filters is not a JSON object", Log: "query=filters unreadable"}
		}
		for _, key := range sortedKeys(tree) {
			if !slices.Contains(allowed, key) {
				return "", &Refusal{Reason: ReasonQuery, Detail: "a filter this operation does not allow", Log: "query=filters." + quote(key) + " not allowed"}
			}
			terms, ok := filterTerms(tree[key])
			if !ok {
				return "", &Refusal{Reason: ReasonQuery, Detail: "a filter that is not a set of strings", Log: "query=filters." + logKey(key) + " not a set"}
			}
			merged[key] = terms
		}
	}
	if merged["label"] == nil {
		merged["label"] = map[string]bool{}
	}
	merged["label"][LabelKey+"="+project] = true
	out, err := Encode(merged)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func filterTerms(v any) (map[string]bool, bool) {
	terms := map[string]bool{}
	switch x := v.(type) {
	case map[string]any:
		for k, b := range x {
			if _, ok := b.(bool); !ok {
				return nil, false
			}
			terms[k] = true
		}
	case []any:
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			terms[s] = true
		}
	default:
		return nil, false
	}
	return terms, true
}
