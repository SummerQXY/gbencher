package rule

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

// Selection contains the command-line filters and overrides applied after a profile.
type Selection struct {
	Benchmarks []string
	Levels     []string
	Include    []string
	Exclude    []string
	Set        []ParamSet
}

// ParamSet is one parsed --set assignment.
type ParamSet struct {
	RuleID string
	Param  string
	Value  any
}

// Select filters a set, applies profile and command-line overrides, and returns cloned rules
// ordered by id.
func Select(set *Set, profile *Profile, sel Selection) ([]*Rule, error) {
	if set == nil {
		return nil, fmt.Errorf("no rules selected")
	}
	byID := make(map[string]*Rule, len(set.Rules))
	for _, r := range set.Rules {
		if r != nil {
			byID[r.ID] = r
		}
	}

	if profile != nil {
		for id, override := range profile.Overrides {
			r, ok := byID[id]
			if !ok {
				return nil, fmt.Errorf("profile override references unknown rule %s", id)
			}
			if _, err := ApplyParams(r, override.Params); err != nil {
				return nil, err
			}
		}
	}
	for _, setArg := range sel.Set {
		if _, ok := byID[setArg.RuleID]; !ok {
			return nil, fmt.Errorf("--set references unknown rule %s", setArg.RuleID)
		}
	}

	all := slices.Clone(set.Rules)
	slices.SortFunc(all, func(a, b *Rule) int {
		if a == nil {
			if b == nil {
				return 0
			}
			return 1
		}
		if b == nil {
			return -1
		}
		return strings.Compare(a.ID, b.ID)
	})
	chosen := make(map[string]bool, len(all))
	for _, r := range all {
		if r != nil {
			chosen[r.ID] = true
		}
	}
	if profile != nil {
		var err error
		chosen, err = narrowByPatterns(chosen, profile.Include, byID)
		if err != nil {
			return nil, err
		}
		chosen, err = excludePatterns(chosen, profile.Exclude, byID)
		if err != nil {
			return nil, err
		}
		var unmatched []string
		for _, benchmark := range profile.Benchmarks {
			if !hasBenchmark(all, benchmark) {
				unmatched = append(unmatched, benchmark)
			}
		}
		if len(unmatched) > 0 {
			return nil, fmt.Errorf("unknown benchmark %s", strings.Join(unmatched, ", "))
		}
		chosen = filterSet(chosen, all, profile.Benchmarks, profile.Levels)
	}
	var err error
	chosen, err = narrowByPatterns(chosen, sel.Include, byID)
	if err != nil {
		return nil, err
	}
	chosen, err = excludePatterns(chosen, sel.Exclude, byID)
	if err != nil {
		return nil, err
	}
	chosen = filterSet(chosen, all, sel.Benchmarks, sel.Levels)
	if len(chosen) == 0 {
		return nil, fmt.Errorf("no rules selected")
	}

	out := make([]*Rule, 0, len(chosen))
	for _, original := range all {
		if original == nil || !chosen[original.ID] {
			continue
		}
		var layers []map[string]any
		if profile != nil {
			if override, ok := profile.Overrides[original.ID]; ok {
				layers = append(layers, override.Params)
			}
		}
		for _, assignment := range sel.Set {
			if assignment.RuleID == original.ID {
				layers = append(layers, map[string]any{assignment.Param: assignment.Value})
			}
		}
		params, err := ApplyParams(original, layers...)
		if err != nil {
			return nil, err
		}
		copy := *original
		copy.Params = params
		out = append(out, &copy)
	}
	return out, nil
}

// Merge applies overlay rules by id, with overlay content taking precedence.
func Merge(base, overlay *Set) *Set {
	byID := make(map[string]*Rule)
	if base != nil {
		for _, r := range base.Rules {
			if r != nil {
				byID[r.ID] = r
			}
		}
	}
	if overlay != nil {
		for _, r := range overlay.Rules {
			if r != nil {
				byID[r.ID] = r
			}
		}
	}
	rules := make([]*Rule, 0, len(byID))
	for _, r := range byID {
		rules = append(rules, r)
	}
	slices.SortFunc(rules, func(a, b *Rule) int { return strings.Compare(a.ID, b.ID) })
	return &Set{Rules: rules, Hash: hashSet(rules), Source: "external"}
}

func narrowByPatterns(chosen map[string]bool, patterns []string, all map[string]*Rule) (map[string]bool, error) {
	if len(patterns) == 0 {
		return chosen, nil
	}
	matched := make(map[string]bool)
	for _, pattern := range patterns {
		ids, err := matchingIDs(pattern, all)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("rule pattern %q matched no rules", pattern)
		}
		for _, id := range ids {
			matched[id] = true
		}
	}
	for id := range chosen {
		if !matched[id] {
			delete(chosen, id)
		}
	}
	return chosen, nil
}

func excludePatterns(chosen map[string]bool, patterns []string, all map[string]*Rule) (map[string]bool, error) {
	for _, pattern := range patterns {
		ids, err := matchingIDs(pattern, all)
		if err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("rule pattern %q matched no rules", pattern)
		}
		for _, id := range ids {
			delete(chosen, id)
		}
	}
	return chosen, nil
}

func matchingIDs(pattern string, all map[string]*Rule) ([]string, error) {
	if _, err := path.Match(pattern, ""); err != nil {
		return nil, fmt.Errorf("invalid rule pattern %q: %w", pattern, err)
	}
	var ids []string
	for id := range all {
		if ok, _ := path.Match(pattern, id); ok {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids, nil
}

func filterSet(chosen map[string]bool, all []*Rule, benchmarks, levels []string) map[string]bool {
	for _, r := range all {
		if r == nil || !chosen[r.ID] {
			continue
		}
		if len(benchmarks) > 0 && !slices.Contains(benchmarks, r.Benchmark.ID+"@"+r.Benchmark.Version) {
			delete(chosen, r.ID)
			continue
		}
		if len(levels) > 0 && !slices.Contains(levels, r.Profile) {
			delete(chosen, r.ID)
		}
	}
	return chosen
}

func hasBenchmark(rules []*Rule, benchmark string) bool {
	for _, r := range rules {
		if r != nil && r.Benchmark.ID+"@"+r.Benchmark.Version == benchmark {
			return true
		}
	}
	return false
}
