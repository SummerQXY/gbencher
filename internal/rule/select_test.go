package rule_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/rule"
)

func selectionSet() *rule.Set {
	return &rule.Set{Source: "embedded", Rules: []*rule.Rule{
		{ID: "cis-gcp-1.1", Profile: "L1", Benchmark: rule.Benchmark{ID: "cis-gcp", Version: "1.0"}, Params: map[string]any{"settings": map[string]any{"left": 1, "right": 2}, "ports": []any{22}}, Hash: "hash-a"},
		{ID: "cis-gke-3.1.1", Profile: "L1", Benchmark: rule.Benchmark{ID: "cis-gke", Version: "2.0"}, Hash: "hash-b"},
		{ID: "cis-gke-3.1.2", Profile: "L2", Benchmark: rule.Benchmark{ID: "cis-gke", Version: "2.0"}, Hash: "hash-c"},
		{ID: "cis-gke-3.1.3", Profile: "L1", Benchmark: rule.Benchmark{ID: "cis-gke", Version: "2.0"}, Hash: "hash-d"},
		{ID: "cis-gke-3.1.4", Profile: "L2", Benchmark: rule.Benchmark{ID: "cis-gke", Version: "2.0"}, Hash: "hash-e"},
	}}
}

func TestSelect_UnmatchedPatternIsError(t *testing.T) {
	_, err := rule.Select(selectionSet(), nil, rule.Selection{Include: []string{"cis-gcp-9.99"}})
	if err == nil || !strings.Contains(err.Error(), "cis-gcp-9.99") {
		t.Fatalf("got %v", err)
	}
}

func TestSelect_EmptyResultIsError(t *testing.T) {
	p := &rule.Profile{Levels: []string{"L1"}}
	_, err := rule.Select(selectionSet(), p, rule.Selection{Levels: []string{"L2"}})
	if err == nil || !strings.Contains(err.Error(), "no rules selected") {
		t.Fatalf("error = %v, want no rules selected", err)
	}
	_, err = rule.Select(selectionSet(), nil, rule.Selection{Include: []string{"cis-gcp-9.99"}})
	if err == nil || !strings.Contains(err.Error(), "cis-gcp-9.99") {
		t.Fatalf("error = %v, want unmatched pattern", err)
	}
}

func TestSelect_ExcludeGlob(t *testing.T) {
	rules, err := rule.Select(selectionSet(), nil, rule.Selection{Exclude: []string{"cis-gke-3.1.*"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := selectedIDs(rules); !reflect.DeepEqual(got, []string{"cis-gcp-1.1"}) {
		t.Fatalf("selected ids = %v", got)
	}
	if removed := len(selectionSet().Rules) - len(rules); removed != 4 {
		t.Fatalf("glob excluded %d rules, want 4", removed)
	}
}

func TestSelect_ExactSelectionAndOverrides(t *testing.T) {
	p := &rule.Profile{Include: []string{"cis-gcp-1.1"}, Overrides: map[string]rule.Override{
		"cis-gcp-1.1": {Params: map[string]any{"settings": map[string]any{"left": 9}}},
	}}
	rules, err := rule.Select(selectionSet(), p, rule.Selection{Set: []rule.ParamSet{{RuleID: "cis-gcp-1.1", Param: "settings", Value: map[string]any{"right": 8}}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := selectedIDs(rules); !reflect.DeepEqual(got, []string{"cis-gcp-1.1"}) {
		t.Fatalf("selected ids = %v", got)
	}
	want := map[string]any{"left": 9, "right": 8}
	if !reflect.DeepEqual(rules[0].Params["settings"], want) {
		t.Fatalf("params = %#v, want %#v", rules[0].Params["settings"], want)
	}
	if rules[0].Hash != "hash-a" || selectionSet().Rules[0].Params["settings"].(map[string]any)["left"] != 1 {
		t.Fatalf("selection changed hash or source rule: %+v", rules[0])
	}
}

func TestSelect_SortsRulesAndPreservesHashesAndInputs(t *testing.T) {
	b := &rule.Rule{ID: "rule-b", Hash: "hash-b", Params: map[string]any{"value": 2}}
	a := &rule.Rule{ID: "rule-a", Hash: "hash-a", Params: map[string]any{"value": 1}}
	set := &rule.Set{Rules: []*rule.Rule{b, a}}
	rules, err := rule.Select(set, nil, rule.Selection{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := selectedIDs(rules), []string{"rule-a", "rule-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected ids = %v, want %v", got, want)
	}
	if rules[0].Hash != "hash-a" || rules[1].Hash != "hash-b" {
		t.Fatalf("selected hashes = %q, %q", rules[0].Hash, rules[1].Hash)
	}
	if b.Params["value"] != 2 || a.Params["value"] != 1 || b.Hash != "hash-b" || a.Hash != "hash-a" {
		t.Fatalf("source rules changed: a=%+v b=%+v", a, b)
	}
}

func TestSelect_RepeatedSetLayersDeepMergeAndPreserveHash(t *testing.T) {
	r := &rule.Rule{
		ID: "rule-a", Hash: "source-hash",
		Params: map[string]any{"obj": map[string]any{"x": 1, "y": 2}},
	}
	set := &rule.Set{Rules: []*rule.Rule{r}}
	rules, err := rule.Select(set, nil, rule.Selection{Set: []rule.ParamSet{
		{RuleID: "rule-a", Param: "obj", Value: map[string]any{"x": 3}},
		{RuleID: "rule-a", Param: "obj", Value: map[string]any{"y": 4}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"x": 3, "y": 4}
	if got := rules[0].Params["obj"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("effective obj = %#v, want %#v", got, want)
	}
	if rules[0].Hash != "source-hash" || r.Hash != "source-hash" {
		t.Fatalf("rule hash changed: selected=%q source=%q", rules[0].Hash, r.Hash)
	}
	if got := r.Params["obj"]; !reflect.DeepEqual(got, map[string]any{"x": 1, "y": 2}) {
		t.Fatalf("source params changed: %#v", got)
	}
}

func TestMerge_OverlayReplacesByIDAndAppends(t *testing.T) {
	base := &rule.Set{Source: "embedded", Rules: []*rule.Rule{{ID: "b", Hash: "base-b"}, {ID: "a", Hash: "base-a"}}}
	overlay := &rule.Set{Rules: []*rule.Rule{{ID: "a", Hash: "external-a"}, {ID: "c", Hash: "external-c"}}}
	merged := rule.Merge(base, overlay)
	if got := selectedIDs(merged.Rules); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("merged ids = %v", got)
	}
	if merged.Rules[0].Hash != "external-a" || merged.Source != "external" || merged.Hash == base.Hash {
		t.Fatalf("merged set = %+v", merged)
	}
}

func selectedIDs(rules []*rule.Rule) []string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids
}
