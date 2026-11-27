package restschema

import (
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/rules"
)

func corpusSet(t *testing.T) *rule.Set {
	t.Helper()
	files, violations, err := rule.LoadFiles(rules.FS)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Fatalf("corpus violations: %+v", violations)
	}
	set := &rule.Set{}
	for _, file := range files {
		set.Rules = append(set.Rules, file.Rules...)
	}
	return set
}

func TestRESTSchema_AllCorpusEndpointsMatch(t *testing.T) {
	set := corpusSet(t)
	result := Check(set)
	if len(result.Errors) != 0 {
		t.Fatalf("REST schema errors: %+v", result.Errors)
	}
	if len(result.Endpoints) != 9 {
		t.Fatalf("matched %d API endpoints, want 9", len(result.Endpoints))
	}
	for _, id := range []string{"cis-gcp-7.1", "cis-gcp-7.2", "cis-gcp-7.3", "cis-gcp-7.4"} {
		if !result.StaticOK[id] {
			t.Errorf("%s did not pass static field validation", id)
		}
	}
	for id, ok := range result.StaticOK {
		if strings.HasPrefix(id, "cis-gcp-5.") && ok {
			t.Errorf("Workspace rule %s earned static verification", id)
		}
	}
	verification, err := rule.ComputeVerification(set, t.TempDir(), result.StaticOK)
	if err != nil {
		t.Fatal(err)
	}
	for id := range result.Endpoints {
		if strings.HasPrefix(id, "cis-gcp-5.") && verification.Rules[id] != rule.VerificationNone {
			t.Errorf("Workspace rule %s verification = %q, want none", id, verification.Rules[id])
		}
	}
}

func TestRESTSchema_RejectsUnknownFieldPath(t *testing.T) {
	set := corpusSet(t)
	for _, current := range set.Rules {
		if current.ID == "cis-gcp-7.1" {
			current.Check.Assert = strings.Replace(current.Check.Assert, "access", "accessTypo", 1)
		}
	}
	result := Check(set)
	if len(result.Errors) == 0 {
		t.Fatal("unknown BigQuery response field passed schema validation")
	}
}

func TestRESTSchema_RejectsMutatedEndpoint(t *testing.T) {
	set := corpusSet(t)
	for _, current := range set.Rules {
		if current.ID == "cis-gcp-7.1" {
			current.Collect[0].API.Method = "POST"
			break
		}
	}
	result := Check(set)
	if len(result.Errors) == 0 {
		t.Fatal("mutated REST method passed schema validation")
	}
}

func TestRESTSchema_RejectsQueryParametersOutsideEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		ruleID string
		stepID string
		query  string
	}{
		{name: "BigQuery get rejects list query", ruleID: "cis-gcp-7.1", stepID: "dataset_details", query: "?all=true"},
		{name: "DLP list rejects unsupported query", ruleID: "cis-gcp-7.4", stepID: "discovery_configs", query: "?all=true"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set := corpusSet(t)
			mutateAPI(t, set, test.ruleID, test.stepID, func(api *rule.APIStep) {
				api.URL += test.query
			})
			result := Check(set)
			if len(result.Errors) == 0 {
				t.Fatal("query parameter not declared for this endpoint passed validation")
			}
		})
	}
}

func TestRESTSchema_RejectsUnknownFieldPathInForeach(t *testing.T) {
	tests := []struct {
		id string
	}{
		{id: "cis-gcp-7.2"},
		{id: "cis-gcp-7.4"},
	}
	for _, test := range tests {
		t.Run(test.id, func(t *testing.T) {
			set := corpusSet(t)
			for _, current := range set.Rules {
				if current.ID != test.id {
					continue
				}
				for i := range current.Collect {
					if strings.Contains(current.Collect[i].Foreach, "datasetReference.datasetId") {
						current.Collect[i].Foreach = strings.Replace(current.Collect[i].Foreach, "datasetReference.datasetId", "typo", 1)
						break
					}
				}
			}
			result := Check(set)
			if len(result.Errors) == 0 {
				t.Fatal("unknown field path in foreach passed schema validation")
			}
		})
	}
}

func mutateAPI(t *testing.T, set *rule.Set, ruleID, stepID string, mutate func(*rule.APIStep)) {
	t.Helper()
	for _, current := range set.Rules {
		if current.ID != ruleID {
			continue
		}
		for i := range current.Collect {
			step := &current.Collect[i]
			if step.ID == stepID && step.API != nil {
				mutate(step.API)
				return
			}
		}
	}
	t.Fatalf("API step %s.%s not found", ruleID, stepID)
}

func TestRESTSchema_UnknownPathCannotEarnStatic(t *testing.T) {
	set := corpusSet(t)
	for _, current := range set.Rules {
		if current.ID == "cis-gcp-7.1" {
			current.Check.Assert += " && r.unknownField == true"
		}
	}
	result := Check(set)
	if result.StaticOK["cis-gcp-7.1"] {
		t.Fatal("rule with an unresolved field path earned static verification")
	}
}

func TestRESTSchema_UnresolvedMacroPathWarns(t *testing.T) {
	set := corpusSet(t)
	for _, current := range set.Rules {
		if current.ID == "cis-gcp-7.1" {
			current.Check.Assert += " && unknown_items.exists(item, item.value == true)"
		}
	}
	result := Check(set)
	if len(result.Warnings) == 0 {
		t.Fatal("unresolved macro field path did not produce a warning")
	}
	if result.StaticOK["cis-gcp-7.1"] {
		t.Fatal("rule with an unresolved macro path earned static verification")
	}
}
