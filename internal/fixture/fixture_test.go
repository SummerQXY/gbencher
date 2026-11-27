package fixture_test

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/SummerQXY/gbencher/internal/fixture"
	"github.com/SummerQXY/gbencher/internal/rule"
)

func TestEvaluate_PassAndFailFixture(t *testing.T) {
	cases, err := fixture.LoadDir("../../testdata/rules/cis-gcp-3.6")
	if err != nil {
		t.Fatal(err)
	}
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	current, ok := set.Get("cis-gcp-3.6")
	if !ok {
		t.Fatal("rule not found")
	}
	for _, c := range cases {
		got, err := fixture.Evaluate(c, current)
		if err != nil || !reflect.DeepEqual(got, c.Expect) {
			t.Fatalf("got=%+v err=%v want=%+v", got, err, c.Expect)
		}
	}
}

func TestEvaluate_EmptyResourcesAreNotApplicableAtTarget(t *testing.T) {
	tests := []struct {
		name   string
		data   map[string]any
		filter string
	}{
		{name: "empty resource source", data: map[string]any{"items": []any{}}},
		{name: "filtered resource source", data: map[string]any{"items": []any{map[string]any{"name": "sample"}}}, filter: "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			current := &rule.Rule{
				ID: "cis-gcp-fixture-empty",
				Resource: &rule.Resource{
					From:   "data.items",
					Filter: tt.filter,
					Name:   "r.name",
				},
				Check: rule.Check{Assert: "true", Message: "compliant"},
			}
			got, err := fixture.Evaluate(fixture.Case{
				Target: fixture.Target{Type: "project", ProjectID: "example-prod"},
				Data:   tt.data,
			}, current)
			if err != nil {
				t.Fatal(err)
			}
			want := []fixture.Expect{{RuleID: current.ID, ResourceKey: "projects/example-prod", Status: "NOT_APPLICABLE"}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Evaluate = %+v, want %+v", got, want)
			}
		})
	}
}

func TestEvaluate_EmptyPolicyPassesEmptyAndFilteredResources(t *testing.T) {
	tests := []struct {
		name   string
		data   map[string]any
		filter string
	}{
		{name: "empty resource source", data: map[string]any{"items": []any{}}},
		{name: "filtered resource source", data: map[string]any{"items": []any{map[string]any{"name": "sample"}}}, filter: "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			current := &rule.Rule{
				ID:       "cis-gcp-fixture-empty-pass",
				Resource: &rule.Resource{From: "data.items", Filter: tt.filter, Name: "r.name", Empty: "pass"},
				Check:    rule.Check{Assert: "true", Message: "compliant"},
			}
			got, err := fixture.Evaluate(fixture.Case{
				Target: fixture.Target{Type: "project", ProjectID: "example-prod"},
				Data:   tt.data,
			}, current)
			if err != nil {
				t.Fatal(err)
			}
			want := []fixture.Expect{{RuleID: current.ID, ResourceKey: "projects/example-prod", Status: "PASS"}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Evaluate = %+v, want %+v", got, want)
			}
		})
	}
}

func TestEvaluate_EmptyPolicyPassesToleratedCollectionFailure(t *testing.T) {
	current := &rule.Rule{
		ID:       "cis-gcp-fixture-empty-pass-tolerated",
		Collect:  []rule.Step{{ID: "items", Gcloud: "compute instances list", Parse: "json", OnError: "empty"}},
		Resource: &rule.Resource{From: "data.items", Name: "r.name", Empty: "pass"},
		Check:    rule.Check{Assert: "true", Message: "compliant"},
	}
	got, err := fixture.Evaluate(fixture.Case{
		Target:           fixture.Target{Type: "project", ProjectID: "example-prod"},
		CollectionErrors: map[string]string{"items": "service_disabled"},
	}, current)
	if err != nil {
		t.Fatal(err)
	}
	want := []fixture.Expect{{RuleID: current.ID, ResourceKey: "projects/example-prod", Status: "PASS"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Evaluate = %+v, want %+v", got, want)
	}
}

func TestEvaluate_EmptyPolicyDoesNotOverrideServiceDisabled(t *testing.T) {
	current := &rule.Rule{
		ID:       "cis-gcp-fixture-empty-pass-service-disabled",
		Services: []string{"compute.googleapis.com"},
		Resource: &rule.Resource{From: "data.items", Name: "r.name", Empty: "pass"},
		Check:    rule.Check{Assert: "true", Message: "compliant"},
	}
	got, err := fixture.Evaluate(fixture.Case{
		Target:           fixture.Target{Type: "project", ProjectID: "example-prod"},
		DisabledServices: []string{"compute.googleapis.com"},
	}, current)
	if err != nil {
		t.Fatal(err)
	}
	want := []fixture.Expect{{RuleID: current.ID, ResourceKey: "projects/example-prod", Status: "NOT_APPLICABLE"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Evaluate = %+v, want %+v", got, want)
	}
}

func TestEvaluate_ResourceExpressionErrorDoesNotBecomeNotApplicable(t *testing.T) {
	current := &rule.Rule{
		ID:       "cis-gcp-fixture-expression-error",
		Resource: &rule.Resource{From: "data.items[", Name: "r.name", Empty: "pass"},
		Check:    rule.Check{Assert: "true", Message: "compliant"},
	}
	got, err := fixture.Evaluate(fixture.Case{
		Target: fixture.Target{Type: "project", ProjectID: "example-prod"},
		Data:   map[string]any{"items": []any{}},
	}, current)
	if err == nil {
		t.Fatalf("Evaluate returned %+v without an expression error", got)
	}
}

func TestFixture_RejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "unknown.json"), []byte(`{"target":{"project_id":"example-prod"},"data":{},"expect":[],"meta":{"provenance":{}},"unexpected":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.LoadDir(dir); err == nil {
		t.Fatal("LoadDir accepted an unknown key")
	}
}

func TestEvaluate_AllTaskFixturesMatch(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, ruleID := range []string{"cis-gcp-3.6", "cis-gcp-1.5", "cis-gke-3.1.1"} {
		t.Run(ruleID, func(t *testing.T) {
			cases, err := fixture.LoadDir("../../testdata/rules/" + ruleID)
			if err != nil {
				t.Fatal(err)
			}
			current, ok := set.Get(ruleID)
			if !ok {
				t.Fatal("rule not found")
			}
			for _, c := range cases {
				got, err := fixture.Evaluate(c, current)
				if err != nil {
					t.Fatal(err)
				}
				want := append([]fixture.Expect(nil), c.Expect...)
				sort.Slice(want, func(i, j int) bool { return want[i].ResourceKey < want[j].ResourceKey })
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("got=%+v want=%+v", got, want)
				}
			}
		})
	}
}

func TestFixture_DecodeJSONUsesIntegerContract(t *testing.T) {
	dir := t.TempDir()
	content := `{"target":{"type":"project","project_id":"example-prod"},"data":{"step":{"count":123456789012}},"expect":[{"rule_id":"r","resource_key":"k","status":"PASS"}],"meta":{"provenance":{"step":"handwritten"}}}`
	if err := os.WriteFile(filepath.Join(dir, "case.json"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cases, err := fixture.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if value := cases[0].Data["step"].(map[string]any)["count"]; value != int64(123456789012) {
		t.Fatalf("decoded number has type %T and value %v", value, value)
	}
}

func TestFixtureClusterProvenanceRoundTrips(t *testing.T) {
	dir := t.TempDir()
	content := `{"target":{"type":"cluster","project_id":"example-prod","cluster_name":"sample","cluster_location":"us-central1"},"cluster":{"name":"sample"},"data":{},"expect":[{"rule_id":"cluster-rule","resource_key":"cluster-rule","status":"PASS"}],"meta":{"provenance":{"cluster":"handwritten","nodes":"schema"}}}`
	if err := os.WriteFile(filepath.Join(dir, "case.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cases, err := fixture.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"cluster": "handwritten", "nodes": "schema"}
	if !reflect.DeepEqual(cases[0].Meta.Provenance, want) {
		t.Fatalf("provenance = %v, want %v", cases[0].Meta.Provenance, want)
	}
}

func TestFixture_LoadsOfflineScenarioInputs(t *testing.T) {
	dir := t.TempDir()
	content := `{"target":{"type":"project","project_id":"example-prod"},"data":{},"expect":[{"rule_id":"r","resource_key":"projects/example-prod","status":"FAIL"}],"meta":{"provenance":{"items":"handwritten"}},"disabled_services":["compute.googleapis.com"],"collection_errors":{"items":"service_disabled"}}`
	if err := os.WriteFile(filepath.Join(dir, "case.json"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cases, err := fixture.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cases[0].DisabledServices, []string{"compute.googleapis.com"}) || !reflect.DeepEqual(cases[0].CollectionErrors, map[string]string{"items": "service_disabled"}) {
		t.Fatalf("scenario inputs = disabled:%v errors:%v", cases[0].DisabledServices, cases[0].CollectionErrors)
	}
}

func TestFixture_LoadsOptionalEvaluationTime(t *testing.T) {
	dir := t.TempDir()
	content := `{"target":{"type":"project","project_id":"example-prod"},"data":{},"now":"2026-11-17T10:03:20.444238Z","expect":[{"rule_id":"r","resource_key":"k","status":"PASS"}],"meta":{"provenance":{}}}`
	if err := os.WriteFile(filepath.Join(dir, "case.json"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cases, err := fixture.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 11, 17, 10, 3, 20, 444238000, time.UTC)
	if !cases[0].Now.Equal(want) {
		t.Fatalf("evaluation time = %s, want %s", cases[0].Now, want)
	}
}

func TestEvaluate_RejectsInvalidParams(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	current, ok := set.Get("cis-gcp-3.6")
	if !ok {
		t.Fatal("rule not found")
	}
	for _, tc := range []struct {
		name   string
		params map[string]any
	}{
		{name: "unknown", params: map[string]any{"unexpected": true}},
		{name: "wrong type", params: map[string]any{"ports": "22"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			currentCase := fixture.Case{
				Target: fixture.Target{Type: "project", ProjectID: "example-prod"},
				Data:   map[string]any{"firewalls": []any{}},
				Params: tc.params,
			}
			if _, err := fixture.Evaluate(currentCase, current); err == nil {
				t.Fatal("Evaluate accepted invalid fixture params")
			}
		})
	}
}

func TestFixture_RejectsIncompleteExpectAndInvalidProvenance(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
	}{
		{
			name: "incomplete expect",
			json: `{"target":{"type":"project"},"data":{},"expect":[{"rule_id":"r","resource_key":"k"}],"meta":{"provenance":{}}}`,
		},
		{
			name: "invalid provenance",
			json: `{"target":{"type":"project"},"data":{},"expect":[{"rule_id":"r","resource_key":"k","status":"PASS"}],"meta":{"provenance":{"step":"snapshot-ish"}}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "case.json"), []byte(tc.json), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.LoadDir(dir); err == nil {
				t.Fatal("LoadDir accepted malformed fixture metadata")
			}
		})
	}
}

func TestFixture_RejectsInvalidEvaluationTime(t *testing.T) {
	for _, value := range []string{`"not-a-time"`, `123`} {
		t.Run(value, func(t *testing.T) {
			dir := t.TempDir()
			content := `{"target":{"type":"project","project_id":"example-prod"},"data":{},"now":` + value + `,"expect":[{"rule_id":"r","resource_key":"k","status":"PASS"}],"meta":{"provenance":{}}}`
			if err := os.WriteFile(filepath.Join(dir, "case.json"), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.LoadDir(dir); err == nil {
				t.Fatal("LoadDir accepted an invalid evaluation time")
			}
		})
	}
}
