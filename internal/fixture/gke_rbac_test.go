package fixture_test

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/fixture"
	"github.com/SummerQXY/gbencher/internal/report"
	"github.com/SummerQXY/gbencher/internal/rule"
)

var gkeRBACRuleIDs = []string{
	"cis-gke-4.1.1", "cis-gke-4.1.2", "cis-gke-4.1.3",
	"cis-gke-4.1.4", "cis-gke-4.1.5", "cis-gke-4.1.6",
	"cis-gke-4.1.7", "cis-gke-4.1.8", "cis-gke-4.1.9",
}

func TestGKERBACFixtureBatchCoversNineRules(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, ruleID := range gkeRBACRuleIDs {
		t.Run(ruleID, func(t *testing.T) {
			current, ok := set.Get(ruleID)
			if !ok {
				t.Fatalf("rule %s not found", ruleID)
			}
			cases, err := fixture.LoadDir(filepath.Join("..", "..", "testdata", "rules", ruleID))
			if err != nil {
				t.Fatal(err)
			}
			seen := make(map[string]bool)
			for _, input := range cases {
				got, err := fixture.Evaluate(input, current)
				if err != nil {
					t.Fatalf("evaluate fixture: %v", err)
				}
				if len(got) != len(input.Expect) {
					t.Fatalf("result count = %d, want %d", len(got), len(input.Expect))
				}
				want := append([]fixture.Expect(nil), input.Expect...)
				sort.Slice(got, func(i, j int) bool {
					if got[i].ResourceKey != got[j].ResourceKey {
						return got[i].ResourceKey < got[j].ResourceKey
					}
					return got[i].Status < got[j].Status
				})
				sort.Slice(want, func(i, j int) bool {
					if want[i].ResourceKey != want[j].ResourceKey {
						return want[i].ResourceKey < want[j].ResourceKey
					}
					return want[i].Status < want[j].Status
				})
				for i := range got {
					if got[i] != want[i] {
						t.Fatalf("result[%d] = %+v, want %+v", i, got[i], want[i])
					}
					seen[got[i].Status] = true
				}
			}
			for _, status := range []string{"PASS", "FAIL", "NOT_APPLICABLE"} {
				if !seen[status] {
					t.Errorf("missing %s fixture", status)
				}
			}
			if strings.TrimSpace(current.Check.ReviewWhen) != "" && !seen["REVIEW"] {
				t.Error("missing REVIEW fixture for contextual rule")
			}
		})
	}
}

func TestGKERBACFixturesDeclareSourceProvenance(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, ruleID := range gkeRBACRuleIDs {
		current, ok := set.Get(ruleID)
		if !ok {
			t.Fatalf("rule %s not found", ruleID)
		}
		cases, err := fixture.LoadDir(filepath.Join("..", "..", "testdata", "rules", ruleID))
		if err != nil {
			t.Fatal(err)
		}
		for i, input := range cases {
			for _, step := range current.Collect {
				if got := input.Meta.Provenance[step.ID]; got != "schema" {
					t.Errorf("%s case %d step %s provenance = %q, want schema", ruleID, i, step.ID, got)
				}
			}
		}
	}
}

func TestGKERBACPodKeyMergesControllerMembers(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	current, ok := set.Get("cis-gke-4.1.5")
	if !ok {
		t.Fatal("cis-gke-4.1.5 not found")
	}
	input, err := fixture.LoadDir(filepath.Join("..", "..", "testdata", "rules", current.ID))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range input {
		if item.Expect[0].ResourceKey == "payments/Deployment/api" {
			got, err := fixture.Evaluate(item, current)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 || got[0].ResourceKey != "payments/Deployment/api" || got[1].ResourceKey != "payments/Deployment/api" {
				t.Fatalf("rolling update resources = %+v, want two members with stable Deployment key", got)
			}
			targetKey := "projects/example-project/locations/us-central1/clusters/example-cluster"
			resultItems := make([]report.Result, 0, len(got))
			for i, pod := range item.Data["pods"].(map[string]any)["items"].([]any) {
				podObject := pod.(map[string]any)
				metadata := podObject["metadata"].(map[string]any)
				podSpec := podObject["spec"].(map[string]any)
				status := "PASS"
				if podSpec["serviceAccountName"] == "default" {
					status = "FAIL"
				}
				resultItems = append(resultItems, report.Result{
					Rule: report.RuleRef{
						ID: current.ID, Ref: current.Ref, Title: current.Title,
						Profile: current.Profile, Severity: current.Severity, Mode: current.Mode,
					},
					Target:     report.TargetRef{Type: "cluster", Key: targetKey, ProjectID: "example-project", Cluster: "example-cluster"},
					Resource:   report.ResourceRef{Kind: "k8s.io/Pod", Name: metadata["name"].(string), Key: got[i].ResourceKey},
					Collection: report.Collection{Status: "SUCCEEDED"},
					Assessment: report.Assessment{Status: status},
				})
			}
			assembled, err := report.Assemble(report.Input{
				Rules:   []*rule.Rule{current},
				Units:   []report.UnitRef{{RuleID: current.ID, TargetKey: targetKey, Outcome: "evaluated"}},
				Results: resultItems,
			})
			if err != nil {
				t.Fatalf("merge rolling update members: %v", err)
			}
			if len(assembled.Results) != 1 || assembled.Results[0].Resource.Members != 2 || assembled.Results[0].Assessment.Status != "FAIL" {
				t.Fatalf("merged rolling update result = %+v, want one FAIL result with two members", assembled.Results)
			}
			if assembled.Results[0].FindingKey != report.FindingKey(current.ID, targetKey, "payments/Deployment/api") {
				t.Fatalf("finding key = %q, want controller key identity", assembled.Results[0].FindingKey)
			}
			return
		}
	}
	t.Fatal("missing rolling update fixture")
}
