package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/schemas"
)

func TestMergeResultsUsesSpecStatusPriority(t *testing.T) {
	statuses := []string{"FAIL", "ERROR", "REVIEW", "SKIPPED", "PASS"}
	for higher := range statuses {
		for lower := higher + 1; lower < len(statuses); lower++ {
			for _, pair := range [][2]int{{higher, lower}, {lower, higher}} {
				in := sampleInput(t)
				first := in.Results[0]
				first.Assessment.Status = statuses[pair[0]]
				second := first
				second.Assessment.Status = statuses[pair[1]]
				if first.Assessment.Status == "FAIL" || second.Assessment.Status == "FAIL" {
					first.Collection.Status = "SUCCEEDED"
					second.Collection.Status = "SUCCEEDED"
				} else if first.Assessment.Status == "ERROR" || second.Assessment.Status == "ERROR" || first.Assessment.Status == "SKIPPED" || second.Assessment.Status == "SKIPPED" {
					first.Collection.Status = "FAILED"
					second.Collection.Status = "FAILED"
				}
				in.Results = []Result{first, second}
				outcome := "evaluated"
				if first.Assessment.Status == "ERROR" || second.Assessment.Status == "ERROR" {
					outcome = "error"
				} else if first.Assessment.Status == "SKIPPED" || second.Assessment.Status == "SKIPPED" {
					outcome = "skipped"
				}
				in.Units[0].Outcome = outcome
				assembled, err := Assemble(in)
				if err != nil {
					t.Fatalf("Assemble(%s, %s): %v", statuses[pair[0]], statuses[pair[1]], err)
				}
				if len(assembled.Results) != 1 || assembled.Results[0].Assessment.Status != statuses[higher] {
					t.Fatalf("merged status for %s and %s = %+v", statuses[pair[0]], statuses[pair[1]], assembled.Results)
				}
			}
		}
	}
}

func TestMergeResultsCapsMembersAndEvidence(t *testing.T) {
	in := sampleInput(t)
	in.Results = nil
	for i := 0; i < 25; i++ {
		result := sampleInput(t).Results[0]
		result.Resource.Name = fmt.Sprintf("pod-%02d", i)
		result.Resource.Key = "controller/deployment"
		result.Evidence = []Evidence{{Expr: "item", Value: i, CollectorKey: ""}, {Expr: "item", Value: i + 100, CollectorKey: ""}, {Expr: "item", Value: i + 200, CollectorKey: ""}}
		in.Results = append(in.Results, result)
	}
	assembled, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(assembled.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(assembled.Results))
	}
	merged := assembled.Results[0]
	if merged.Resource.Members != 20 {
		t.Fatalf("members = %d, want 20", merged.Resource.Members)
	}
	if len(merged.Evidence) != 50 {
		t.Fatalf("evidence = %d, want 50", len(merged.Evidence))
	}
	encoded, err := json.Marshal(assembled)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateJSON("report", encoded); err != nil {
		t.Fatalf("merged report does not match schema: %v", err)
	}
}

func TestMergeResultsPreservesCollectorReferences(t *testing.T) {
	in := sampleInput(t)
	second := in.Results[0]
	second.Resource.Name = "pod-b"
	second.Resource.Key = "controller/deployment"
	second.CollectorKeys = []string{"collector-b"}
	second.Evidence = []Evidence{{Expr: "check", Value: true, CollectorKey: "collector-b"}}
	first := in.Results[0]
	first.Resource.Name = "pod-a"
	first.Resource.Key = "controller/deployment"
	first.CollectorKeys = []string{"collector-a"}
	first.Evidence = []Evidence{{Expr: "check", Value: true, CollectorKey: "collector-a"}}
	in.Results = []Result{second, first}
	in.Collectors = []Collector{
		{Key: "collector-a", ScopeKey: "projects/example-prod", Type: "kubectl", Command: "kubectl get pods"},
		{Key: "collector-b", ScopeKey: "projects/example-prod", Type: "kubectl", Command: "kubectl get replicasets"},
	}
	assembled, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	merged := assembled.Results[0]
	if got := strings.Join(merged.Collection.CollectorIDs, ","); got != "collect-1,collect-2" {
		t.Fatalf("collector IDs = %q", got)
	}
	if len(merged.Evidence) != 2 || merged.Evidence[0].CollectorID != "collect-1" || merged.Evidence[1].CollectorID != "collect-2" {
		t.Fatalf("evidence collector IDs = %+v", merged.Evidence)
	}
}

func TestMergeResultsRejectsCrossTargetGrouping(t *testing.T) {
	in := sampleInput(t)
	second := in.Results[0]
	second.Target.Key = "projects/other-prod"
	second.Target.ProjectID = "other-prod"
	second.Resource.Key = in.Results[0].Resource.Key
	in.Results = append(in.Results, second)
	in.Units = append(in.Units, UnitRef{RuleID: second.Rule.ID, TargetKey: second.Target.Key, Outcome: "evaluated"})
	assembled, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(assembled.Results) != 2 {
		t.Fatalf("results = %d, want separate target results", len(assembled.Results))
	}
	if assembled.Results[0].Target.Key == assembled.Results[1].Target.Key {
		t.Fatalf("targets were combined: %+v", assembled.Results)
	}
}

func TestFindingKeyStableAcrossResourceReplacement(t *testing.T) {
	targetKey := "projects/example-prod/locations/us-central1/clusters/c1"
	first := ResourceRef{Kind: "Pod", Name: "web-7d6f9", Key: "namespace/default/deployment/web"}
	second := ResourceRef{Kind: "Pod", Name: "web-86b94", Key: "namespace/default/deployment/web"}
	firstFinding := FindingKey("cis-gke-4.1.5", targetKey, first.Key)
	secondFinding := FindingKey("cis-gke-4.1.5", targetKey, second.Key)
	if first.Name == second.Name || firstFinding != secondFinding {
		t.Fatalf("finding key changed across resource replacement: %q != %q", firstFinding, secondFinding)
	}
}
