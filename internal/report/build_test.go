package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/schemas"
)

func sampleInput(t *testing.T) Input {
	t.Helper()
	r := &rule.Rule{ID: "cis-gcp-1.1", Ref: "1.1", Title: "sample", Profile: "L1", Severity: "high", Mode: "deterministic", CISAssessment: "automated", Hash: "sha256:" + strings.Repeat("a", 64), Params: map[string]any{"limit": 3}}
	return Input{
		Scan:  Scan{ID: "scan-20261116T000000Z-a1", StartedAt: "2026-11-16T00:00:00Z", FinishedAt: "2026-11-16T00:01:00Z", Tool: Tool{Name: "gbench", Version: "1.0", RulesetHash: "sha256:" + strings.Repeat("b", 64), RulesetSource: "embedded"}, Environment: Environment{GcloudVersion: "1", OS: "linux", Arch: "amd64"}, Identity: Identity{Account: "scanner@example.com"}, Selection: Selection{ProfileHash: "sha256:" + strings.Repeat("c", 64), Benchmarks: []string{"cis-gcp@1"}, Levels: []string{"L1"}}, Targets: []ScanTarget{{Type: "project", ID: "example-prod", Clusters: ClusterInventory{Status: "SUCCEEDED"}}}},
		Rules: []*rule.Rule{r}, Units: []UnitRef{{RuleID: r.ID, TargetKey: "projects/example-prod", Outcome: "evaluated"}},
		Results: []Result{{Rule: RuleRef{ID: r.ID, Ref: r.Ref, Title: r.Title, Profile: r.Profile, Severity: r.Severity, Mode: r.Mode}, Target: TargetRef{Type: "project", Key: "projects/example-prod", ProjectID: "example-prod"}, Resource: ResourceRef{Kind: "cloudresourcemanager.googleapis.com/Project", Name: "example-prod", Key: "projects/example-prod"}, Collection: Collection{Status: "SUCCEEDED"}, Assessment: Assessment{Status: "PASS", Message: "ok"}}},
	}
}

func TestAssemble_DeterministicOutput(t *testing.T) {
	in := sampleInput(t)
	second := in.Results[0]
	second.Resource.Key += "/secondary"
	in.Results = append(in.Results, second)
	a, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	shuffled := sampleInput(t)
	shuffled.Results = append(shuffled.Results, second)
	shuffled.Results[0], shuffled.Results[1] = shuffled.Results[1], shuffled.Results[0]
	b, err := Assemble(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		t.Fatal("output depends on input order")
	}
	if err := schemas.ValidateJSON("report", ja); err != nil {
		t.Fatal(err)
	}
}

func TestFindingKey_StableAndDistinct(t *testing.T) {
	a := FindingKey("r", "t", "x")
	if a != FindingKey("r", "t", "x") || a == FindingKey("r", "t", "y") || !strings.HasPrefix(a, "fk1:") {
		t.Fatalf("unexpected finding keys: %q", a)
	}
}

func TestAssemble_MissingResultForUnitIsError(t *testing.T) {
	in := sampleInput(t)
	in.Results = nil
	if _, err := Assemble(in); err == nil {
		t.Fatal("expected missing result error")
	}
}

func TestAssemble_RejectsUnitOutcomeThatDoesNotMatchWorstResult(t *testing.T) {
	in := sampleInput(t)
	in.Results[0].Assessment.Status = "ERROR"
	in.Results[0].Collection.Status = "FAILED"
	if _, err := Assemble(in); err == nil {
		t.Fatal("expected unit outcome mismatch error")
	}
}

func TestAssemble_RejectsDuplicateUnitPair(t *testing.T) {
	in := sampleInput(t)
	in.Units = append(in.Units, in.Units[0])
	if _, err := Assemble(in); err == nil {
		t.Fatal("expected duplicate unit error")
	}
}

func TestAssemble_RejectsResultWithoutUnit(t *testing.T) {
	in := sampleInput(t)
	orphan := in.Results[0]
	orphan.Target.Key = "projects/other"
	in.Results = append(in.Results, orphan)
	if _, err := Assemble(in); err == nil {
		t.Fatal("expected orphan result error")
	}
}

func TestAssemble_UsesWorstResultOutcomeForUnit(t *testing.T) {
	in := sampleInput(t)
	in.Results[0].Assessment.Status = "PASS"
	second := in.Results[0]
	second.Resource.Key += "/secondary"
	second.Assessment.Status = "SKIPPED"
	second.Collection.Status = "FAILED"
	in.Results = append(in.Results, second)
	in.Units[0].Outcome = "skipped"
	assembled, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	if assembled.Scan.Coverage != (Coverage{Units: 1, Skipped: 1}) || assembled.Scan.Status != "completed_with_gaps" {
		t.Fatalf("coverage/status = %+v/%q, want skipped gap", assembled.Scan.Coverage, assembled.Scan.Status)
	}
}

func TestAssemble_CoverageAndStatusDerivedFromUnits(t *testing.T) {
	in := sampleInput(t)
	in.Scan.Status = "completed_with_gaps"
	in.Scan.Coverage = Coverage{Units: 99, Error: 99}
	r := in.Results[0]
	r.Assessment.Status = "SKIPPED"
	r.Collection.Status = "FAILED"
	in.Results[0] = r
	in.Units[0].Outcome = "skipped"
	out, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan.Status != "completed_with_gaps" || out.Scan.Coverage != (Coverage{Units: 1, Skipped: 1}) {
		t.Fatalf("derived status/coverage = %q %+v", out.Scan.Status, out.Scan.Coverage)
	}
}

func TestAssemble_CollectorIDsSortedAndStable(t *testing.T) {
	in := sampleInput(t)
	in.Collectors = []Collector{{Key: "z", ScopeKey: "projects/example-prod", Type: "gcloud", Command: "gcloud z"}, {Key: "a", ScopeKey: "projects/example-prod", Type: "gcloud", Command: "gcloud a"}}
	in.Results[0].CollectorKeys = []string{"z", "a"}
	first, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Collectors[0], in.Collectors[1] = in.Collectors[1], in.Collectors[0]
	second, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) || first.Collectors[0].Key != second.Collectors[0].Key || first.Collectors[0].ID != "collect-1" || first.Results[0].Collection.CollectorIDs[0] != "collect-1" {
		t.Fatalf("unstable collectors: %+v / %+v", first.Collectors, second.Collectors)
	}
}

func TestAssemble_CollectorKeysAreScopedToResultTarget(t *testing.T) {
	in := sampleInput(t)
	second := in.Results[0]
	second.Target.Key = "projects/other-prod"
	second.Target.ProjectID = "other-prod"
	second.Resource.Key = "projects/other-prod"
	in.Results = append(in.Results, second)
	in.Units = append(in.Units, UnitRef{RuleID: second.Rule.ID, TargetKey: second.Target.Key, Outcome: "evaluated"})
	in.Collectors = []Collector{
		{Key: "shared-command", ScopeKey: "projects/example-prod", Type: "gcloud", Command: "gcloud projects describe"},
		{Key: "shared-command", ScopeKey: "projects/other-prod", Type: "gcloud", Command: "gcloud projects describe"},
	}
	for i := range in.Results {
		in.Results[i].CollectorKeys = []string{"shared-command"}
	}
	assembled, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	if got := assembled.Results[0].Collection.CollectorIDs; len(got) != 1 || got[0] != "collect-1" {
		t.Fatalf("first target collector IDs = %v", got)
	}
	if got := assembled.Results[1].Collection.CollectorIDs; len(got) != 1 || got[0] != "collect-2" {
		t.Fatalf("second target collector IDs = %v", got)
	}
}

func TestAssemble_RejectsDuplicateCollectorKeyAndScope(t *testing.T) {
	in := sampleInput(t)
	in.Collectors = []Collector{
		{Key: "same", ScopeKey: "projects/example-prod", Type: "gcloud", Command: "gcloud one"},
		{Key: "same", ScopeKey: "projects/example-prod", Type: "gcloud", Command: "gcloud two"},
	}
	if _, err := Assemble(in); err == nil {
		t.Fatal("expected duplicate scoped collector key error")
	}
}

func TestAssemble_RejectsUnknownCollectorScope(t *testing.T) {
	in := sampleInput(t)
	in.Collectors = []Collector{{Key: "key", ScopeKey: "projects/other-prod", Type: "gcloud", Command: "gcloud x"}}
	in.Results[0].CollectorKeys = []string{"key"}
	if _, err := Assemble(in); err == nil {
		t.Fatal("expected unknown scoped collector key error")
	}
}

func TestAssemble_DiscardsPrepopulatedCollectorReferences(t *testing.T) {
	in := sampleInput(t)
	in.Results[0].Collection.CollectorIDs = []string{"collect-999"}
	in.Results[0].Evidence = []Evidence{{Expr: "r", Value: true, CollectorID: "collect-999"}}
	assembled, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	if got := assembled.Results[0].Collection.CollectorIDs; len(got) != 0 {
		t.Fatalf("unverified collection IDs survived: %v", got)
	}
	if got := assembled.Results[0].Evidence[0].CollectorID; got != "" {
		t.Fatalf("unverified evidence collector ID survived: %q", got)
	}
}

func TestAssemble_SummaryCountsMatchResults(t *testing.T) {
	in := sampleInput(t)
	in.Results = append(in.Results, in.Results[0])
	in.Results[1].Resource.Key = "projects/example-prod/other"
	in.Results[1].Assessment.Status = "FAIL"
	out, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Summary.ResultsTotal != 2 || out.Summary.StatusCounts["PASS"] != 1 || out.Summary.StatusCounts["FAIL"] != 1 {
		t.Fatalf("unexpected summary: %+v", out.Summary)
	}
	if len(out.RuleSummaries) != 1 || out.RuleSummaries[0].Status != "MIXED" || out.RuleSummaries[0].StatusCounts["PASS"] != 1 {
		t.Fatalf("unexpected rule summary: %+v", out.RuleSummaries)
	}
}

func TestAssemble_NilSlicesSerializeAsEmptyArrays(t *testing.T) {
	in := sampleInput(t)
	in.Scan.Selection.Benchmarks, in.Scan.Selection.Levels, in.Scan.Selection.Capabilities = nil, nil, nil
	in.Scan.Targets[0].Clusters.Names = nil
	in.Scan.Targets[0].Clusters.Unreachable = nil
	in.Results[0].Evidence = nil
	out, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"benchmarks":null`) || strings.Contains(string(b), `"levels":null`) || strings.Contains(string(b), `"capabilities":null`) || strings.Contains(string(b), `"names":null`) || strings.Contains(string(b), `"unreachable":null`) || strings.Contains(string(b), `"evidence":null`) || strings.Contains(string(b), `"collector_ids":null`) {
		t.Fatalf("nil array serialized as null: %s", b)
	}
	if err := schemas.ValidateJSON("report", b); err != nil {
		t.Fatal(err)
	}
}

func TestAssemble_RedactsSecretsInFreeTextFields(t *testing.T) {
	in := sampleInput(t)
	errorText := "AIzaSecret"
	in.Collectors = []Collector{{Key: "k", ScopeKey: "projects/example-prod", Type: "gcloud", Command: "gcloud ya29.secret", Error: &errorText}}
	in.Results[0].CollectorKeys = []string{"k"}
	in.Results[0].Assessment.Message = "Bearer token-value"
	in.Results[0].Evidence = []Evidence{{Expr: "r", Value: "AIzaKey", CollectorKey: "k"}}
	out, err := Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	for _, secret := range []string{"ya29.secret", "AIzaSecret", "token-value", "AIzaKey"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatalf("secret %q leaked in %s", secret, b)
		}
	}
}

func TestAssemble_FailCannotHaveFailedCollection(t *testing.T) {
	in := sampleInput(t)
	in.Results[0].Assessment.Status = "FAIL"
	in.Results[0].Collection.Status = "FAILED"
	_, err := Assemble(in)
	if err == nil {
		t.Fatal("expected invalid FAIL/FAILED invariant error")
	}
}
