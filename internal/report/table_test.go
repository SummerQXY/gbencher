package report

import (
	"bytes"
	"strings"
	"testing"
)

func sampleTableReport(statuses ...string) *Report {
	results := make([]Result, 0, len(statuses))
	for i, status := range statuses {
		results = append(results, Result{
			Rule:   RuleRef{ID: "cis-gcp-1.1", Ref: "1.1", Title: "sample", Severity: "high"},
			Target: TargetRef{Type: "project", Key: "projects/example-prod"},
			Resource: ResourceRef{
				Kind: "cloudresourcemanager.googleapis.com/Project",
				Name: "example-prod",
				Key:  "projects/example-prod/" + string(rune('a'+i)),
			},
			Assessment: Assessment{Status: status, Message: "message"},
		})
	}
	counts := make(map[string]int)
	for _, result := range results {
		counts[result.Assessment.Status]++
	}
	return &Report{
		Scan:    Scan{Status: "completed", Coverage: Coverage{Units: len(results), Evaluated: len(results)}},
		Summary: Summary{ResultsTotal: len(results), StatusCounts: counts},
		Results: results,
	}
}

func TestWriteTable_DefaultHidesPassAndShowsCoverage(t *testing.T) {
	var out bytes.Buffer
	if err := sampleTableReport("PASS", "FAIL").WriteTable(TableOptions{Out: &out}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "FAIL") || strings.Contains(s, "  PASS  ") || !strings.Contains(s, "coverage") {
		t.Fatalf("unexpected table output:\n%s", s)
	}
}

func TestWriteTable_ShowPassAndTruncatesMessage(t *testing.T) {
	r := sampleTableReport("PASS")
	r.Results[0].Assessment.Message = "这是一个很长的消息"
	var out bytes.Buffer
	if err := r.WriteTable(TableOptions{ShowPass: true, MaxMessage: 5, Out: &out}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "PASS") || !strings.Contains(s, "cis-gcp-1.1") {
		t.Fatalf("PASS result missing from output:\n%s", s)
	}
	if !strings.Contains(s, "这是一个…") || strings.Contains(s, "这是一个很长") {
		t.Fatalf("message was not truncated by characters:\n%s", s)
	}
}

func TestWriteTable_StripsEscapeSequencesFromResourceNames(t *testing.T) {
	r := sampleTableReport("FAIL")
	r.Results[0].Resource.Name = "\x1b[31mexample-prod\x1b[0m"
	var out bytes.Buffer
	if err := r.WriteTable(TableOptions{Out: &out}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), "example-prod") {
		t.Fatalf("resource name was not safely rendered:\n%q", out.String())
	}
}

func TestWriteTable_FoldsLineBreaksAndTabs(t *testing.T) {
	r := sampleTableReport("FAIL")
	r.Results[0].Resource.Name = "resource\nPASS\thigh\tforged-rule\tother"
	r.Results[0].Assessment.Message = "message\u2028PASS\u2029forged-message"
	var out bytes.Buffer
	if err := r.WriteTable(TableOptions{Out: &out}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if strings.Count(s, "forged-rule") != 1 || strings.Count(s, "forged-message") != 1 {
		t.Fatalf("unexpected table output:\n%s", s)
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "forged-rule") && !strings.HasPrefix(line, "FAIL ") {
			t.Fatalf("resource text created an extra table row:\n%s", s)
		}
		if strings.Contains(line, "forged-message") && !strings.HasPrefix(line, "FAIL ") {
			t.Fatalf("message text created an extra table row:\n%s", s)
		}
	}
}

func TestWriteTable_SummaryStatusOrderIsDeterministic(t *testing.T) {
	r := sampleTableReport("FAIL", "PASS", "ERROR", "SKIPPED", "NOT_APPLICABLE")
	var first, second bytes.Buffer
	if err := r.WriteTable(TableOptions{ShowPass: true, Out: &first}); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteTable(TableOptions{ShowPass: true, Out: &second}); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("table output changed between writes:\n%s\n%s", first.String(), second.String())
	}
}
