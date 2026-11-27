package eval_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/eval"
	"github.com/SummerQXY/gbencher/internal/failure"
	"github.com/SummerQXY/gbencher/internal/rule"
)

func TestAssess_ReviewOnlyWhenAssertTrue(t *testing.T) {
	r := &rule.Rule{Check: rule.Check{Assert: "false", ReviewWhen: "true", Message: "failed"}}
	inst := &eval.ResourceInstance{Elem: map[string]any{}}
	got, _, err := eval.Assess(context.Background(), mustEnv(t), r, inst, eval.NewData(), ctxOf(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "FAIL" || got.Message != "failed" {
		t.Fatalf("assessment = %#v", got)
	}
}

func TestAssess_UsesOriginalResourceFields(t *testing.T) {
	r := &rule.Rule{
		Resource: &rule.Resource{From: "data.networks", Name: "r.name", Kind: "compute.googleapis.com/Network"},
		Check:    rule.Check{Assert: `r.name != "default"`, Message: "network {{ .r.name }} failed"},
	}
	d := eval.NewData()
	d.Set("networks", []any{map[string]any{"name": "default"}})
	c := ctxOf(t)
	expanded, err := eval.ExpandResources(context.Background(), mustEnv(t), r, d, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	inst := expanded.Instances[0]
	if got, want := inst.Name, "projects/example-prod/default"; got != want {
		t.Fatalf("normalized name = %q, want %q", got, want)
	}
	got, _, err := eval.Assess(context.Background(), mustEnv(t), r, &inst, d, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "FAIL" || got.Message != "network default failed" {
		t.Fatalf("assessment = %#v, want FAIL using original resource name", got)
	}
}

func TestAssess_FailedElementProducesSkippedOrErrorWithoutEvaluation(t *testing.T) {
	for _, status := range []string{"SKIPPED", "ERROR"} {
		t.Run(status, func(t *testing.T) {
			d := eval.NewData()
			elem := map[string]any{"name": "one"}
			d.Fail(elem, "step", status, "collection failed", nil)
			r := &rule.Rule{Check: rule.Check{Assert: "this is invalid CEL", Message: "unused"}}
			got, _, err := eval.Assess(context.Background(), mustEnv(t), r, &eval.ResourceInstance{Elem: elem}, d, ctxOf(t), nil)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != status || !strings.Contains(got.Message, "collection failed") {
				t.Fatalf("assessment = %#v", got)
			}
		})
	}
	d := eval.NewData()
	elem := map[string]any{"name": "one"}
	d.Fail(elem, "a", "SKIPPED", "skip reason", nil)
	d.Fail(elem, "b", "ERROR", "error reason", nil)
	got, _, err := eval.Assess(context.Background(), mustEnv(t), &rule.Rule{Check: rule.Check{Assert: "invalid"}}, &eval.ResourceInstance{Elem: elem}, d, ctxOf(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "ERROR" {
		t.Fatalf("status = %q, want ERROR", got.Status)
	}
}

func TestAssess_EvidenceTruncatesAt4KiBAnd50Items(t *testing.T) {
	items := make([]string, 51)
	for i := range items {
		items[i] = `"x"`
	}
	items[0] = `"` + strings.Repeat("x", 5000) + `"`
	r := &rule.Rule{Check: rule.Check{Assert: "true"}, Evidence: items}
	got, ev, err := eval.Assess(context.Background(), mustEnv(t), r, &eval.ResourceInstance{Elem: map[string]any{}}, eval.NewData(), ctxOf(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "PASS" || len(ev) != 50 || !ev[0].Truncated {
		t.Fatalf("assessment=%#v evidence length=%d first=%#v", got, len(ev), ev[0])
	}
	serialized, err := json.Marshal(ev[0].Value)
	if err != nil || len(serialized) > 4*1024 {
		t.Fatalf("truncated evidence serializes to %d bytes, err=%v", len(serialized), err)
	}
}

func TestAssess_MessageRenderErrorKeepsStatus(t *testing.T) {
	r := &rule.Rule{Check: rule.Check{Assert: "false", Message: "{{ .r.missing.value }}"}}
	got, _, err := eval.Assess(context.Background(), mustEnv(t), r, &eval.ResourceInstance{Elem: map[string]any{}}, eval.NewData(), ctxOf(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "FAIL" || !strings.Contains(got.Message, "message render error") {
		t.Fatalf("assessment = %#v", got)
	}
}

func TestAssess_AggregateRuleWithFailedForeachItemIsSkippedNotEvaluated(t *testing.T) {
	d := eval.NewData()
	d.Fail(map[string]any{"id": "one"}, "foreach", "SKIPPED", "one item failed", nil)
	r := &rule.Rule{Check: rule.Check{Assert: "invalid"}}
	got, _, err := eval.Assess(context.Background(), mustEnv(t), r, &eval.ResourceInstance{}, d, ctxOf(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "SKIPPED" || !strings.Contains(got.Message, "one item failed") {
		t.Fatalf("assessment = %#v", got)
	}
}

func TestPartialData_UnattributedFailureYieldsAggregateResult(t *testing.T) {
	d := eval.NewData()
	d.Fail(nil, "step", "ERROR", "aggregate failed", &failure.Failure{})
	got, ok := eval.PartialData(d, []eval.ResourceInstance{{Elem: map[string]any{"name": "known"}}})
	if !ok || got.Status != "ERROR" || !strings.Contains(got.Message, "partial data") {
		t.Fatalf("assessment=%#v ok=%v", got, ok)
	}
	d2 := eval.NewData()
	if _, ok := eval.PartialData(d2, nil); ok {
		t.Fatal("expected no partial result without failures")
	}
}

func mustEnv(t *testing.T) *eval.Env {
	t.Helper()
	e, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func ctxOf(t *testing.T) eval.Context {
	t.Helper()
	return eval.Context{Project: "example-prod", TargetKind: "project", TargetKey: "projects/example-prod"}
}
