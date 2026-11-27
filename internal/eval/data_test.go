package eval_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SummerQXY/gbencher/internal/eval"
	"github.com/SummerQXY/gbencher/internal/rule"
)

func TestOriginalObjects_RejectsConstructedMaps(t *testing.T) {
	d := eval.NewData()
	d.Set("a", []any{map[string]any{"n": 1}})
	if err := eval.OriginalObjects(d, []any{map[string]any{"n": 1}}); err == nil {
		t.Fatal("a copy must be rejected")
	}
}

func TestOriginalObjects_AcceptsFilteredFlattenedAndConcatenatedElements(t *testing.T) {
	d := eval.NewData()
	d.Set("a", []any{map[string]any{"n": 1}, map[string]any{"n": 2}})
	d.Set("b", []any{map[string]any{"n": 3}})
	d.Set("nested", []any{[]any{map[string]any{"n": 4}}})
	e, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	for _, expr := range []string{"data.a.filter(x, x.n > 1)", "data.nested.flatten()", "data.a + data.b"} {
		got, err := e.List(context.Background(), expr, d, eval.Context{}, nil)
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		if err := eval.OriginalObjects(d, got); err != nil {
			t.Errorf("%s: %v", expr, err)
		}
	}
}

func TestData_FailureFollowsElementThroughFilter(t *testing.T) {
	d := eval.NewData()
	elem := map[string]any{"n": 1}
	d.Set("a", []any{elem})
	d.Fail(elem, "collect", "ERROR", "failed", nil)
	e, _ := eval.NewEnv()
	got, err := e.List(context.Background(), "data.a.filter(x, x.n == 1)", d, eval.Context{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if failures := d.Failures(got[0]); len(failures) != 1 || failures[0].Step != "collect" {
		t.Fatalf("got %#v", failures)
	}
}

func TestData_NonMapElementFailureIsUnattributed(t *testing.T) {
	d := eval.NewData()
	d.Fail("item", "collect", "ERROR", "failed", nil)
	if got := d.Failures("item"); len(got) != 0 {
		t.Fatalf("element failures: %#v", got)
	}
	if got := d.Unattributed(nil); len(got) != 1 || got[0].Step != "collect" {
		t.Fatalf("unattributed failures: %#v", got)
	}
}

func TestData_UnattributedExcludesKnownElements(t *testing.T) {
	d := eval.NewData()
	elem := map[string]any{"n": 1}
	d.Set("a", []any{elem})
	d.Fail(elem, "collect", "ERROR", "failed", nil)
	if got := d.Unattributed([]any{elem}); len(got) != 0 {
		t.Fatalf("got %#v", got)
	}
}

func TestData_AttachMutatesOriginalElementAndFailuresAreSorted(t *testing.T) {
	d := eval.NewData()
	elem := map[string]any{"n": 1}
	d.Set("a", []any{elem})
	d.Attach(elem, "attached", "value")
	if elem["attached"] != "value" {
		t.Fatalf("element was not mutated: %#v", elem)
	}
	d.Fail(elem, "z-step", "ERROR", "z", nil)
	d.Fail(elem, "a-step", "ERROR", "a", nil)
	got := d.Failures(elem)
	if len(got) != 2 || got[0].Step != "a-step" || got[1].Step != "z-step" {
		t.Fatalf("failures were not sorted: %#v", got)
	}
}

func TestData_OperationsAreSafeForConcurrentCallers(t *testing.T) {
	d := eval.NewData()
	elem := map[string]any{}
	d.Set("shared", []any{elem})
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			step := fmt.Sprintf("step-%02d", i)
			d.Set(step, i)
			d.Get(step)
			d.Attach(elem, step, i)
			d.Fail(elem, step, "ERROR", "reason", nil)
			d.Failures(elem)
		}(i)
	}
	wg.Wait()
	if got := len(d.Failures(elem)); got != 12 {
		t.Fatalf("got %d failures", got)
	}
}

func TestData_AttachAndEvaluationAreRaceSafe(t *testing.T) {
	d := eval.NewData()
	elem := map[string]any{"n": 1}
	d.Set("a", []any{elem})
	e, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			d.Attach(elem, "n", i%2)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			if _, err := e.Bool(context.Background(), "data.a[0].n >= 0", d, nil, eval.Context{}, nil); err != nil {
				t.Errorf("evaluation failed: %v", err)
			}
		}
	}()
	wg.Wait()
}

func TestEnv_ListRespectsContextDeadline(t *testing.T) {
	e, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	d := eval.NewData()
	d.Set("a", []any{1, 2, 3})
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := e.List(ctx, "data.a.map(x, x)", d, eval.Context{}, nil); err == nil {
		t.Fatal("expected deadline error")
	}
}

func TestEnv_CostLimitStopsRunawayExpression(t *testing.T) {
	e, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	d := eval.NewData()
	d.Set("a", strings.Repeat("b", 50_000))
	params := map[string]any{"pattern": strings.Repeat("a", 1_000)}
	if _, err := e.Bool(context.Background(), "data.a.matches(params.pattern)", d, nil, eval.Context{}, params); err == nil || !strings.Contains(strings.ToLower(err.Error()), "cost") {
		t.Fatalf("expected CEL cost limit error, got %v", err)
	}
}

func TestEnv_CostObserverReceivesActualCost(t *testing.T) {
	e, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	d := eval.NewData()
	var observed uint64
	e.SetCostObserver(func(_ string, cost uint64) { observed = cost })
	if _, err := e.Bool(context.Background(), "1 + 2 == 3", d, nil, eval.Context{}, nil); err != nil {
		t.Fatal(err)
	}
	if observed == 0 {
		t.Fatalf("observer got cost %d", observed)
	}
}

func TestEnv_CostObserverCanWriteData(t *testing.T) {
	e, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	d := eval.NewData()
	e.SetCostObserver(func(_ string, _ uint64) { d.Set("observer", true) })
	done := make(chan error, 1)
	go func() {
		_, err := e.Bool(context.Background(), "1 + 2 == 3", d, nil, eval.Context{}, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cost observer deadlocked while writing data")
	}
	if value, ok := d.Get("observer"); !ok || value != true {
		t.Fatalf("observer did not write data: %v, %v", value, ok)
	}
}

func TestEnv_ListRespectsCancellationDuringMaterialization(t *testing.T) {
	e, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	items := make([]any, 5_000_000)
	for i := range items {
		items[i] = i
	}
	d := eval.NewData()
	d.Set("a", items)
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(100*time.Millisecond, cancel)
	defer func() {
		timer.Stop()
		cancel()
	}()
	if _, err := e.List(ctx, "data.a", d, eval.Context{}, nil); err == nil {
		t.Fatal("expected cancellation while materializing the result")
	}
}

func TestCompileAll_ReportsRuleAndExpression(t *testing.T) {
	e, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	r := &rule.Rule{ID: "cis-gcp-1.1", Resource: &rule.Resource{From: "data.items", Filter: "data.items", Name: "r.missing("}}
	err = e.CompileAll(r)
	if err == nil || !strings.Contains(err.Error(), r.ID) || !strings.Contains(err.Error(), "resource.name") {
		t.Fatalf("got %v", err)
	}
}

func TestCompileAll_RejectsResourceFromWithoutResourceVariable(t *testing.T) {
	e, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	r := &rule.Rule{ID: "example-rule", Resource: &rule.Resource{From: "r.x"}, Check: rule.Check{Assert: "true"}}
	err = e.CompileAll(r)
	if err == nil || !strings.Contains(err.Error(), r.ID) || !strings.Contains(err.Error(), "resource.from") {
		t.Fatalf("got %v", err)
	}
	if _, err := e.List(context.Background(), r.Resource.From, eval.NewData(), eval.Context{}, nil); err == nil {
		t.Fatal("resource.from must fail in the list environment when it refers to r")
	}
}

func TestCompileAll_RejectsResourceVariableInAggregateExpressions(t *testing.T) {
	e, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	r := &rule.Rule{ID: "example-aggregate", Check: rule.Check{Assert: "r.x == 1"}}
	err = e.CompileAll(r)
	if err == nil || !strings.Contains(err.Error(), r.ID) || !strings.Contains(err.Error(), "check.assert") {
		t.Fatalf("got %v", err)
	}
	if _, err := e.Bool(context.Background(), r.Check.Assert, eval.NewData(), nil, eval.Context{}, nil); err == nil {
		t.Fatal("aggregate assert must fail in the environment without r")
	}
}

func TestCompileAll_UsesResourceVariableOnlyAtResourceLocations(t *testing.T) {
	e, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	r := &rule.Rule{
		ID:       "example-resource",
		Collect:  []rule.Step{{Foreach: "r.items"}},
		Resource: &rule.Resource{From: "data.items", Filter: "r.enabled", Name: "r.name", Key: "r.key"},
		Check:    rule.Check{Assert: "r.valid", ReviewWhen: "r.review"},
		Evidence: []string{"r.value"},
	}
	if err := e.CompileAll(r); err == nil || !strings.Contains(err.Error(), "collect[0].foreach") {
		t.Fatalf("foreach must compile without r: %v", err)
	}
	r.Collect = nil
	if err := e.CompileAll(r); err != nil {
		t.Fatalf("resource expressions should compile with r: %v", err)
	}
}

func TestCompileAll_CompilesEvidenceWithoutResourceVariableForAggregate(t *testing.T) {
	e, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	r := &rule.Rule{ID: "example-aggregate", Evidence: []string{"r.value"}}
	if err := e.CompileAll(r); err == nil || !strings.Contains(err.Error(), "evidence[0]") {
		t.Fatalf("aggregate evidence must compile without r: %v", err)
	}
}
