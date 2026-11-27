package engine

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/eval"
	"github.com/SummerQXY/gbencher/internal/failure"
	"github.com/SummerQXY/gbencher/internal/plan"
	"github.com/SummerQXY/gbencher/internal/rule"
)

type executorRunner struct {
	calls   atomic.Int32
	start   chan struct{}
	release chan struct{}
	out     collect.Output
}

func (r *executorRunner) Run(ctx context.Context, _ collect.Exec, _ collect.Limits) (collect.Output, error) {
	r.calls.Add(1)
	if r.start != nil {
		r.start <- struct{}{}
		select {
		case <-r.release:
		case <-ctx.Done():
			return collect.Output{}, ctx.Err()
		}
	}
	return r.out, nil
}

func TestExecutor_ConcurrentIdenticalFailingCommandRunsOnceAndSharesFailure(t *testing.T) {
	runner := &executorRunner{start: make(chan struct{}, 1), release: make(chan struct{}), out: collect.Output{ExitCode: 1, Stderr: []byte("denied")}}
	allow := &rule.Allowlist{Gcloud: []rule.GcloudEntry{{Path: []string{"compute", "instances", "list"}, Bind: []rule.Bind{rule.BindProject}}}, GcloudFlags: []string{"--project", "--format"}}
	e := newExecutor(context.Background(), nil, runner, "gcloud", nil, plan.Guard{Allow: allow}, "projects/example-prod", rule.Step{}, 0)
	e.useTarget(plan.Target{Type: "project", Key: "projects/example-prod", ProjectID: "example-prod"})
	const callers = 32
	var wg sync.WaitGroup
	got := make(chan *failure.Failure, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, f := e.execute(context.Background(), rule.Step{ID: "x", Gcloud: "compute instances list --project=example-prod --format=json"}, nil)
			got <- f
		}()
	}
	<-runner.start
	close(runner.release)
	wg.Wait()
	close(got)
	if runner.calls.Load() != 1 {
		t.Fatalf("calls=%d", runner.calls.Load())
	}
	var first *failure.Failure
	for f := range got {
		if f == nil {
			t.Fatal("expected failure")
		}
		if first == nil {
			first = f
		} else if f != first {
			t.Fatal("callers did not receive the shared failure")
		}
	}
}

func TestExecutor_NonJSONStdoutIsParseErrorNotEmpty(t *testing.T) {
	runner := &executorRunner{out: collect.Output{Stdout: []byte("WARNING: update available\n[]")}}
	allow := &rule.Allowlist{Gcloud: []rule.GcloudEntry{{Path: []string{"compute", "instances", "list"}, Bind: []rule.Bind{rule.BindProject}}}, GcloudFlags: []string{"--project", "--format"}}
	e := newExecutor(context.Background(), nil, runner, "gcloud", nil, plan.Guard{Allow: allow}, "projects/example-prod", rule.Step{}, 0)
	e.useTarget(plan.Target{Type: "project", Key: "projects/example-prod", ProjectID: "example-prod"})
	value, f := e.execute(context.Background(), rule.Step{ID: "x", Parse: "json", Gcloud: "compute instances list --project=example-prod --format=json"}, nil)
	if f == nil || f.Class != failure.Parse {
		t.Fatalf("failure=%v", f)
	}
	if value != nil {
		t.Fatalf("unexpected value %#v", value)
	}
}

func TestExecutor_LeadingBOMJSONParses(t *testing.T) {
	runner := &executorRunner{out: collect.Output{Stdout: []byte("\xef\xbb\xbf[]")}}
	allow := &rule.Allowlist{Gcloud: []rule.GcloudEntry{{Path: []string{"compute", "instances", "list"}, Bind: []rule.Bind{rule.BindProject}}}, GcloudFlags: []string{"--project", "--format"}}
	e := newExecutor(context.Background(), nil, runner, "gcloud", nil, plan.Guard{Allow: allow}, "projects/example-prod", rule.Step{}, 0)
	e.useTarget(plan.Target{Type: "project", Key: "projects/example-prod", ProjectID: "example-prod"})
	value, f := e.execute(context.Background(), rule.Step{ID: "x", Parse: "json", Gcloud: "compute instances list --project=example-prod --format=json"}, nil)
	if f != nil {
		t.Fatalf("failure=%v", f)
	}
	if got, ok := value.([]any); !ok || len(got) != 0 {
		t.Fatalf("value=%#v", value)
	}
}

type sharedValueRunner struct {
	calls atomic.Int32
	data  []byte
}

func (r *sharedValueRunner) Run(context.Context, collect.Exec, collect.Limits) (collect.Output, error) {
	r.calls.Add(1)
	return collect.Output{Stdout: r.data}, nil
}

func TestExecutor_DeduplicatedJSONIsIsolatedPerUnit(t *testing.T) {
	allow, err := rule.LoadAllowlist()
	if err != nil {
		t.Fatal(err)
	}
	runner := &sharedValueRunner{data: []byte(`[{"nested":[{"name":"item"}]}]`)}
	ex := newExecutor(context.Background(), nil, runner, "gcloud", nil, plan.Guard{Allow: allow}, "projects/example-prod", rule.Step{}, 0)
	ex.useTarget(plan.Target{Type: "project", Key: "projects/example-prod", ProjectID: "example-prod"})
	step := rule.Step{ID: "instances", Gcloud: "compute instances list --project=example-prod --format=json", Parse: "json"}
	values := make([]any, 2)
	failures := make([]*failure.Failure, 2)
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(2)
	var callers sync.WaitGroup
	for i := range values {
		callers.Add(1)
		go func(index int) {
			defer callers.Done()
			value, failed, _ := ex.executeWithKey(context.Background(), step, map[string]any{})
			values[index] = value
			failures[index] = failed
			ready.Done()
			if failed != nil {
				return
			}
			<-start
			data := eval.NewData()
			data.Set("instances", value)
			original := value.([]any)[0].(map[string]any)
			data.Attach(original, fmt.Sprintf("unit_%d", index), true)
			if err := eval.OriginalObjects(data, []any{original}); err != nil {
				t.Errorf("attached element lost original object identity: %v", err)
			}
			data.Fail(original, "details", "ERROR", "unit failure", nil)
			if len(data.Failures(original)) != 1 {
				t.Error("failure was not associated with the unit's original object")
			}
		}(i)
	}
	ready.Wait()
	close(start)
	callers.Wait()
	for _, failed := range failures {
		if failed != nil {
			t.Fatalf("execute failed: %v", failed)
		}
	}
	if got := runner.calls.Load(); got != 1 {
		t.Fatalf("deduplicated command calls=%d, want 1", got)
	}
	first := values[0].([]any)[0].(map[string]any)
	second := values[1].([]any)[0].(map[string]any)
	if reflectMapPointer(first) == reflectMapPointer(second) {
		t.Fatal("deduplicated result map is shared between units")
	}
	firstSlice := first["nested"].([]any)
	secondSlice := second["nested"].([]any)
	if reflectSlicePointer(firstSlice) == reflectSlicePointer(secondSlice) {
		t.Fatal("deduplicated result slice is shared between units")
	}
	firstNested := firstSlice[0].(map[string]any)
	secondNested := secondSlice[0].(map[string]any)
	if reflectMapPointer(firstNested) == reflectMapPointer(secondNested) {
		t.Fatal("nested result map is shared between units")
	}
	if first["unit_0"] != true || first["unit_1"] != nil || second["unit_1"] != true || second["unit_0"] != nil {
		t.Fatalf("attached values leaked between units: first=%#v second=%#v", first, second)
	}
}

func reflectMapPointer(value map[string]any) uintptr {
	return reflect.ValueOf(value).Pointer()
}

func reflectSlicePointer(value []any) uintptr {
	return reflect.ValueOf(value).Pointer()
}
