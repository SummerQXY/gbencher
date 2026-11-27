package eval_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/SummerQXY/gbencher/internal/eval"
	"github.com/SummerQXY/gbencher/internal/failure"
	"github.com/SummerQXY/gbencher/internal/rule"
)

func TestRunSteps_ForeachAttachesInPlaceAndKeepsIdentity(t *testing.T) {
	env := mustStepsEnv(t)
	sas := []any{map[string]any{"email": "a@example.com"}, map[string]any{"email": "b@example.com"}}
	d := eval.NewData()
	d.Set("sas", sas)
	r := &rule.Rule{Collect: []rule.Step{{ID: "keys", Foreach: "data.sas", As: "sa", Attach: "keys", Gcloud: "iam service-accounts keys list --iam-account={{ .sa.email }}"}}}
	var calls []string
	exec := func(_ context.Context, s rule.Step, values map[string]any) (any, *failure.Failure) {
		if s.ID != "keys" {
			t.Fatalf("unexpected step %q", s.ID)
		}
		email := values["sa"].(map[string]any)["email"].(string)
		calls = append(calls, email)
		return []any{map[string]any{"name": "key-" + email}}, nil
	}
	if _, err := eval.RunSteps(context.Background(), env, r, d, eval.Context{}, nil, exec, 500); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"a@example.com", "b@example.com"}) {
		t.Fatalf("calls = %#v", calls)
	}
	for _, item := range sas {
		if _, ok := item.(map[string]any)["keys"]; !ok {
			t.Fatalf("keys not attached: %#v", item)
		}
	}
	got, ok := d.Get("keys")
	if !ok || !reflect.DeepEqual(got, []any{[]any{map[string]any{"name": "key-a@example.com"}}, []any{map[string]any{"name": "key-b@example.com"}}}) {
		t.Fatalf("data.keys = %#v, %v", got, ok)
	}
}

func TestRunSteps_FanoutLimitEvaluatesFirstItemsAndMarksTheRestError(t *testing.T) {
	env := mustStepsEnv(t)
	items := []any{map[string]any{"n": 1}, map[string]any{"n": 2}, map[string]any{"n": 3}}
	d := eval.NewData()
	d.Set("items", items)
	r := &rule.Rule{Collect: []rule.Step{{ID: "details", Foreach: "data.items", As: "item", Attach: "detail", Gcloud: "compute instances describe {{ .item.n }}"}}}
	calls := 0
	out, err := eval.RunSteps(context.Background(), env, r, d, eval.Context{}, nil, func(context.Context, rule.Step, map[string]any) (any, *failure.Failure) {
		calls++
		return map[string]any{"ok": true}, nil
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if !reflect.DeepEqual(out.Truncated, []eval.Truncation{{Step: "details", Evaluated: 2, Total: 3}}) {
		t.Fatalf("Truncated = %#v", out.Truncated)
	}
	failed := d.Failures(items[2])
	if len(failed) != 1 || failed[0].Status != "ERROR" || failed[0].Reason != "fanout_exceeded" || failed[0].Failure.Class != failure.FanoutExceeded {
		t.Fatalf("truncated failure = %#v", failed)
	}
	for _, item := range items[:2] {
		if _, ok := item.(map[string]any)["detail"]; !ok {
			t.Fatalf("detail not attached: %#v", item)
		}
	}
}

func TestRunSteps_SingleItemFailureDoesNotAbortOthers(t *testing.T) {
	env := mustStepsEnv(t)
	items := []any{map[string]any{"n": 1}, map[string]any{"n": 2}, map[string]any{"n": 3}}
	d := eval.NewData()
	d.Set("items", items)
	r := &rule.Rule{Collect: []rule.Step{{ID: "details", Foreach: "data.items", As: "item", Attach: "detail", Gcloud: "compute instances describe {{ .item.n }}"}}}
	out, err := eval.RunSteps(context.Background(), env, r, d, eval.Context{}, nil, func(_ context.Context, _ rule.Step, values map[string]any) (any, *failure.Failure) {
		if values["item"].(map[string]any)["n"] == 2 {
			return nil, &failure.Failure{Class: failure.Permission}
		}
		return map[string]any{"ok": true}, nil
	}, 500)
	if err != nil {
		t.Fatal(err)
	}
	if out.Aborted != nil {
		t.Fatalf("unexpected abort: %+v", out.Aborted)
	}
	if failures := d.Failures(items[1]); len(failures) != 1 || failures[0].Status != "SKIPPED" {
		t.Fatalf("item failure = %#v", failures)
	}
	got, ok := d.Get("details")
	want := []any{map[string]any{"ok": true}, map[string]any{"ok": true}}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("data.details = %#v, %v", got, ok)
	}
}

func TestRunSteps_AuthExpiredIsFatal(t *testing.T) {
	r := &rule.Rule{Collect: []rule.Step{{ID: "one", Gcloud: "compute instances list"}}}
	out, err := eval.RunSteps(context.Background(), mustStepsEnv(t), r, eval.NewData(), eval.Context{}, nil, func(context.Context, rule.Step, map[string]any) (any, *failure.Failure) {
		return nil, &failure.Failure{Class: failure.AuthExpired}
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if out.Aborted == nil || !out.Aborted.Fatal {
		t.Fatalf("Aborted = %+v", out.Aborted)
	}
}

func TestRunSteps_EmptyOnServiceDisabledUsesShape(t *testing.T) {
	tests := []struct {
		name string
		step rule.Step
		want any
	}{
		{name: "list", step: rule.Step{ID: "items", Gcloud: "compute instances list", OnError: "empty"}, want: []any{}},
		{name: "describe", step: rule.Step{ID: "item", Gcloud: "compute instances describe x", OnError: "empty"}, want: map[string]any{}},
		{name: "text", step: rule.Step{ID: "text", Gcloud: "logging read x", Parse: "text", OnError: "empty"}, want: ""},
		{name: "lines", step: rule.Step{ID: "lines", Kubectl: "get pods", Parse: "lines", OnError: "empty"}, want: []string{}},
		{name: "logging_read", step: rule.Step{ID: "entries", Gcloud: "logging read", OnError: "empty"}, want: []any{}},
		{name: "logging_read_with_filter", step: rule.Step{ID: "filtered_entries", Gcloud: `logging read 'resource.type="gce_instance"' --limit=1`, OnError: "empty"}, want: []any{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eval.EmptyValueForStep(tt.step); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("EmptyValueForStep(%s) = %#v; want %#v", tt.step.ID, got, tt.want)
			}
			d := eval.NewData()
			_, err := eval.RunSteps(context.Background(), mustStepsEnv(t), &rule.Rule{Collect: []rule.Step{tt.step}}, d, eval.Context{}, nil, func(context.Context, rule.Step, map[string]any) (any, *failure.Failure) {
				return nil, &failure.Failure{Class: failure.ServiceDisabled}
			}, 10)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := d.Get(tt.step.ID)
			if !ok || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("data.%s = %#v, %v; want %#v", tt.step.ID, got, ok, tt.want)
			}
		})
	}
}

func TestRunSteps_IgnoreLeavesDataAbsentAndRecordsIgnoredStep(t *testing.T) {
	r := &rule.Rule{Collect: []rule.Step{
		{ID: "ignored", Gcloud: "compute instances list", OnError: "ignore"},
		{ID: "next", Gcloud: "compute instances list"},
	}}
	d := eval.NewData()
	calls := 0
	out, err := eval.RunSteps(context.Background(), mustStepsEnv(t), r, d, eval.Context{}, nil, func(_ context.Context, step rule.Step, _ map[string]any) (any, *failure.Failure) {
		calls++
		if step.ID == "ignored" {
			return nil, &failure.Failure{Class: failure.NotFound}
		}
		return "next", nil
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Get("ignored"); ok {
		t.Fatal("ignored data must remain absent")
	}
	if got, ok := d.Get("next"); !ok || got != "next" {
		t.Fatalf("next = %#v, %v", got, ok)
	}
	if calls != 2 || !reflect.DeepEqual(out.IgnoredSteps, []eval.IgnoredStep{{Step: "ignored", Reason: string(failure.NotFound)}}) {
		t.Fatalf("outcome = %+v, calls = %d", out, calls)
	}
}

func TestRunSteps_EmptyListSetsEmptySlice(t *testing.T) {
	d := eval.NewData()
	d.Set("items", []any{})
	r := &rule.Rule{Collect: []rule.Step{{ID: "details", Foreach: "data.items", As: "item", Gcloud: "compute instances describe {{ .item.name }}"}}}
	out, err := eval.RunSteps(context.Background(), mustStepsEnv(t), r, d, eval.Context{}, nil, func(context.Context, rule.Step, map[string]any) (any, *failure.Failure) {
		t.Fatal("exec called for empty foreach")
		return nil, nil
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := d.Get("details")
	if !ok || got == nil || !reflect.DeepEqual(got, []any{}) || out.Aborted != nil {
		t.Fatalf("data.details = %#v, %v; outcome = %+v", got, ok, out)
	}
}

func TestRunSteps_ForeachDefaultsVariableToItem(t *testing.T) {
	d := eval.NewData()
	d.Set("items", []any{"first"})
	r := &rule.Rule{Collect: []rule.Step{{ID: "values", Foreach: "data.items", Gcloud: "compute instances describe {{ .item }}"}}}
	_, err := eval.RunSteps(context.Background(), mustStepsEnv(t), r, d, eval.Context{}, nil, func(_ context.Context, _ rule.Step, vars map[string]any) (any, *failure.Failure) {
		return vars["item"], nil
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := d.Get("values")
	if !ok || !reflect.DeepEqual(got, []any{"first"}) {
		t.Fatalf("data.values = %#v, %v; want []any{\"first\"}", got, ok)
	}
}

func TestRunSteps_AttachSourceMustBeOriginalObjects(t *testing.T) {
	d := eval.NewData()
	r := &rule.Rule{Collect: []rule.Step{{ID: "details", Foreach: "[{name: 'constructed'}]", As: "item", Attach: "detail", Gcloud: "compute instances describe {{ .item.name }}"}}}
	_, err := eval.RunSteps(context.Background(), mustStepsEnv(t), r, d, eval.Context{}, nil, func(context.Context, rule.Step, map[string]any) (any, *failure.Failure) {
		return map[string]any{}, nil
	}, 10)
	if err == nil {
		t.Fatal("expected constructed attach source to fail")
	}
}

func TestRunSteps_AttachSourceRejectsScalarElements(t *testing.T) {
	d := eval.NewData()
	d.Set("items", []any{"scalar"})
	r := &rule.Rule{Collect: []rule.Step{{ID: "details", Foreach: "data.items", As: "item", Attach: "detail", Gcloud: "compute instances describe {{ .item }}"}}}
	_, err := eval.RunSteps(context.Background(), mustStepsEnv(t), r, d, eval.Context{}, nil, func(context.Context, rule.Step, map[string]any) (any, *failure.Failure) {
		return map[string]any{}, nil
	}, 10)
	if err == nil {
		t.Fatal("expected scalar attach source to fail")
	}
}

func TestRunSteps_ForeachWithoutAttachAllowsScalarElements(t *testing.T) {
	d := eval.NewData()
	d.Set("items", []any{"scalar"})
	r := &rule.Rule{Collect: []rule.Step{{ID: "values", Foreach: "data.items", As: "item", Gcloud: "compute instances describe {{ .item }}"}}}
	_, err := eval.RunSteps(context.Background(), mustStepsEnv(t), r, d, eval.Context{}, nil, func(_ context.Context, _ rule.Step, vars map[string]any) (any, *failure.Failure) {
		return vars["item"], nil
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := d.Get("values")
	if !ok || !reflect.DeepEqual(got, []any{"scalar"}) {
		t.Fatalf("data.values = %#v, %v", got, ok)
	}
}

func mustStepsEnv(t *testing.T) *eval.Env {
	t.Helper()
	env, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	return env
}
