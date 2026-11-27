package eval

import (
	"context"
	"fmt"
	"strings"

	"github.com/SummerQXY/gbencher/internal/cmdline"
	"github.com/SummerQXY/gbencher/internal/failure"
	"github.com/SummerQXY/gbencher/internal/rule"
)

// ExecuteFunc runs a prepared collection step and returns its parsed value or classified failure.
type ExecuteFunc func(ctx context.Context, step rule.Step, values map[string]any) (any, *failure.Failure)

// Abort describes a collection failure that stops the current rule's step sequence.
type Abort struct {
	Status, Reason string
	Fatal          bool
	Failure        *failure.Failure
}

// IgnoredStep records a failed step skipped by its on_error policy.
type IgnoredStep struct{ Step, Reason string }

// Truncation records a foreach step limited by the fanout bound.
type Truncation struct {
	Step             string
	Evaluated, Total int
}

// StepOutcome contains rule-level effects that the engine uses to assemble collection status.
type StepOutcome struct {
	Aborted      *Abort
	EmptySteps   []string
	IgnoredSteps []IgnoredStep
	Truncated    []Truncation
}

// RunSteps executes collection steps in declaration order and writes their values to d.
func RunSteps(ctx context.Context, env *Env, r *rule.Rule, d *Data, c Context, params map[string]any, exec ExecuteFunc, fanout int) (StepOutcome, error) {
	var outcome StepOutcome
	for _, step := range r.Collect {
		if step.Foreach == "" {
			value, f := exec(ctx, step, c.Vars(params, nil))
			if f == nil {
				d.Set(step.ID, value)
				continue
			}
			decision := Decide(f, step.OnError)
			switch decision.Action {
			case ActionEmpty:
				d.Set(step.ID, EmptyValue(shape(step)))
				outcome.EmptySteps = append(outcome.EmptySteps, step.ID)
			case ActionContinue:
				outcome.IgnoredSteps = append(outcome.IgnoredSteps, IgnoredStep{Step: step.ID, Reason: decision.Reason})
			case ActionAbort:
				outcome.Aborted = &Abort{Status: decision.Status, Reason: decision.Reason, Fatal: decision.Fatal, Failure: f}
				return outcome, nil
			}
			continue
		}

		items, err := env.List(ctx, step.Foreach, d, c, params)
		if err != nil {
			return outcome, err
		}
		if len(items) == 0 {
			d.Set(step.ID, []any{})
			continue
		}
		if step.Attach != "" {
			for i, item := range items {
				if _, ok := item.(map[string]any); !ok {
					return outcome, fmt.Errorf("attach source element %d is not an object", i)
				}
			}
			if err := OriginalObjects(d, items); err != nil {
				return outcome, err
			}
		}

		evaluated := len(items)
		if fanout >= 0 && evaluated > fanout {
			evaluated = fanout
			f := &failure.Failure{Class: failure.FanoutExceeded, Summary: "fanout limit exceeded"}
			for _, item := range items[evaluated:] {
				d.Fail(item, step.ID, "ERROR", "fanout_exceeded", f)
			}
			outcome.Truncated = append(outcome.Truncated, Truncation{Step: step.ID, Evaluated: evaluated, Total: len(items)})
		}

		values := make([]any, 0, evaluated)
		variable := step.As
		if variable == "" {
			variable = "item"
		}
		for _, item := range items[:evaluated] {
			value, f := exec(ctx, step, c.Vars(params, map[string]any{variable: item}))
			if f == nil {
				values = append(values, value)
				attachValue(d, item, step.Attach, value)
				continue
			}
			decision := Decide(f, step.OnError)
			switch decision.Action {
			case ActionEmpty:
				empty := EmptyValue(shape(step))
				values = append(values, empty)
				attachValue(d, item, step.Attach, empty)
				outcome.EmptySteps = append(outcome.EmptySteps, step.ID)
			case ActionContinue:
				outcome.IgnoredSteps = append(outcome.IgnoredSteps, IgnoredStep{Step: step.ID, Reason: decision.Reason})
			case ActionAbort:
				d.Fail(item, step.ID, decision.Status, decision.Reason, f)
				if decision.Fatal {
					outcome.Aborted = &Abort{Status: decision.Status, Reason: decision.Reason, Fatal: true, Failure: f}
					return outcome, nil
				}
			}
		}
		d.Set(step.ID, values)
	}
	return outcome, nil
}

func attachValue(d *Data, item any, field string, value any) {
	if field == "" {
		return
	}
	if object, ok := item.(map[string]any); ok {
		d.Attach(object, field, value)
	}
}

func shape(step rule.Step) EmptyShape {
	if step.API != nil && step.API.ListField != "" {
		return EmptyList
	}
	switch step.Parse {
	case "text":
		return EmptyString
	case "lines":
		return EmptyLines
	}
	if step.Gcloud != "" {
		words, err := cmdline.Split(step.Gcloud)
		if err == nil {
			path := make([]string, 0, len(words))
			for _, word := range words {
				value := word.String()
				if strings.HasPrefix(value, "-") || strings.Contains(value, "{{") {
					break
				}
				path = append(path, value)
			}
			if len(path) > 0 && path[len(path)-1] == "list" || len(path) >= 2 && path[0] == "logging" && path[1] == "read" {
				return EmptyList
			}
		}
	}
	return EmptyObject
}

// EmptyValueForStep returns the value used by an empty-on-error collection step.
func EmptyValueForStep(step rule.Step) any {
	return EmptyValue(shape(step))
}
