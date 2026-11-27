package eval

import (
	"context"
	"fmt"
	"sync"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"github.com/SummerQXY/gbencher/internal/celenv"
	"github.com/SummerQXY/gbencher/internal/rule"
)

const (
	// Offline evaluation of 267 fixture files observed 1,070 CEL evaluations with a peak cost of 2,575.
	// The 1,000,000 limit exceeds the measured tenfold minimum of 25,750. Fixture evaluation does
	// not execute collector foreach expressions, so the observed peak does not cover those inputs.
	celCostLimit = 1_000_000
	celTimeout   = 2 * time.Second
)

// Env owns the CEL environments and evaluation diagnostics for a scan.
type Env struct {
	withoutResource *cel.Env
	withResource    *cel.Env
	mu              sync.RWMutex
	costObserver    func(string, uint64)
	compiled        map[string]*cel.Ast
}

// NewEnv creates the pair of CEL environments used for aggregate and resource expressions.
func NewEnv() (*Env, error) {
	without, err := celenv.New(false)
	if err != nil {
		return nil, err
	}
	with, err := celenv.New(true)
	if err != nil {
		return nil, err
	}
	return &Env{withoutResource: without, withResource: with, compiled: make(map[string]*cel.Ast)}, nil
}

// SetCostObserver installs a diagnostic callback for evaluated expressions.
func (e *Env) SetCostObserver(f func(expr string, cost uint64)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.costObserver = f
}

// CompileAll compiles every expression in r and reports the first invalid location.
func (e *Env) CompileAll(r *rule.Rule) error {
	if r == nil {
		return fmt.Errorf("rule is nil")
	}
	type site struct {
		location, expression string
		env                  *cel.Env
	}
	var sites []site
	for i, step := range r.Collect {
		if step.Foreach != "" {
			sites = append(sites, site{location: fmt.Sprintf("collect[%d].foreach", i), expression: step.Foreach, env: e.withoutResource})
		}
	}
	if r.Resource != nil {
		for _, item := range []struct {
			location, expression string
			env                  *cel.Env
		}{
			{"resource.from", r.Resource.From, e.withoutResource},
			{"resource.filter", r.Resource.Filter, e.withResource},
			{"resource.name", r.Resource.Name, e.withResource},
			{"resource.key", r.Resource.Key, e.withResource},
		} {
			if item.expression != "" {
				sites = append(sites, site{location: item.location, expression: item.expression, env: item.env})
			}
		}
	}
	checkEnv := e.withoutResource
	if r.Resource != nil {
		checkEnv = e.withResource
	}
	for _, item := range []struct{ location, expression string }{
		{"check.assert", r.Check.Assert}, {"check.review_when", r.Check.ReviewWhen},
	} {
		if item.expression != "" {
			sites = append(sites, site{location: item.location, expression: item.expression, env: checkEnv})
		}
	}
	for i, expr := range r.Evidence {
		if expr != "" {
			sites = append(sites, site{location: fmt.Sprintf("evidence[%d]", i), expression: expr, env: checkEnv})
		}
	}
	for _, item := range sites {
		if _, err := e.compile(item.env, item.expression); err != nil {
			return fmt.Errorf("rule %s %s: %w", r.ID, item.location, err)
		}
	}
	return nil
}

// List evaluates a list expression in the environment without r.
func (e *Env) List(ctx context.Context, expr string, d *Data, c Context, params map[string]any) ([]any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	listCtx, cancel := context.WithTimeout(ctx, celTimeout)
	defer cancel()
	value, _, err := e.evaluate(listCtx, e.withoutResource, expr, d, c, params, nil)
	if err != nil {
		return nil, err
	}
	l, ok := value.(traits.Lister)
	if !ok {
		return nil, fmt.Errorf("expression did not produce a list (got %T)", value)
	}
	size, ok := l.Size().(types.Int)
	if !ok {
		return nil, fmt.Errorf("expression did not produce a list (got %T)", value)
	}
	capacity := int(size)
	if capacity > 1024 {
		capacity = 1024
	}
	out := make([]any, 0, capacity)
	for i := int64(0); i < int64(size); i++ {
		if i%256 == 0 {
			if err := listCtx.Err(); err != nil {
				return nil, err
			}
		}
		item := l.Get(types.Int(i))
		if types.IsError(item) {
			return nil, fmt.Errorf("list element %d: %v", i, item)
		}
		out = append(out, item.Value())
	}
	if err := listCtx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Bool evaluates an expression and requires a boolean result.
func (e *Env) Bool(ctx context.Context, expr string, d *Data, r any, c Context, params map[string]any) (bool, error) {
	env := e.withoutResource
	if r != nil {
		env = e.withResource
	}
	value, _, err := e.evaluate(ctx, env, expr, d, c, params, r)
	if err != nil {
		return false, err
	}
	b, ok := value.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression did not produce a boolean")
	}
	return b, nil
}

// Value evaluates an expression and returns its native CEL value.
func (e *Env) Value(ctx context.Context, expr string, d *Data, r any, c Context, params map[string]any) (any, error) {
	env := e.withoutResource
	if r != nil {
		env = e.withResource
	}
	value, _, err := e.evaluate(ctx, env, expr, d, c, params, r)
	if err != nil {
		return nil, err
	}
	return value.Value(), nil
}

func (e *Env) evaluate(ctx context.Context, env *cel.Env, expr string, d *Data, c Context, params map[string]any, resource any) (ref.Val, *uint64, error) {
	ast, err := e.compile(env, expr)
	if err != nil {
		return nil, nil, fmt.Errorf("compile CEL expression: %w", err)
	}
	observer := e.getCostObserver()
	options := []cel.ProgramOption{cel.CostLimit(celCostLimit), cel.InterruptCheckFrequency(100)}
	if observer != nil {
		options = append(options, cel.CostTracking(nil))
	}
	program, err := env.Program(ast, options...)
	if err != nil {
		return nil, nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	evalCtx, cancel := context.WithTimeout(ctx, celTimeout)
	defer cancel()
	if err := evalCtx.Err(); err != nil {
		return nil, nil, err
	}
	d.mu.RLock()
	vars := map[string]any{"data": d.values, "params": params, "ctx": c.CELMap()}
	if env == e.withResource {
		vars["r"] = resource
	}
	value, details, err := program.ContextEval(evalCtx, vars)
	d.mu.RUnlock()
	var cost *uint64
	if details != nil {
		cost = details.ActualCost()
	}
	if err != nil {
		return nil, cost, err
	}
	if types.IsError(value) {
		return nil, cost, fmt.Errorf("evaluate CEL expression: %v", value)
	}
	if observer != nil && cost != nil {
		observer(expr, *cost)
	}
	return value, cost, nil
}

func (e *Env) compile(env *cel.Env, expr string) (*cel.Ast, error) {
	key := "without-resource\x00" + expr
	if env == e.withResource {
		key = "with-resource\x00" + expr
	}
	e.mu.RLock()
	ast := e.compiled[key]
	e.mu.RUnlock()
	if ast != nil {
		return ast, nil
	}
	ast, issues := env.Compile(expr)
	if issues.Err() != nil {
		return nil, issues.Err()
	}
	e.mu.Lock()
	if existing := e.compiled[key]; existing != nil {
		ast = existing
	} else {
		e.compiled[key] = ast
	}
	e.mu.Unlock()
	return ast, nil
}

func (e *Env) getCostObserver() func(string, uint64) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.costObserver
}
