package celenv_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types/ref"

	"github.com/SummerQXY/gbencher/internal/celenv"
)

// newEnv builds the environment under test and fails the test when it cannot be created.
func newEnv(t *testing.T, withResource bool) *cel.Env {
	t.Helper()
	env, err := celenv.New(withResource)
	if err != nil {
		t.Fatalf("New(%v): %v", withResource, err)
	}
	return env
}

// eval compiles expr, which must be valid in env, and evaluates it against vars. Only the
// evaluation error is returned: an expression that fails to compile fails the test, so a
// caller that expects an evaluation error cannot be satisfied by a rejected expression.
func eval(t *testing.T, env *cel.Env, expr string, vars map[string]any) (ref.Val, error) {
	t.Helper()
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		t.Fatalf("compile %q: %v", expr, iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatalf("program %q: %v", expr, err)
	}
	out, _, err := prg.Eval(vars)
	return out, err
}

func TestNew_EvaluatesDays(t *testing.T) {
	env := newEnv(t, false)
	vars := map[string]any{"ctx": map[string]any{"now": time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}}

	cases := []struct {
		name    string
		expr    string
		want    bool
		wantErr string // substring of the expected evaluation error; empty when the expression must succeed
	}{
		{"older than the window", `ctx.now - timestamp("2026-01-01T00:00:00Z") > days(90)`, true, ""},
		{"one day past the window", `ctx.now - timestamp("2026-03-02T00:00:00Z") > days(90)`, true, ""},
		{"exactly the window", `ctx.now - timestamp("2026-03-03T00:00:00Z") > days(90)`, false, ""},
		{"inside the window", `ctx.now - timestamp("2026-03-04T00:00:00Z") > days(90)`, false, ""},
		{"a day is 24 hours", `days(1) == duration("24h")`, true, ""},
		{"zero days", `days(0) == duration("0s")`, true, ""},
		{"negative days", `days(-1) == duration("-24h")`, true, ""},
		{"largest count that fits a duration", `days(106751) > days(106750)`, true, ""},
		{"count past the duration range", `days(106752) > days(1)`, false, "overflow"},
		{"negative count past the duration range", `days(-106752) < days(1)`, false, "overflow"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := eval(t, env, c.expr, vars)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("%s: want an evaluation error mentioning %q, got value %v and error %v", c.expr, c.wantErr, out, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: %v", c.expr, err)
			}
			if got, ok := out.Value().(bool); !ok || got != c.want {
				t.Errorf("%s = %v, want %v", c.expr, out, c.want)
			}
		})
	}
}

func TestNew_ExtensionsAvailable(t *testing.T) {
	env := newEnv(t, false)
	vars := map[string]any{"data": map[string]any{}, "params": map[string]any{"n": int64(1)}}

	cases := []struct {
		expr string
		want any // the native Go value the result is converted to and compared with
	}{
		{`"AbC".lowerAscii()`, "abc"},          // strings
		{`[[1],[2]].flatten()`, []int64{1, 2}}, // lists
		{`sets.contains([1,2],[1])`, true},     // sets
		{`math.greatest(1,2)`, int64(2)},       // math
		{`base64.encode(b"a")`, "YQ=="},        // encoders
		{`cel.bind(x, 1, x+1)`, int64(2)},      // bindings
		{`data.?x.orValue(7)`, int64(7)},       // optional types
		// Ordering across int and double type-checks only when cross-type numeric comparisons
		// are enabled. Equality needs no option at runtime, but the type checker rejects a
		// literal `1 == 1.0`, so equality is exercised on a dyn value, which is how rules
		// obtain their numbers.
		{`1 <= 1.0`, true},
		{`params.n == 1.0`, true},
	}
	for _, c := range cases {
		t.Run(c.expr, func(t *testing.T) {
			out, err := eval(t, env, c.expr, vars)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			got, err := out.ConvertToNative(reflect.TypeOf(c.want))
			if err != nil {
				t.Fatalf("convert %v to %T: %v", out, c.want, err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %#v, want %#v", got, c.want)
			}
		})
	}
}

func TestNew_ResourceVariableOnlyWhenRequested(t *testing.T) {
	cases := []struct {
		expr         string
		withResource bool
		compiles     bool
	}{
		{"r.name", false, false},
		{"r.name", true, true},
		// data and params are maps and ctx and r are dyn, whose operations are only checked at
		// runtime.
		{"data.x", false, true},
		{"params.x", false, true},
		{"ctx.x", false, true},
		{"data + 1", false, false},
		{"params + 1", false, false},
		{"ctx + 1", false, true},
		{"r + 1", true, true},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/resource=%v", c.expr, c.withResource), func(t *testing.T) {
			_, iss := newEnv(t, c.withResource).Compile(c.expr)
			if got := iss == nil || iss.Err() == nil; got != c.compiles {
				t.Errorf("compiles = %v, want %v (issues: %v)", got, c.compiles, iss)
			}
		})
	}

	// The resource variable is bound at evaluation time as well as declared.
	out, err := eval(t, newEnv(t, true), "r.name", map[string]any{"r": map[string]any{"name": "web-1"}})
	if err != nil || out.Value() != "web-1" {
		t.Errorf("r.name = %v (error: %v), want web-1", out, err)
	}
}
