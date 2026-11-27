package rule_test

import (
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/internal/rule/lint"
)

func ptrFloat64(value float64) *float64 { return &value }

func TestApplyParams_DeepMergeAndTypeMismatch(t *testing.T) {
	r := selectionSet().Rules[0]
	r.Params["ports"] = []any{22}
	got, err := rule.ApplyParams(r, map[string]any{"settings": map[string]any{"left": 3}})
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]any{"left": 3, "right": 2}; !reflect.DeepEqual(got["settings"], want) {
		t.Fatalf("settings = %#v, want %#v", got["settings"], want)
	}
	cases := []struct {
		name string
		def  any
		set  any
	}{
		{"list to string", []any{22}, "22"},
		{"integer to float", 1, 1.0},
		{"mixed list element types", []any{22}, []any{22, "80"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &rule.Rule{ID: "cis-gcp-1.1", Params: map[string]any{"value": tc.def}}
			_, err := rule.ApplyParams(r, map[string]any{"value": tc.set})
			if err == nil || !strings.Contains(err.Error(), r.ID) || !strings.Contains(err.Error(), "value") {
				t.Fatalf("error = %v, want rule id and parameter", err)
			}
		})
	}
}

func TestApplyParams_ConstraintViolation(t *testing.T) {
	min, max := 1.0, 365.0
	r := &rule.Rule{ID: "cis-gcp-2.2", Params: map[string]any{"freshness_days": 30}, ParamsConstraints: map[string]rule.ParamConstraint{"freshness_days": {Minimum: &min, Maximum: &max}}}
	for _, value := range []any{0, 500} {
		_, err := rule.ApplyParams(r, map[string]any{"freshness_days": value})
		if err == nil || !strings.Contains(err.Error(), r.ID) || !strings.Contains(err.Error(), "freshness_days") {
			t.Errorf("value %v: error = %v", value, err)
		}
	}
}

func TestApplyParams_RejectsIntegerOutsideInt64Range(t *testing.T) {
	r := &rule.Rule{ID: "cis-gcp-1.1", Params: map[string]any{"value": 1}}
	if _, err := rule.ApplyParams(r, map[string]any{"value": uint64(math.MaxUint64)}); err == nil || !strings.Contains(err.Error(), "int64") {
		t.Fatalf("error = %v, want int64 range error", err)
	}
	objectRule := &rule.Rule{ID: "cis-gcp-1.2", Params: map[string]any{"object": map[string]any{}}}
	if _, err := rule.ApplyParams(objectRule, map[string]any{"object": map[string]any{"value": uint64(math.MaxUint64)}}); err == nil || !strings.Contains(err.Error(), "int64") {
		t.Fatalf("nested error = %v, want int64 range error", err)
	}
	profile := &rule.Profile{Overrides: map[string]rule.Override{
		"cis-gcp-1.1": {Params: map[string]any{"settings": map[string]any{"value": uint64(math.MaxUint64)}}},
	}}
	if _, err := rule.Select(selectionSet(), profile, rule.Selection{}); err == nil || !strings.Contains(err.Error(), "int64") {
		t.Fatalf("profile override error = %v, want int64 range error", err)
	}
}

func TestParamConstraint_CheckUsesExactNumericComparison(t *testing.T) {
	large := int64(9007199254740992)
	if err := (rule.ParamConstraint{Enum: []any{large}}).Check(int64(9007199254740993)); err == nil {
		t.Fatal("adjacent large integer unexpectedly matched enum")
	}
	if err := (rule.ParamConstraint{Enum: []any{int64(1)}}).Check(float64(1)); err != nil {
		t.Fatalf("equivalent integer and float did not match: %v", err)
	}
	max := float64(9007199254740992)
	if err := (rule.ParamConstraint{Maximum: &max}).Check(int64(9007199254740993)); err == nil {
		t.Fatal("integer above a large maximum unexpectedly passed")
	}
}

func TestParamConstraint_CheckRejectsNonFiniteNumbers(t *testing.T) {
	inf := math.Inf(1)
	cases := []struct {
		name  string
		value any
		c     rule.ParamConstraint
	}{
		{"nan bound", math.NaN(), rule.ParamConstraint{Minimum: ptrFloat64(0)}},
		{"infinity bound", math.Inf(1), rule.ParamConstraint{Maximum: ptrFloat64(math.MaxFloat64)}},
		{"infinity enum", inf, rule.ParamConstraint{Enum: []any{inf}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.c.Check(tc.value); err == nil {
				t.Fatal("non-finite number passed a constraint")
			}
		})
	}
}

func TestLargeIntegerConstraintCheckMatchesLintAndOverride(t *testing.T) {
	allowed := int64(9007199254740992)
	value := int64(9007199254740993)
	c := rule.ParamConstraint{Enum: []any{allowed}}
	r := &rule.Rule{ID: "cis-gcp-2.2", Params: map[string]any{"value": value}, ParamsConstraints: map[string]rule.ParamConstraint{"value": c}}
	_, overrideErr := rule.ApplyParams(r, map[string]any{"value": value})
	findings := lint.Run([]*rule.File{{Rules: []*rule.Rule{r}}}, nil, lint.Options{})
	var lintRejected bool
	for _, finding := range findings {
		if finding.Code == "params-default-violates-constraint" {
			lintRejected = true
		}
	}
	if overrideErr == nil || !lintRejected {
		t.Fatalf("override error=%v, lint rejected=%t, findings=%+v", overrideErr, lintRejected, findings)
	}
}

func TestApplyParams_UnknownRuleAndUnknownParamAreErrors(t *testing.T) {
	if _, err := rule.ApplyParams(nil, map[string]any{"x": 1}); err == nil || !strings.Contains(err.Error(), "rule") {
		t.Fatalf("nil rule error = %v", err)
	}
	r := &rule.Rule{ID: "cis-gcp-1.1", Params: map[string]any{"known": 1}}
	if _, err := rule.ApplyParams(r, map[string]any{"unknown": 1}); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown param error = %v", err)
	}
}

func TestSetArg_ParsesLastDotAndOptionalParamsPrefix(t *testing.T) {
	first, err := rule.ParseSetArg("cis-gcp-3.6.ports=[22]")
	if err != nil {
		t.Fatal(err)
	}
	second, err := rule.ParseSetArg("cis-gcp-3.6.params.ports=[22]")
	if err != nil {
		t.Fatal(err)
	}
	if first.RuleID != "cis-gcp-3.6" || first.Param != "ports" || !reflect.DeepEqual(first, second) || !reflect.DeepEqual(first.Value, []any{int64(22)}) {
		t.Fatalf("parsed values: first=%+v second=%+v", first, second)
	}
	params, err := rule.ApplyParams(&rule.Rule{ID: first.RuleID, Params: map[string]any{"ports": []any{22}}}, map[string]any{"ports": first.Value})
	if err != nil || !reflect.DeepEqual(params["ports"], []any{22}) {
		t.Fatalf("integer default override: params=%#v err=%v", params, err)
	}
	if _, err := rule.ParseSetArg("cis-gcp-3.6.ports=["); err == nil {
		t.Fatal("invalid JSON value was accepted")
	}
	withEquals, err := rule.ParseSetArg(`cis-gcp-3.6.name="a=b"`)
	if err != nil || withEquals.Value != "a=b" {
		t.Fatalf("JSON string with equals: %+v, %v", withEquals, err)
	}
}

func TestSetArg_NormalizesNumbersInObjectsAndNestedArrays(t *testing.T) {
	setArg, err := rule.ParseSetArg(`cis-gcp-3.6.obj={"count":2,"ratio":1.5,"nested":{"values":[3,1.25]}}`)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"count": int64(2), "ratio": float64(1.5),
		"nested": map[string]any{"values": []any{int64(3), float64(1.25)}},
	}
	if !reflect.DeepEqual(setArg.Value, want) {
		t.Fatalf("parsed object = %#v, want %#v", setArg.Value, want)
	}
	r := &rule.Rule{ID: "cis-gcp-3.6", Params: map[string]any{"obj": map[string]any{}}}
	params, err := rule.ApplyParams(r, map[string]any{"obj": setArg.Value})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(params["obj"], want) {
		t.Fatalf("effective object = %#v, want %#v", params["obj"], want)
	}
}

func TestSetArg_RejectsIntegerOutsideInt64Range(t *testing.T) {
	for _, arg := range []string{
		"cis-gcp-3.6.obj={\"count\":9223372036854775808}",
		"cis-gcp-3.6.count=18446744073709551615",
	} {
		if _, err := rule.ParseSetArg(arg); err == nil || !strings.Contains(err.Error(), "int64") {
			t.Errorf("ParseSetArg(%q) error = %v, want int64 range error", arg, err)
		}
	}
}

func TestSetArg_RejectsTrailingJSONValue(t *testing.T) {
	_, err := rule.ParseSetArg("cis-gcp-3.6.value=1 2")
	if err == nil || !strings.Contains(err.Error(), "trailing") && !strings.Contains(err.Error(), "one JSON value") {
		t.Fatalf("error = %v, want trailing JSON content error", err)
	}
}

func TestConstraintCheckMatchesLintAndOverride(t *testing.T) {
	min, max := 1.0, 365.0
	c := rule.ParamConstraint{Minimum: &min, Maximum: &max}
	r := &rule.Rule{ID: "cis-gcp-2.2", Params: map[string]any{"freshness_days": 0}, ParamsConstraints: map[string]rule.ParamConstraint{"freshness_days": c}}
	_, overrideErr := rule.ApplyParams(r, map[string]any{"freshness_days": 0})
	findings := lint.Run([]*rule.File{{Rules: []*rule.Rule{r}}}, nil, lint.Options{})
	var lintRejected bool
	for _, finding := range findings {
		if finding.Code == "params-default-violates-constraint" {
			lintRejected = true
		}
	}
	if (overrideErr != nil) != lintRejected {
		t.Fatalf("override rejected=%t, lint rejected=%t, findings=%+v", overrideErr != nil, lintRejected, findings)
	}
}
