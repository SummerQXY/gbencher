package collect_test

import (
	"reflect"
	"testing"

	"github.com/SummerQXY/gbencher/internal/collect"
)

type methodValue struct{}

func (methodValue) String() string { return "ok" }

type embeddedValue struct{ Value string }

type pointerEmbeddedValue struct{ *embeddedValue }

type methodShadowValue struct{ embeddedValue }

func (methodShadowValue) Value() string { return "method" }

type namedString string

func (namedString) String() string { return "method" }

type panicString string

func (panicString) String() string { panic("String method called") }

func TestRenderArgv_QuotedFilterStaysOneToken(t *testing.T) {
	got, err := collect.RenderArgv(`logging read 'protoPayload.serviceName="admin.googleapis.com" OR x' --limit=1`, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"logging", "read", `protoPayload.serviceName="admin.googleapis.com" OR x`, "--limit=1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RenderArgv() = %#v, want %#v", got, want)
	}
}

func TestRenderArgv_ActionWithSpacesIsNotSplit(t *testing.T) {
	got, err := collect.RenderArgv(`--policy={{ .policy }}`, map[string]any{"policy": "allow all"})
	if err == nil {
		t.Fatalf("RenderArgv() = %#v, want whitespace error", got)
	}
}

func TestRenderArgv_ValueWithWhitespaceIsRejected(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "spaces", value: "gs://x --impersonate-service-account=evil@example.com"},
		{name: "tabs", value: "a\tb"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := collect.RenderArgv(`storage buckets get-iam-policy {{ .v }}`, map[string]any{"v": test.value})
			if err == nil {
				t.Fatalf("RenderArgv() = %#v, want whitespace error", got)
			}
		})
	}
}

func TestRenderArgv_ControlCharacterRejected(t *testing.T) {
	for _, value := range []string{"a\nb", "a\x1bb"} {
		got, err := collect.RenderArgv(`--policy={{ .v }}`, map[string]any{"v": value})
		if err == nil {
			t.Fatalf("RenderArgv(%q) = %#v, want control character error", value, got)
		}
	}
}

func TestRenderArgv_MissingKeyIsError(t *testing.T) {
	got, err := collect.RenderArgv(`{{ .nope }}`, map[string]any{})
	if err == nil {
		t.Fatalf("RenderArgv() = %#v, want missing key error", got)
	}
}

func TestRenderArgv_ActionFirstWordRejectsLeadingDash(t *testing.T) {
	for _, template := range []string{`{{ .v }}`, `{{ .v }}=x`} {
		got, err := collect.RenderArgv(template, map[string]any{"v": "-x"})
		if err == nil {
			t.Errorf("RenderArgv(%q) = %#v, want leading dash error", template, got)
		}
	}
	got, err := collect.RenderArgv(`--name={{ .v }}`, map[string]any{"v": "-x"})
	if err != nil || !reflect.DeepEqual(got, []string{"--name=-x"}) {
		t.Fatalf("RenderArgv() = %#v, %v; want [--name=-x], nil", got, err)
	}
}

func TestRenderArgv_OnlyAcceptsScalarValues(t *testing.T) {
	for _, value := range []any{nil, []string{"x"}, map[string]string{"x": "y"}} {
		got, err := collect.RenderArgv(`{{ .v }}`, map[string]any{"v": value})
		if err == nil {
			t.Errorf("RenderArgv(%#v) = %#v, want value type error", value, got)
		}
	}
	got, err := collect.RenderArgv(`{{ .v }}`, map[string]any{"v": 42})
	if err != nil || !reflect.DeepEqual(got, []string{"42"}) {
		t.Fatalf("RenderArgv() = %#v, %v; want [42], nil", got, err)
	}
}

func TestRenderArgv_RejectsNonScalarFormattingExpression(t *testing.T) {
	got, err := collect.RenderArgv(`{{ printf "%v" .v }}`, map[string]any{"v": map[string]string{"x": "y"}})
	if err == nil {
		t.Fatalf("RenderArgv() = %#v, want non-scalar expression error", got)
	}

	got, err = collect.RenderArgv(`{{ .b.url }}`, map[string]any{"b": map[string]any{"url": "gs://example"}})
	if err != nil || !reflect.DeepEqual(got, []string{"gs://example"}) {
		t.Fatalf("RenderArgv() = %#v, %v; want [gs://example], nil", got, err)
	}
}

func TestRenderArgv_RejectsMethodSelector(t *testing.T) {
	got, err := collect.RenderArgv(`{{ .v.String }}`, map[string]any{"v": methodValue{}})
	if err == nil {
		t.Fatalf("RenderArgv() = %#v, want method selector error", got)
	}
}

func TestRenderArgv_NilEmbeddedFieldReturnsError(t *testing.T) {
	got, err := collect.RenderArgv(`{{ .v.Value }}`, map[string]any{"v": pointerEmbeddedValue{}})
	if err == nil {
		t.Fatalf("RenderArgv() = %#v, want nil embedded field error", got)
	}

	got, err = collect.RenderArgv(`{{ .v.Value }}`, map[string]any{"v": embeddedValue{Value: "ok"}})
	if err != nil || !reflect.DeepEqual(got, []string{"ok"}) {
		t.Fatalf("RenderArgv() = %#v, %v; want [ok], nil", got, err)
	}
}

func TestRenderArgv_UsesValidatedEmbeddedField(t *testing.T) {
	got, err := collect.RenderArgv(`{{ .v.Value }}`, map[string]any{"v": methodShadowValue{
		embeddedValue: embeddedValue{Value: "field"},
	}})
	if err != nil || !reflect.DeepEqual(got, []string{"field"}) {
		t.Fatalf("RenderArgv() = %#v, %v; want [field], nil", got, err)
	}
}

func TestRenderArgv_FormatsNamedStringWithoutCallingString(t *testing.T) {
	for _, value := range []any{namedString("field"), panicString("safe")} {
		got, err := collect.RenderArgv(`{{ .v }}`, map[string]any{"v": value})
		if err != nil || !reflect.DeepEqual(got, []string{stringValue(value)}) {
			t.Fatalf("RenderArgv(%T) = %#v, %v; want underlying string, nil", value, got, err)
		}
	}
}

func TestRenderArgv_FormatsNumericAndBooleanScalars(t *testing.T) {
	got, err := collect.RenderArgv(`{{ .count }} {{ .ratio }} {{ .enabled }}`, map[string]any{
		"count":   int64(42),
		"ratio":   float64(1.25),
		"enabled": true,
	})
	want := []string{"42", "1.25", "true"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("RenderArgv() = %#v, %v; want %#v, nil", got, err, want)
	}
}

func TestRenderArgv_ConditionalActionWordFailsClosed(t *testing.T) {
	got, err := collect.RenderArgv(`{{ if .x }}--limit=1{{ end }}`, map[string]any{"x": true})
	if err == nil {
		t.Fatalf("RenderArgv() = %#v, want action parse error", got)
	}
}

func TestRenderURL_PercentEncodesSegment(t *testing.T) {
	got, err := collect.RenderURL(`https://bigquery.googleapis.com/bigquery/v2/projects/{{ .project }}/datasets/{{ .ds }}`,
		map[string]any{"project": "example-prod", "ds": "a/b c"})
	want := "https://bigquery.googleapis.com/bigquery/v2/projects/example-prod/datasets/a%2Fb%20c"
	if err != nil || got != want {
		t.Fatalf("RenderURL() = %q, %v; want %q, nil", got, err, want)
	}
}

func TestRenderURL_RejectsNonScalarFormattingExpression(t *testing.T) {
	for _, action := range []string{`{{ .v }}`, `{{ print .v }}`} {
		got, err := collect.RenderURL(`https://example.com/v1/`+action,
			map[string]any{"v": map[string]string{"x": "y"}})
		if err == nil {
			t.Errorf("RenderURL(%q) = %q, want non-scalar expression error", action, got)
		}
	}

	got, err := collect.RenderURL(`https://example.com/v1/{{ .b.url }}`,
		map[string]any{"b": map[string]any{"url": "a/b c"}})
	want := "https://example.com/v1/a%2Fb%20c"
	if err != nil || got != want {
		t.Fatalf("RenderURL() = %q, %v; want %q, nil", got, err, want)
	}
}

func TestRenderURL_RejectsMethodSelector(t *testing.T) {
	got, err := collect.RenderURL(`https://example.com/v1/{{ .v.String }}`,
		map[string]any{"v": methodValue{}})
	if err == nil {
		t.Fatalf("RenderURL() = %q, want method selector error", got)
	}
}

func TestRenderURL_UsesValidatedEmbeddedField(t *testing.T) {
	got, err := collect.RenderURL(`https://example.com/v1/{{ .v.Value }}`,
		map[string]any{"v": methodShadowValue{embeddedValue: embeddedValue{Value: "field"}}})
	want := "https://example.com/v1/field"
	if err != nil || got != want {
		t.Fatalf("RenderURL() = %q, %v; want %q, nil", got, err, want)
	}
}

func TestRenderURL_FormatsNamedStringWithoutCallingString(t *testing.T) {
	got, err := collect.RenderURL(`https://example.com/v1/{{ .v }}`,
		map[string]any{"v": panicString("safe")})
	want := "https://example.com/v1/safe"
	if err != nil || got != want {
		t.Fatalf("RenderURL() = %q, %v; want %q, nil", got, err, want)
	}
}

func stringValue(value any) string {
	switch value := value.(type) {
	case namedString:
		return string(value)
	case panicString:
		return string(value)
	default:
		return ""
	}
}

func TestRenderURL_RejectsActionInHostAndUserinfo(t *testing.T) {
	for _, template := range []string{
		`https://{{ .host }}/v1/projects/{{ .project }}`,
		`https://user:pass@example.com/v1/{{ .project }}`,
	} {
		got, err := collect.RenderURL(template, map[string]any{"host": "example.com", "project": "p"})
		if err == nil {
			t.Errorf("RenderURL(%q) = %q, want error", template, got)
		}
	}
}

func TestRenderURL_ActionMustOccupyWholeSegment(t *testing.T) {
	for _, template := range []string{
		`https://example.com/v1/pre{{ .project }}`,
		`https://example.com/v1/{{ .project }}post`,
		`https://example.com/v1/{{ .a }}{{ .b }}`,
	} {
		got, err := collect.RenderURL(template, map[string]any{"project": "p", "a": "a", "b": "b"})
		if err == nil {
			t.Errorf("RenderURL(%q) = %q, want segment boundary error", template, got)
		}
	}
}

func TestRenderURL_RequiresHTTPSWithoutWhitespace(t *testing.T) {
	for _, template := range []string{
		`http://example.com/v1/{{ .project }}`,
		`https://example.com/v1/{{ .project }} `,
	} {
		got, err := collect.RenderURL(template, map[string]any{"project": "p"})
		if err == nil {
			t.Errorf("RenderURL(%q) = %q, want validation error", template, got)
		}
	}
}
