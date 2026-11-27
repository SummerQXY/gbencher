package collect_test

import (
	"testing"

	"github.com/SummerQXY/gbencher/internal/collect"
)

func TestDecodeJSON_IntegralNumbersBecomeInt64AndBOMIsStripped(t *testing.T) {
	got, err := collect.DecodeJSON([]byte("\xef\xbb\xbf{\"a\":22,\"b\":1.5}"))
	if err != nil {
		t.Fatal(err)
	}
	values, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("DecodeJSON() type = %T", got)
	}
	if value, ok := values["a"].(int64); !ok || value != 22 {
		t.Errorf("a = %#v (%T), want int64(22)", values["a"], values["a"])
	}
	if value, ok := values["b"].(float64); !ok || value != 1.5 {
		t.Errorf("b = %#v (%T), want float64(1.5)", values["b"], values["b"])
	}
}

func TestDecodeJSON_NonJSONOrTrailingContentIsError(t *testing.T) {
	for _, input := range []string{"WARNING: update available\n[]", "[] trailing"} {
		if _, err := collect.DecodeJSON([]byte(input)); err == nil {
			t.Errorf("DecodeJSON(%q) returned no error", input)
		}
	}
}

func TestDecodeJSON_IntegerRangeIsCheckedRecursively(t *testing.T) {
	for _, tc := range []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{input: "9223372036854775807", want: 9223372036854775807},
		{input: "-9223372036854775808", want: -9223372036854775808},
		{input: "9223372036854775808", wantErr: true},
		{input: "-9223372036854775809", wantErr: true},
		{input: `{"nested":[9223372036854775808]}`, wantErr: true},
	} {
		got, err := collect.DecodeJSON([]byte(tc.input))
		if tc.wantErr {
			if err == nil {
				t.Errorf("DecodeJSON(%q) = %#v, want an error", tc.input, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("DecodeJSON(%q): %v", tc.input, err)
			continue
		}
		if value, ok := got.(int64); !ok || value != tc.want {
			t.Errorf("DecodeJSON(%q) = %#v (%T), want int64(%d)", tc.input, got, got, tc.want)
		}
	}
}
