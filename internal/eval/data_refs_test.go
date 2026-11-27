package eval_test

import (
	"slices"
	"testing"

	"github.com/SummerQXY/gbencher/internal/eval"
)

func TestDataDependencies(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		fields  []string
		unknown bool
	}{
		{name: "nested field selection", expr: "data.pods.items", fields: []string{"pods"}},
		{name: "optional selection", expr: "data.?nodes.orValue([])", fields: []string{"nodes"}},
		{name: "quoted index", expr: `data["roles"]`, fields: []string{"roles"}},
		{name: "optional quoted index", expr: `data[?"roles"].orValue([])`, fields: []string{"roles"}},
		{name: "macro and list composition", expr: "data.pods.filter(p, p.enabled).map(p, [p]) + data.nodes.filter(n, n.ready).map(n, [n])", fields: []string{"nodes", "pods"}},
		{name: "macro variable shadows data", expr: "data.pods.map(data, [data.name])", fields: []string{"pods"}},
		{name: "dynamic optional index", expr: `['instances'].map(id, data[?id].orValue([])).flatten()`, unknown: true},
		{name: "whole data value", expr: "data", unknown: true},
	}
	env, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := env.DataDependencies(tt.expr)
			if err != nil {
				t.Fatalf("DataDependencies(%q): %v", tt.expr, err)
			}
			if !slices.Equal(got.Fields, tt.fields) || got.Unknown != tt.unknown {
				t.Fatalf("DataDependencies(%q) = %+v, want fields=%v unknown=%v", tt.expr, got, tt.fields, tt.unknown)
			}
		})
	}
}
