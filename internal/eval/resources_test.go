package eval_test

import (
	"context"
	"testing"

	"github.com/SummerQXY/gbencher/internal/eval"
	"github.com/SummerQXY/gbencher/internal/rule"
)

func TestExpandResources_NamePrefixAndDefaultKey(t *testing.T) {
	r := ruleWithResource("data.fws", "", "r.name")
	d := eval.NewData()
	d.Set("fws", []any{map[string]any{"name": "global/firewalls/allow-ssh"}})
	res, err := eval.ExpandResources(context.Background(), mustEnv(t), r, d, ctxOf(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Instances[0].Name; got != "projects/example-prod/global/firewalls/allow-ssh" {
		t.Fatalf("name = %q", got)
	}
	if got := res.Instances[0].Key; got != res.Instances[0].Name {
		t.Fatalf("key = %q, want default name %q", got, res.Instances[0].Name)
	}
}

func TestExpandResources_KeyExpressionUsesOriginalElement(t *testing.T) {
	r := ruleWithResource("data.networks", "", `r.name + "-display"`)
	r.Resource.Key = "r.name"
	d := eval.NewData()
	d.Set("networks", []any{map[string]any{"name": "default"}})
	res, err := eval.ExpandResources(context.Background(), mustEnv(t), r, d, ctxOf(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	inst := res.Instances[0]
	if got, want := inst.Name, "projects/example-prod/default-display"; got != want {
		t.Fatalf("name = %q, want %q", got, want)
	}
	if got, want := inst.Key, "default"; got != want {
		t.Fatalf("key = %q, want original resource name %q", got, want)
	}
}

func TestExpandResources_ClusterScopePrefix(t *testing.T) {
	r := ruleWithResource("data.items", "", "r.name")
	d := eval.NewData()
	d.Set("items", []any{map[string]any{"name": "namespaces/default/pods/p1"}})
	c := ctxOf(t)
	c.Cluster = map[string]any{"name": "cluster-a"}
	c.TargetKey = "projects/example-prod/locations/us-central1/clusters/cluster-a"
	res, err := eval.ExpandResources(context.Background(), mustEnv(t), r, d, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := res.Instances[0].Name, "clusters/cluster-a/namespaces/default/pods/p1"; got != want {
		t.Fatalf("name = %q, want %q", got, want)
	}
}

func TestExpandResources_EmptyAndFilteredOut(t *testing.T) {
	for _, tc := range []struct {
		name, expr, filter, want string
	}{
		{name: "empty", expr: "[]", want: "no_resources"},
		{name: "filtered", expr: "data.items", filter: "false", want: "filtered_out"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := ruleWithResource(tc.expr, tc.filter, "r.name")
			d := eval.NewData()
			if tc.name == "filtered" {
				d.Set("items", []any{map[string]any{"name": "one"}})
			}
			got, err := eval.ExpandResources(context.Background(), mustEnv(t), r, d, ctxOf(t), nil)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Empty || got.EmptyReason != tc.want || len(got.Instances) != 0 {
				t.Fatalf("got %#v", got)
			}
		})
	}
}

func TestExpandResources_AggregateInstanceUsesTargetKindAndKey(t *testing.T) {
	c := ctxOf(t)
	c.TargetKind, c.TargetKey = "project-kind", "projects/example-prod"
	got, err := eval.ExpandResources(context.Background(), mustEnv(t), &rule.Rule{}, eval.NewData(), c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Instances) != 1 {
		t.Fatalf("instances = %#v", got.Instances)
	}
	inst := got.Instances[0]
	if inst.Elem != nil || inst.Kind != c.TargetKind || inst.Name != c.TargetKey || inst.Key != c.TargetKey {
		t.Fatalf("instance = %#v", inst)
	}
}

func ruleWithResource(from, filter, name string) *rule.Rule {
	return &rule.Rule{Resource: &rule.Resource{From: from, Filter: filter, Name: name, Kind: "example/Resource"}}
}
