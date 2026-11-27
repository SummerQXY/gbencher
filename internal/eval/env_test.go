package eval_test

import (
	"testing"
	"time"

	"github.com/SummerQXY/gbencher/internal/eval"
)

func TestContext_CELMapFields(t *testing.T) {
	now := time.Date(2026, 11, 16, 1, 2, 3, 0, time.UTC)
	c := eval.Context{
		Project: "example-prod", ProjectNumber: "123", Organization: "111", OrganizationDomain: "example.com",
		Folder: "222", Account: "scanner@example.com", Cluster: map[string]any{"name": "cluster"}, Now: now,
		TargetKey: "projects/example-prod", TargetKind: "project-kind",
	}
	got := c.CELMap()
	want := []string{"project", "project_number", "organization", "organization_domain", "folder", "account", "cluster", "now"}
	if len(got) != len(want) {
		t.Fatalf("got fields %#v", got)
	}
	for _, key := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("missing %q", key)
		}
	}
	if _, ok := got["target_key"]; ok {
		t.Fatal("target_key must not be exposed")
	}
	if _, ok := got["target_kind"]; ok {
		t.Fatal("target_kind must not be exposed")
	}
	if got["now"] != now {
		t.Fatalf("now = %#v", got["now"])
	}
}

func TestContext_VarsIncludesExtraWithoutTargetMetadata(t *testing.T) {
	c := eval.Context{Project: "example-prod", TargetKey: "projects/example-prod", TargetKind: "kind"}
	got := c.Vars(map[string]any{"limit": 3}, map[string]any{"item": "value"})
	if got["project"] != "example-prod" || got["params"].(map[string]any)["limit"] != 3 || got["item"] != "value" {
		t.Fatalf("unexpected vars: %#v", got)
	}
	if _, ok := got["target_key"]; ok {
		t.Fatal("target_key must not be a template variable")
	}
	if _, ok := got["target_kind"]; ok {
		t.Fatal("target_kind must not be a template variable")
	}
}
