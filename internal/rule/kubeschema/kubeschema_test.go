package kubeschema

import (
	"slices"
	"testing"

	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/rules"
)

func TestKubectlSchemaLintRejectsUnknownResource(t *testing.T) {
	result := Check(&rule.Set{Rules: []*rule.Rule{kubectlRule("cis-gke-test", "get unknownresources -o json", "data.pods.items.exists(item, item.metadata.name != '')")}})
	if len(result.Errors) == 0 {
		t.Fatal("unknown Kubernetes resource passed schema validation")
	}
}

func TestKubectlSchemaLintRejectsUnknownFieldPath(t *testing.T) {
	result := Check(&rule.Set{Rules: []*rule.Rule{kubectlRule("cis-gke-test", "get pods -o json", "data.pods.items.exists(item, item.spec.unknownField == true)")}})
	if len(result.Errors) == 0 {
		t.Fatalf("unknown Kubernetes field passed schema validation: warnings=%v static=%v", result.Warnings, result.StaticOK)
	}
}

func TestKubectlSchemaLintWarnsOnUnresolvedPath(t *testing.T) {
	for _, expression := range []string{
		"external.items.exists(item, item.spec.containers.exists(container, container.name == 'app'))",
		"data.pods.items.exists(item, item[params.field] == 'app')",
	} {
		result := Check(&rule.Set{Rules: []*rule.Rule{kubectlRule("cis-gke-test", "get pods -o json", expression)}})
		if len(result.Warnings) == 0 {
			t.Errorf("unresolved Kubernetes path did not produce a warning: %s", expression)
		}
		if result.StaticOK["cis-gke-test"] {
			t.Errorf("rule with an unresolved Kubernetes path earned static verification: %s", expression)
		}
	}
}

func TestKubectlSchemaLintWarnsOnUnverifiedClusterContext(t *testing.T) {
	for _, expression := range []string{
		"ctx.cluster.?autopilot.?enabled.orValue(false)",
		"data.cluster.?autopilot.?enabled.orValue(false)",
		"ctx.cluster.?noSuchField.orValue(false)",
		"data.cluster.?noSuchField.orValue(false)",
	} {
		result := Check(&rule.Set{Rules: []*rule.Rule{kubectlRule("cis-gke-test", "get pods -o json", expression)}})
		if len(result.Errors) != 0 {
			t.Errorf("cluster context path produced a field error without a complete GKE Cluster schema: %s: %v", expression, result.Errors)
		}
		if len(result.Warnings) == 0 {
			t.Errorf("cluster context path was treated as schema-verified: %s", expression)
		}
		if result.StaticOK["cis-gke-test"] {
			t.Errorf("rule with an unverified cluster context path earned static verification: %s", expression)
		}
	}
}

func TestKubectlSchemaLintTracksMacroElementSchema(t *testing.T) {
	expression := "data.pods.items.exists(p, p.spec.containers.all(c, c.name != '') && p.spec.containers.filter(c, c.image != '').map(c, c.name).exists(n, n != '')) && (data.pods.items + data.pods.items).flatten().exists(p, p.metadata.name != '') && data.pods.items.exists(p, p.?metadata.?name.orValue('') != '')"
	result := Check(&rule.Set{Rules: []*rule.Rule{kubectlRule("cis-gke-test", "get pods -o json", expression)}})
	if len(result.Errors) != 0 || len(result.Warnings) != 0 {
		t.Fatalf("macro element schema was not tracked: errors=%v warnings=%v", result.Errors, result.Warnings)
	}
	if !result.StaticOK["cis-gke-test"] {
		t.Fatal("fully resolved Kubernetes paths did not earn static verification")
	}
	for _, expression := range []string{
		"(data.pods.items + data.pods.items).exists(p, p.unknownField == true)",
		"(data.pods.items + data.pods.items).flatten().exists(p, p.unknownField == true)",
		"data.pods.items.exists(p, p.spec.containers.all(c, c.unknownField == true))",
		"data.pods.items.exists(p, p.spec.containers.filter(c, c.unknownField == true).size() > 0)",
		"data.pods.items.exists(p, p.spec.containers.map(c, c.unknownField).exists(n, n == true))",
	} {
		result = Check(&rule.Set{Rules: []*rule.Rule{kubectlRule("cis-gke-test", "get pods -o json", expression)}})
		if len(result.Errors) == 0 {
			t.Errorf("unknown field after list operation passed schema validation: %s", expression)
		}
	}
}

func TestKubectlSchemaLintTracksMapProjectionTypes(t *testing.T) {
	for _, expression := range []string{
		"data.pods.items.map(p, p).exists(p, p.noSuchField == true)",
		"data.pods.items.map(p, p.metadata).exists(m, m.noSuchField == true)",
		"data.pods.items.map(p, p.spec.containers).flatten().map(c, c.resources).exists(r, r.noSuchField == true)",
	} {
		result := Check(&rule.Set{Rules: []*rule.Rule{kubectlRule("cis-gke-test", "get pods -o json", expression)}})
		if len(result.Errors) == 0 {
			t.Errorf("unknown field after map projection passed schema validation: %s", expression)
		}
		if result.StaticOK["cis-gke-test"] {
			t.Errorf("unknown field after map projection earned static verification: %s", expression)
		}
	}
}

func TestKubectlSchemaLintValidatesAllHeterogeneousListTypes(t *testing.T) {
	var wantErrors []string
	for i, expression := range []string{
		"(data.pods.items + data.nodes.items).exists(item, item.spec.containers.exists(container, container.name != ''))",
		"(data.nodes.items + data.pods.items).exists(item, item.spec.containers.exists(container, container.name != ''))",
	} {
		current := &rule.Rule{
			ID:      "cis-gke-test",
			Collect: []rule.Step{{ID: "pods", Kubectl: "get pods -o json"}, {ID: "nodes", Kubectl: "get nodes -o json"}},
			Check:   rule.Check{Assert: expression},
		}
		result := Check(&rule.Set{Rules: []*rule.Rule{current}})
		if len(result.Errors) == 0 {
			t.Errorf("path absent from one heterogeneous list type passed validation: %s", expression)
		}
		if result.StaticOK[current.ID] {
			t.Errorf("heterogeneous list earned static verification: %s", expression)
		}
		if i == 0 {
			wantErrors = slices.Clone(result.Errors)
		} else if !slices.Equal(result.Errors, wantErrors) {
			t.Errorf("list order changed findings: got %v, want %v", result.Errors, wantErrors)
		}
	}
	current := &rule.Rule{
		ID:      "cis-gke-test",
		Collect: []rule.Step{{ID: "pods", Kubectl: "get pods -o json"}, {ID: "nodes", Kubectl: "get nodes -o json"}},
		Check:   rule.Check{Assert: "(data.pods.items + data.nodes.items).exists(item, item.metadata.name != '')"},
	}
	result := Check(&rule.Set{Rules: []*rule.Rule{current}})
	if len(result.Errors) != 0 || len(result.Warnings) != 0 || !result.StaticOK[current.ID] {
		t.Fatalf("common heterogeneous fields were not validated: errors=%v warnings=%v static=%v", result.Errors, result.Warnings, result.StaticOK)
	}
}

func TestKubeconfigClusterFieldsExistInDiscoverySchema(t *testing.T) {
	if err := CheckKubeconfigFields(); err != nil {
		t.Fatalf("kubeconfig cluster fields are absent from the pinned discovery schema: %v", err)
	}
}

func TestKubectlSchemaLintChecksGKECorpus(t *testing.T) {
	files, violations, err := rule.LoadFiles(rules.FS)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Fatalf("rule corpus violations: %+v", violations)
	}
	set := &rule.Set{}
	for _, file := range files {
		set.Rules = append(set.Rules, file.Rules...)
	}
	var kubectlRules int
	for _, current := range set.Rules {
		for _, step := range current.Collect {
			if step.Kubectl != "" {
				kubectlRules++
				break
			}
		}
	}
	if kubectlRules != 25 {
		t.Fatalf("found %d kubectl rules, want 25", kubectlRules)
	}
	result := Check(set)
	if len(result.Errors) != 0 || len(result.Warnings) != 10 {
		t.Fatalf("GKE kubectl schema lint findings: errors=%v warnings=%v", result.Errors, result.Warnings)
	}
	if len(result.StaticOK) != 15 {
		t.Fatalf("%d of %d kubectl rules earned static verification, want 15 with cluster context paths excluded", len(result.StaticOK), kubectlRules)
	}
	for _, id := range []string{"cis-gke-4.2.1", "cis-gke-4.3.2", "cis-gke-4.6.2"} {
		if result.StaticOK[id] {
			t.Errorf("rule with unverified GKE Cluster describe fields earned static verification: %s", id)
		}
	}
	if !result.StaticOK["cis-gke-4.1.1"] {
		t.Fatal("pure Kubernetes resource rule lost static verification")
	}
}

func kubectlRule(id, command, assert string) *rule.Rule {
	return &rule.Rule{
		ID:       id,
		Collect:  []rule.Step{{ID: "pods", Kubectl: command}},
		Resource: &rule.Resource{From: "data.pods.items", Kind: "v1/Pod"},
		Check:    rule.Check{Assert: assert},
	}
}
