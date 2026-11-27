package rule_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/SummerQXY/gbencher/internal/rule"
)

func TestVerification_RequiresCapturedClusterContext(t *testing.T) {
	current := &rule.Rule{
		ID:    "cluster-context",
		Scope: "cluster",
		Check: rule.Check{Assert: "ctx.cluster.enabled"},
	}
	for _, provenance := range []map[string]string{
		nil,
		{"cluster": "schema"},
		{"cluster": "handwritten"},
	} {
		got := computeVerificationFixture(t, current, provenance)
		if got != rule.VerificationNone {
			t.Errorf("provenance %v produced %q, want none", provenance, got)
		}
	}
	for _, source := range []string{"captured", "captured+mutated"} {
		got := computeVerificationFixture(t, current, map[string]string{"cluster": source})
		if got != rule.VerificationFixture {
			t.Errorf("provenance %q produced %q, want fixture", source, got)
		}
	}
	stringOnly := &rule.Rule{
		ID:    "cluster-context-string",
		Check: rule.Check{Assert: `"ctx.cluster.enabled" == "ctx.cluster.enabled"`},
	}
	if got := computeVerificationFixture(t, stringOnly, nil); got != rule.VerificationFixture {
		t.Fatalf("string literal verification = %q, want fixture", got)
	}
}

func TestVerification_RequiresCapturedDataClusterContext(t *testing.T) {
	current := &rule.Rule{
		ID:      "data-cluster-context",
		Scope:   "cluster",
		Collect: []rule.Step{{ID: "nodes", Kubectl: "get nodes"}},
		Check:   rule.Check{Assert: "data.cluster.enabled"},
	}
	tests := []struct {
		name       string
		provenance map[string]string
		want       rule.VerificationLevel
	}{
		{
			name:       "missing cluster provenance",
			provenance: map[string]string{"nodes": "schema"},
			want:       rule.VerificationNone,
		},
		{
			name: "schema cluster provenance",
			provenance: map[string]string{
				"cluster": "schema",
				"nodes":   "schema",
			},
			want: rule.VerificationNone,
		},
		{
			name: "captured cluster provenance",
			provenance: map[string]string{
				"cluster": "captured",
				"nodes":   "schema",
			},
			want: rule.VerificationFixture,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := computeVerificationFixture(t, current, tt.provenance); got != tt.want {
				t.Fatalf("verification = %q, want %q", got, tt.want)
			}
		})
	}

	mixed := *current
	mixed.ID = "mixed-cluster-context"
	mixed.Check.Assert = "ctx.cluster.enabled && data.cluster.enabled"
	for _, tt := range []struct {
		name       string
		provenance map[string]string
		want       rule.VerificationLevel
	}{
		{
			name:       "missing provenance for mixed references",
			provenance: map[string]string{"nodes": "schema"},
			want:       rule.VerificationNone,
		},
		{
			name: "captured provenance for mixed references",
			provenance: map[string]string{
				"cluster": "captured+mutated",
				"nodes":   "schema",
			},
			want: rule.VerificationFixture,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := computeVerificationFixture(t, &mixed, tt.provenance); got != tt.want {
				t.Fatalf("verification = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerification_RejectsSchemaClusterContextForGcloudData(t *testing.T) {
	current := &rule.Rule{
		ID:    "cluster-context-gcloud",
		Scope: "cluster",
		Collect: []rule.Step{{
			ID:     "settings",
			Gcloud: "container clusters describe",
		}},
		Check: rule.Check{Assert: "ctx.cluster.enabled && data.settings.enabled"},
	}
	got := computeVerificationFixture(t, current, map[string]string{
		"cluster":  "schema",
		"settings": "captured",
	})
	if got != rule.VerificationNone {
		t.Fatalf("verification = %q, want none", got)
	}
}

func TestVerification_ChecksClusterAndStepProvenanceSeparately(t *testing.T) {
	current := &rule.Rule{
		ID:    "cluster-context-mixed",
		Scope: "cluster",
		Collect: []rule.Step{{
			ID:     "settings",
			Gcloud: "container clusters describe",
		}},
		Check: rule.Check{Assert: "ctx.cluster.enabled && data.settings.enabled"},
	}
	tests := []struct {
		name       string
		provenance map[string]string
		want       rule.VerificationLevel
	}{
		{
			name: "cluster captured and step handwritten",
			provenance: map[string]string{
				"cluster":  "captured",
				"settings": "handwritten",
			},
			want: rule.VerificationNone,
		},
		{
			name: "cluster and step captured",
			provenance: map[string]string{
				"cluster":  "captured+mutated",
				"settings": "captured",
			},
			want: rule.VerificationFixture,
		},
		{
			name: "step captured without cluster provenance",
			provenance: map[string]string{
				"settings": "captured",
			},
			want: rule.VerificationNone,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := computeVerificationFixture(t, current, tt.provenance); got != tt.want {
				t.Fatalf("verification = %q, want %q", got, tt.want)
			}
		})
	}

	kubectlRule := &rule.Rule{
		ID:      "kubectl-schema",
		Scope:   "cluster",
		Collect: []rule.Step{{ID: "nodes", Kubectl: "get nodes"}},
		Check:   rule.Check{Assert: "true"},
	}
	if got := computeVerificationFixture(t, kubectlRule, map[string]string{
		"nodes": "schema",
	}); got != rule.VerificationFixture {
		t.Fatalf("kubectl schema verification = %q, want fixture", got)
	}
}

func computeVerificationFixture(t *testing.T, current *rule.Rule, provenance map[string]string) rule.VerificationLevel {
	t.Helper()
	fixturesDir := t.TempDir()
	ruleDir := filepath.Join(fixturesDir, current.ID)
	if err := os.MkdirAll(ruleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pass", "fail"} {
		data := []byte(`{"meta":{"provenance":` + marshalProvenance(t, provenance) + `}}`)
		if err := os.WriteFile(filepath.Join(ruleDir, name+".json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := rule.ComputeVerification(&rule.Set{Rules: []*rule.Rule{current}}, fixturesDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return got.Rules[current.ID]
}

func marshalProvenance(t *testing.T, provenance map[string]string) string {
	t.Helper()
	data, err := json.Marshal(provenance)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestComputeVerification_NoFixturesIsNone(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	got, err := rule.ComputeVerification(set, filepath.Join(t.TempDir(), "missing"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != len(set.Rules) {
		t.Fatalf("verification count = %d, want %d", len(got.Rules), len(set.Rules))
	}
	for id, level := range got.Rules {
		if level != rule.VerificationNone {
			t.Errorf("%s verification = %q, want none", id, level)
		}
	}
}

func TestComputeVerification_HandwrittenFixturesStayNone(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	id := set.Rules[0].ID
	dir := filepath.Join(t.TempDir(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pass", "fail"} {
		data := []byte("{\"meta\":{\"provenance\":{\"step\":\"handwritten\"}}}\n")
		if err := os.WriteFile(filepath.Join(dir, name+".json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := rule.ComputeVerification(set, filepath.Dir(dir), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Rules[id] != rule.VerificationNone {
		t.Fatalf("%s verification = %q, want none", id, got.Rules[id])
	}
}
