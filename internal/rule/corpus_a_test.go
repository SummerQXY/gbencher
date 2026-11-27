package rule_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/celenv"
	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/rules"
)

// corpusFiles lists the embedded paths of every rule file in the corpus.
var corpusFiles = []string{
	"cis-gcp-foundation-v5.0.0/1-iam.yaml",
	"cis-gcp-foundation-v5.0.0/2-logging-monitoring.yaml",
	"cis-gcp-foundation-v5.0.0/3-networking.yaml",
	"cis-gcp-foundation-v5.0.0/4-virtual-machines.yaml",
	"cis-gcp-foundation-v5.0.0/5-storage.yaml",
	"cis-gcp-foundation-v5.0.0/6a-cloud-sql-mysql-postgresql.yaml",
	"cis-gcp-foundation-v5.0.0/6b-cloud-sql-sqlserver-instance.yaml",
	"cis-gcp-foundation-v5.0.0/7-bigquery.yaml",
	"cis-gcp-foundation-v5.0.0/8-dataproc.yaml",
	"cis-gke-v2.0.0/3-worker-nodes.yaml",
	"cis-gke-v2.0.0/4-policies.yaml",
	"cis-gke-v2.0.0/5a-managed-services-registry-iam-kms-nodes.yaml",
	"cis-gke-v2.0.0/5b-managed-services-network-logging-auth-storage.yaml",
}

// loadRule reads the rule file at relPath from the embedded FS and returns the rule
// with the given id. ParseFile violations are logged but do not fail the test.
func loadRule(t *testing.T, relPath string, id string) *rule.Rule {
	t.Helper()
	data, err := rules.FS.ReadFile(relPath)
	if err != nil {
		t.Fatalf("read embedded %s: %v", relPath, err)
	}
	f, vs, err := rule.ParseFile(relPath, data)
	if err != nil {
		t.Fatalf("ParseFile(%s): %v", relPath, err)
	}
	if len(vs) > 0 {
		t.Logf("%s has %d violation(s)", relPath, len(vs))
	}
	for _, r := range f.Rules {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not found in %s", id, relPath)
	return nil
}

// assertEval compiles the rule's assert and review_when CEL expressions and
// evaluates them against resource with the rule's Params as the params variable.
// It checks that the results match wantAssert and wantReview.
func assertEval(t *testing.T, r *rule.Rule, resource map[string]any, wantAssert, wantReview bool) {
	t.Helper()
	env, err := celenv.New(true)
	if err != nil {
		t.Fatalf("celenv.New: %v", err)
	}
	vars := map[string]any{
		"r":      resource,
		"params": r.Params,
		"data":   map[string]any{},
		"ctx":    map[string]any{},
	}

	evalBool := func(expr string) bool {
		ast, iss := env.Compile(expr)
		if iss != nil && iss.Err() != nil {
			t.Fatalf("compile %q: %v", expr, iss.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			t.Fatalf("program %q: %v", expr, err)
		}
		out, _, err := prg.Eval(vars)
		if err != nil {
			t.Fatalf("evaluate %q: %v", expr, err)
		}
		b, ok := out.Value().(bool)
		if !ok {
			t.Fatalf("%q = %v, want bool", expr, out.Value())
		}
		return b
	}

	gotAssert := evalBool(r.Check.Assert)
	if gotAssert != wantAssert {
		t.Errorf("%s: assert = %v, want %v", r.ID, gotAssert, wantAssert)
	}

	if r.Check.ReviewWhen != "" {
		gotReview := evalBool(r.Check.ReviewWhen)
		if gotReview != wantReview {
			t.Errorf("%s: review_when = %v, want %v", r.ID, gotReview, wantReview)
		}
	}
}

func TestCorpusFilesDeclareDSLVersion(t *testing.T) {
	for _, path := range corpusFiles {
		data, err := rules.FS.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		f, vs, err := rule.ParseFile(path, data)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", path, err)
		}
		for _, v := range vs {
			if strings.Contains(v.Message, "dsl_version") {
				t.Logf("%s: dsl_version violation remains: %s", path, v.Message)
			}
		}
		if f.DSLVersion != 1 {
			t.Errorf("%s: DSLVersion = %d, want 1", path, f.DSLVersion)
		}
	}
}

func TestNoVerifyFieldsTags(t *testing.T) {
	for _, path := range corpusFiles {
		data, err := rules.FS.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		f, vs, err := rule.ParseFile(path, data)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", path, err)
		}
		for _, v := range vs {
			t.Logf("%s: violation %s: %s", path, v.Path, v.Message)
		}
		for _, r := range f.Rules {
			if slices.Contains(r.Tags, "verify-fields") {
				t.Errorf("%s: %s still has verify-fields tag", path, r.ID)
			}
		}
	}
}

func TestWorkerNodeRules_COSProxyBehavior(t *testing.T) {
	for _, id := range []string{"cis-gke-3.1.1", "cis-gke-3.1.2", "cis-gke-3.1.3", "cis-gke-3.1.4"} {
		r := loadRule(t, "cis-gke-v2.0.0/3-worker-nodes.yaml", id)
		cos := map[string]any{"status": map[string]any{"nodeInfo": map[string]any{"osImage": "Container-Optimized OS from Google"}}}
		ubuntu := map[string]any{"status": map[string]any{"nodeInfo": map[string]any{"osImage": "Ubuntu 22.04"}}}
		assertEval(t, r, cos, true, false)
		assertEval(t, r, ubuntu, true, true)
	}
}

func TestWorkerNodeRules_NoNodeExecNoRequires(t *testing.T) {
	for _, id := range []string{"cis-gke-3.1.1", "cis-gke-3.1.2", "cis-gke-3.1.3", "cis-gke-3.1.4"} {
		r := loadRule(t, "cis-gke-v2.0.0/3-worker-nodes.yaml", id)
		if len(r.Collect) != 1 {
			t.Errorf("%s: want exactly 1 collect step, got %d", id, len(r.Collect))
			continue
		}
		s := r.Collect[0]
		if s.ID != "nodes" {
			t.Errorf("%s: collect step id = %q, want nodes", id, s.ID)
		}
		if s.Kubectl != "get nodes -o json" {
			t.Errorf("%s: collect step kubectl = %q, want get nodes -o json", id, s.Kubectl)
		}
		for _, rt := range r.Requires {
			if rt == "node-exec" {
				t.Errorf("%s: requires still contains node-exec", id)
			}
		}
		for _, s := range r.Collect {
			for _, rt := range s.Requires {
				if rt == "node-exec" {
					t.Errorf("%s: collect step %s requires still contains node-exec", id, s.ID)
				}
			}
		}
	}
}
