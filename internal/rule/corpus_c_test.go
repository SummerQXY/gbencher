package rule_test

import (
	"testing"

	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/internal/rule/lint"
	"github.com/SummerQXY/gbencher/rules"
)

// loadAnyRule finds a rule by id across the entire embedded corpus, loaded once.
func loadAnyRule(t *testing.T, id string) *rule.Rule {
	t.Helper()
	pc := loadCorpus(t)
	fn, ok := pc.FileByRule[id]
	if !ok {
		t.Fatalf("rule %s not found in corpus", id)
	}
	return loadRule(t, fn, id)
}

func TestOrganizationRulesDeclareEvaluatePer(t *testing.T) {
	want := map[string]string{
		"cis-gcp-1.1.1": "organization",
		"cis-gcp-1.1.2": "organization",
		"cis-gcp-1.1.3": "organization",
		"cis-gcp-1.3":   "organization",
		"cis-gcp-1.4":   "organization",
		"cis-gcp-1.17":  "organization",
		"cis-gcp-2.2":   "organization",
		"cis-gcp-3.8":   "project",
	}
	for id, v := range want {
		if got := loadAnyRule(t, id).EvaluatePer; got != v {
			t.Errorf("%s: evaluate_per = %q, want %q", id, got, v)
		}
	}

	// Every other rule must not set evaluate_per to a non-empty value.
	pc := loadCorpus(t)
	for _, r := range pc.AllRules {
		if _, ok := want[r.ID]; ok {
			continue
		}
		if r.EvaluatePer != "" {
			t.Errorf("%s: evaluate_per = %q, but this rule is not in the expected organization set", r.ID, r.EvaluatePer)
		}
	}
}

func TestTemplateParamsAreConstrained(t *testing.T) {
	// 2.2 freshness_days must have Minimum 1, Maximum 365, nothing else.
	r22 := loadAnyRule(t, "cis-gcp-2.2")
	c := r22.ParamsConstraints["freshness_days"]
	if c.Minimum == nil || *c.Minimum != 1 {
		t.Errorf("cis-gcp-2.2: freshness_days minimum = %v, want 1", c.Minimum)
	}
	if c.Maximum == nil || *c.Maximum != 365 {
		t.Errorf("cis-gcp-2.2: freshness_days maximum = %v, want 365", c.Maximum)
	}
	if c.Pattern != "" {
		t.Errorf("cis-gcp-2.2: freshness_days pattern = %q, want empty", c.Pattern)
	}
	if c.MaxLength != nil {
		t.Errorf("cis-gcp-2.2: freshness_days max_length = %v, want nil", c.MaxLength)
	}
	if len(c.Enum) != 0 {
		t.Errorf("cis-gcp-2.2: freshness_days enum = %v, want empty", c.Enum)
	}

	// 5.7.2 namespace must have Pattern ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$, MaxLength 63, nothing else.
	r572 := loadAnyRule(t, "cis-gke-5.7.2")
	nc := r572.ParamsConstraints["namespace"]
	if nc.Pattern != `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` {
		t.Errorf("cis-gke-5.7.2: namespace pattern = %q, want ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", nc.Pattern)
	}
	if nc.MaxLength == nil || *nc.MaxLength != 63 {
		t.Errorf("cis-gke-5.7.2: namespace max_length = %v, want 63", nc.MaxLength)
	}
	if nc.Minimum != nil {
		t.Errorf("cis-gke-5.7.2: namespace minimum = %v, want nil", nc.Minimum)
	}
	if nc.Maximum != nil {
		t.Errorf("cis-gke-5.7.2: namespace maximum = %v, want nil", nc.Maximum)
	}
	if len(nc.Enum) != 0 {
		t.Errorf("cis-gke-5.7.2: namespace enum = %v, want empty", nc.Enum)
	}

	// Lint: the two rules must not produce params-template-unconstrained or
	// params-default-violates-constraint findings.
	corpusFiles := map[string]bool{
		"cis-gcp-foundation-v5.0.0/2-logging-monitoring.yaml":                  true,
		"cis-gke-v2.0.0/5b-managed-services-network-logging-auth-storage.yaml": true,
	}
	var files []*rule.File
	var violations []rule.Violation
	for fn := range corpusFiles {
		f, vs := loadCorpusFile(t, fn)
		files = append(files, f)
		violations = append(violations, vs...)
	}
	al := loadAllowlist(t)
	findings := lint.Run(files, violations, lint.Options{Allow: al})
	for _, f := range findings {
		if f.Code == "params-template-unconstrained" || f.Code == "params-default-violates-constraint" {
			t.Errorf("%s: %s: %s: %s", f.File, f.RuleID, f.Code, f.Message)
		}
	}

	// No evaluate-per finding anywhere in the whole corpus (embeds the check that
	// the lint cleanup is complete).
	allFiles, allViolations := loadAllCorpusFiles(t)
	allFindings := lint.Run(allFiles, allViolations, lint.Options{Allow: al})
	for _, f := range allFindings {
		if f.Code == "evaluate-per" {
			t.Errorf("%s: %s: %s: %s", f.File, f.RuleID, f.Code, f.Message)
		}
	}
}

func TestSharedVPCStepsDeclareCrossProject(t *testing.T) {
	pc := loadCorpus(t)
	type crossStep struct {
		rule string
		step string
	}
	wantCross := map[crossStep]bool{
		{rule: "cis-gke-5.6.1", step: "subnet"}:              true,
		{rule: "cis-gke-5.6.6", step: "effective_firewalls"}: true,
	}
	for _, r := range pc.AllRules {
		for _, s := range r.Collect {
			key := crossStep{rule: r.ID, step: s.ID}
			if wantCross[key] {
				if !s.CrossProject {
					t.Errorf("%s: %s: cross_project = false, want true", r.ID, s.ID)
				}
			} else if s.CrossProject {
				t.Errorf("%s: %s: cross_project = true, want false", r.ID, s.ID)
			}
		}
	}
}

// loadCorpusFile reads a single embedded corpus file and returns the parsed File and violations.
func loadCorpusFile(t *testing.T, relPath string) (*rule.File, []rule.Violation) {
	t.Helper()
	data, err := rules.FS.ReadFile(relPath)
	if err != nil {
		t.Fatalf("read embedded %s: %v", relPath, err)
	}
	f, vs, err := rule.ParseFile(relPath, data)
	if err != nil {
		t.Fatalf("ParseFile(%s): %v", relPath, err)
	}
	return f, vs
}

// loadAllowlist loads the embedded allowlist and fails the test on error.
func loadAllowlist(t *testing.T) *rule.Allowlist {
	t.Helper()
	al, err := rule.LoadAllowlist()
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	return al
}

// loadAllCorpusFiles returns every embedded corpus file and all violations.
func loadAllCorpusFiles(t *testing.T) ([]*rule.File, []rule.Violation) {
	t.Helper()
	pc := loadCorpus(t)
	seen := make(map[string]bool)
	var files []*rule.File
	var violations []rule.Violation
	for _, fn := range pc.FileByRule {
		if seen[fn] {
			continue
		}
		seen[fn] = true
		f, vs := loadCorpusFile(t, fn)
		files = append(files, f)
		violations = append(violations, vs...)
	}
	return files, violations
}
