package rule_test

import (
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/rules"
)

// invariants is the shape of testdata/invariants.yaml.
type invariants struct {
	MustExistRules    []mustExistRule    `yaml:"must_exist_rules"`
	OnErrorEmptySteps []onErrorEmptyStep `yaml:"on_error_empty_steps"`
}

type mustExistRule struct {
	ID                string   `yaml:"id"`
	ForbidServices    []string `yaml:"forbid_services"`
	OnErrorEmptySteps []string `yaml:"on_error_empty_steps"`
}

type onErrorEmptyStep struct {
	Rule string `yaml:"rule"`
	Step string `yaml:"step"`
}

// loadInvariants reads testdata/invariants.yaml and returns its parsed form.
func loadInvariants(t *testing.T) *invariants {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "invariants.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read invariants: %v", err)
	}
	var inv invariants
	if err := yaml.Unmarshal(data, &inv); err != nil {
		t.Fatalf("parse invariants: %v", err)
	}
	return &inv
}

// parsedCorpus loads every rule file from the embedded corpus, building an
// index of rule id to source file and a list of all parsed rules. ParseFile
// errors on any corpus file make the test fail.
type parsedCorpus struct {
	FileByRule map[string]string // rule id → source file path relative to rules/
	AllRules   []*rule.Rule
}

func loadCorpus(t *testing.T) *parsedCorpus {
	t.Helper()
	dirs, err := rules.FS.ReadDir(".")
	if err != nil {
		t.Fatalf("list rules root: %v", err)
	}
	pc := &parsedCorpus{FileByRule: make(map[string]string)}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		entries, err := rules.FS.ReadDir(d.Name())
		if err != nil {
			t.Fatalf("list %s: %v", d.Name(), err)
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
				continue
			}
			rel := filepath.Join(d.Name(), e.Name())
			data, err := rules.FS.ReadFile(rel)
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			f, _, err := rule.ParseFile(rel, data)
			if err != nil {
				t.Fatalf("ParseFile(%s): %v", rel, err)
			}
			for _, r := range f.Rules {
				pc.FileByRule[r.ID] = rel
				pc.AllRules = append(pc.AllRules, r)
			}
		}
	}
	return pc
}

func TestMustExistRules_DoNotDeclareServicesAndUseEmpty(t *testing.T) {
	inv := loadInvariants(t)
	pc := loadCorpus(t)
	for _, m := range inv.MustExistRules {
		t.Run(m.ID, func(t *testing.T) {
			rel, ok := pc.FileByRule[m.ID]
			if !ok {
				t.Fatalf("rule %s not found in corpus", m.ID)
			}
			r := loadRule(t, rel, m.ID)

			for _, svc := range m.ForbidServices {
				for _, s := range r.Services {
					if s == svc {
						t.Errorf("%s declares %s", m.ID, svc)
					}
				}
			}
			for _, sid := range m.OnErrorEmptySteps {
				s := stepByID(t, r, sid)
				if s.OnError != "empty" {
					t.Errorf("%s.%s must use on_error: empty, got %q", m.ID, sid, s.OnError)
				}
			}
		})
	}
}

func stepByID(t *testing.T, r *rule.Rule, stepID string) *rule.Step {
	t.Helper()
	for i := range r.Collect {
		if r.Collect[i].ID == stepID {
			return &r.Collect[i]
		}
	}
	t.Fatalf("%s: step %q not found", r.ID, stepID)
	return nil
}

func TestOnErrorEmptyStepsMatchInvariants(t *testing.T) {
	inv := loadInvariants(t)
	pc := loadCorpus(t)

	// Build the expected set from invariants.yaml.
	want := make(map[string]bool)
	for _, p := range inv.OnErrorEmptySteps {
		want[p.Rule+"."+p.Step] = true
	}

	// Collect every on_error: empty step from every rule in the whole corpus.
	got := make(map[string]bool)
	for _, r := range pc.AllRules {
		for _, s := range r.Collect {
			if s.OnError == "empty" {
				got[r.ID+"."+s.ID] = true
			}
		}
	}

	for k := range want {
		if !got[k] {
			t.Errorf("%s: expected in on_error_empty_steps but not found in corpus", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("%s: found in corpus but not in invariants on_error_empty_steps", k)
		}
	}
}
