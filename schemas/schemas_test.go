package schemas_test

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/profiles"
	"github.com/SummerQXY/gbencher/schemas"
)

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// onlyIssue fails unless err holds exactly one schema issue, located at path and
// mentioning want. A single issue also shows the document is valid in every other respect.
func onlyIssue(t *testing.T, err error, path, want string) {
	t.Helper()
	got := schemas.Issues(err)
	if len(got) != 1 || got[0].Path != path || !strings.Contains(got[0].Message, want) {
		t.Fatalf("want exactly one issue at %q mentioning %q, got %+v (error: %v)", path, want, got, err)
	}
}

func TestRuleSchema_RejectsRemovedCollectors(t *testing.T) {
	// The control document uses dsl_version, evaluate_per, params_constraints, resource.key and
	// cross_project, so accepting it shows that the rejections below come from the removed
	// step types and capabilities alone.
	if err := schemas.ValidateYAML("rule", mustRead(t, "../testdata/schemas/rule-valid.yaml")); err != nil {
		t.Fatalf("control document rejected: %v", err)
	}

	cases := []struct {
		fixture   string
		keyword   string   // must appear in the error text when not empty
		wantPaths []string // distinct issue paths, in Issues order
	}{
		{"rule-node-exec.yaml", "node_exec", []string{"/rules/0/collect/0"}},
		{"rule-shell.yaml", "shell", []string{"/rules/0/collect/0"}},
		{"rule-removed-capabilities.yaml", "", []string{"/rules/0/requires/0", "/rules/0/requires/1"}},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			err := schemas.ValidateYAML("rule", mustRead(t, "../testdata/schemas/"+c.fixture))
			if err == nil || !strings.Contains(err.Error(), c.keyword) {
				t.Fatalf("want a violation mentioning %q, got %v", c.keyword, err)
			}
			var paths []string
			for _, is := range schemas.Issues(err) {
				if !slices.Contains(paths, is.Path) {
					paths = append(paths, is.Path)
				}
			}
			if !slices.Equal(paths, c.wantPaths) {
				t.Fatalf("issue paths = %v, want %v (error: %v)", paths, c.wantPaths, err)
			}
		})
	}
}

func TestRuleSchema_OrganizationRuleRequiresEvaluatePer(t *testing.T) {
	err := schemas.ValidateYAML("rule", mustRead(t, "../testdata/schemas/rule-organization-without-evaluate-per.yaml"))
	onlyIssue(t, err, "/rules/0", "evaluate_per")
}

func TestRuleSchema_NonOrganizationRuleRejectsEvaluatePer(t *testing.T) {
	err := schemas.ValidateYAML("rule", mustRead(t, "../testdata/schemas/rule-project-with-evaluate-per.yaml"))
	if err == nil || !strings.Contains(err.Error(), "evaluate_per") {
		t.Fatalf("want evaluate_per violation, got %v", err)
	}
	onlyIssue(t, err, "/rules/0/evaluate_per", "not allowed")
}

func TestRuleSchema_DSLVersionRequired(t *testing.T) {
	err := schemas.ValidateYAML("rule", mustRead(t, "../testdata/schemas/rule-without-dsl-version.yaml"))
	onlyIssue(t, err, "", "dsl_version")
}

func TestProfileSchema_AcceptsDefaultProfile(t *testing.T) {
	if err := schemas.ValidateYAML("profile", profiles.Default); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
	// Profiles may also arrive as JSON.
	if err := schemas.ValidateYAML("profile", []byte(`{"dsl_version": 1, "levels": ["L1"]}`)); err != nil {
		t.Fatalf("JSON profile rejected: %v", err)
	}
}

func TestProfileSchema_RejectsForbiddenKeys(t *testing.T) {
	cases := []struct{ fixture, path, key string }{
		{"profile-exemptions.yaml", "", "exemptions"},
		{"profile-rules-dirs.yaml", "", "rules_dirs"},
		{"profile-override-check.yaml", "/overrides/cis-gcp-3.6", "check"},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			err := schemas.ValidateYAML("profile", mustRead(t, "../testdata/schemas/"+c.fixture))
			if err == nil || !strings.Contains(err.Error(), c.key) {
				t.Fatalf("want violation mentioning %q, got %v", c.key, err)
			}
			onlyIssue(t, err, c.path, c.key)
		})
	}
}

func TestReportSchema_AcceptsSample(t *testing.T) {
	if err := schemas.ValidateJSON("report", mustRead(t, "../testdata/golden/report.sample.json")); err != nil {
		t.Fatalf("sample report rejected: %v", err)
	}
}

func TestReportSchema_RejectsResultWithoutFindingKey(t *testing.T) {
	err := schemas.ValidateJSON("report", mustRead(t, "../testdata/schemas/report-result-without-finding-key.json"))
	onlyIssue(t, err, "/results/0", "finding_key")
}

func TestReportSchema_RejectsFailOverFailedCollection(t *testing.T) {
	fixture := mustRead(t, "../testdata/schemas/report-fail-over-failed-collection.json")
	err := schemas.ValidateJSON("report", fixture)
	if err == nil {
		t.Fatal("FAIL over FAILED collection was accepted")
	}
	issues := schemas.Issues(err)
	if len(issues) == 0 || !strings.HasPrefix(issues[0].Path, "/results/0") {
		t.Fatalf("issue does not point to result: %+v", issues)
	}
	valid := bytes.ReplaceAll(fixture, []byte(`"status": "FAILED"`), []byte(`"status": "PARTIAL"`))
	if err := schemas.ValidateJSON("report", valid); err != nil {
		t.Fatalf("FAIL over PARTIAL collection rejected: %v", err)
	}
}

func TestCatalogSchema_AcceptsSample(t *testing.T) {
	if err := schemas.ValidateJSON("catalog", mustRead(t, "../testdata/golden/catalog.sample.json")); err != nil {
		t.Fatalf("sample catalog rejected: %v", err)
	}
}

func TestIssues_ReportsPathAndMessageForRefNumber(t *testing.T) {
	// An unquoted ref such as 6.1 is a YAML float; the issue must point at the field.
	err := schemas.ValidateYAML("rule", mustRead(t, "../testdata/schemas/rule-ref-number.yaml"))
	onlyIssue(t, err, "/rules/0/ref", "got number, want string")

	if got := schemas.Issues(nil); got != nil {
		t.Errorf("Issues(nil) = %+v, want nil", got)
	}
	if got := schemas.Issues(errors.New("not a schema violation")); got != nil {
		t.Errorf("Issues(non-schema error) = %+v, want nil", got)
	}
}

func TestSchemas_CompileUnknownNameIsError(t *testing.T) {
	if sch, err := schemas.Compile("nope"); err == nil || sch != nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("Compile: want an error naming the schema, got schema=%v err=%v", sch, err)
	}
	if err := schemas.ValidateJSON("nope", []byte("{}")); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("ValidateJSON: want an error naming the schema, got %v", err)
	}
	if err := schemas.ValidateYAML("nope", []byte("{}")); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("ValidateYAML: want an error naming the schema, got %v", err)
	}
}
