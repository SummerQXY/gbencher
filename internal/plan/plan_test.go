package plan_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/SummerQXY/gbencher/internal/plan"
	"github.com/SummerQXY/gbencher/internal/rule"
)

type fakeDeps struct {
	number      string
	org         string
	folder      string
	clusters    []any
	projectErr  error
	ancestorErr error
	clusterErr  error
}

func (d fakeDeps) ProjectNumber(context.Context, string) (string, error) {
	return d.number, d.projectErr
}

func (d fakeDeps) Ancestors(context.Context, string) (string, string, error) {
	return d.org, d.folder, d.ancestorErr
}

func (d fakeDeps) Clusters(context.Context, string) ([]any, error) {
	return d.clusters, d.clusterErr
}

func planRules() []*rule.Rule {
	return []*rule.Rule{
		{ID: "cis-gke-4.1.1", Scope: "cluster"},
		{ID: "cis-gcp-3.8", Scope: "project"},
		{ID: "cis-gcp-1.17", Scope: "organization", EvaluatePer: "organization"},
		{ID: "cis-gcp-3.6", Scope: "organization", EvaluatePer: "project"},
	}
}

func unitKeys(units []plan.Unit) []string {
	keys := make([]string, 0, len(units))
	for _, unit := range units {
		keys = append(keys, unit.Rule.ID+"|"+unit.Target.Key)
	}
	return keys
}

func TestBuild_ClusterAndOrganizationScopes(t *testing.T) {
	units, issues, err := plan.Build(context.Background(), planRules(), []string{"example-prod"}, fakeDeps{
		number: "123456789012", org: "111", clusters: []any{map[string]any{"name": "c1", "location": "asia-east1"}},
	})
	if err != nil || len(issues) != 0 {
		t.Fatalf("Build() = issues %v, err %v", issues, err)
	}
	want := []string{"cis-gcp-1.17|organizations/111", "cis-gcp-3.6|projects/example-prod",
		"cis-gcp-3.8|projects/example-prod", "cis-gke-4.1.1|projects/example-prod/locations/asia-east1/clusters/c1"}
	if got := unitKeys(units); !reflect.DeepEqual(got, want) {
		t.Fatalf("unit keys = %v, want %v", got, want)
	}
}

func TestBuild_NoClustersYieldsNotApplicableTarget(t *testing.T) {
	units, _, err := plan.Build(context.Background(), []*rule.Rule{{ID: "cluster-rule", Scope: "cluster"}}, []string{"example-prod"}, fakeDeps{number: "123", org: "111"})
	if err != nil || len(units) != 1 || units[0].Target.Key != "projects/example-prod" {
		t.Fatalf("Build() = %#v, %v", units, err)
	}
}

func TestBuild_ClusterEnumerationFailureYieldsOneUnit(t *testing.T) {
	rules := []*rule.Rule{{ID: "cluster-rule", Scope: "cluster"}}
	units, issues, err := plan.Build(context.Background(), rules, []string{"example-prod"}, fakeDeps{number: "123", org: "111", clusterErr: errors.New("unavailable")})
	if err != nil || len(units) != 1 || len(issues) == 0 || units[0].Target.Key != "projects/example-prod" {
		t.Fatalf("Build() = units %#v, issues %#v, err %v", units, issues, err)
	}
}

func TestBuild_OrgRuleWithEmptyOrganizationYieldsOneUnit(t *testing.T) {
	rules := []*rule.Rule{{ID: "org-rule", Scope: "organization", EvaluatePer: "organization"}}
	units, _, err := plan.Build(context.Background(), rules, []string{"example-prod"}, fakeDeps{number: "123"})
	if err != nil || len(units) != 1 || units[0].Target.Key != "organizations/" {
		t.Fatalf("Build() = %#v, %v", units, err)
	}
}

func TestBuild_AllProjectsUnresolvedReturnsError(t *testing.T) {
	_, issues, err := plan.Build(context.Background(), planRules(), []string{"example-prod"}, fakeDeps{projectErr: errors.New("unavailable")})
	if err == nil || len(issues) == 0 {
		t.Fatalf("Build() issues = %#v, err = %v; want issues and error", issues, err)
	}
}

func TestBuild_ProjectResolutionIssuesAreClassified(t *testing.T) {
	_, issues, _ := plan.Build(context.Background(), []*rule.Rule{{ID: "p", Scope: "project"}}, []string{"example-prod"}, fakeDeps{projectErr: errors.New("unavailable")})
	if len(issues) != 1 || issues[0].ProjectID != "example-prod" || issues[0].Kind != "project_unresolved" {
		t.Fatalf("issues = %#v", issues)
	}
}

func TestBuild_ClusterIssueIsClassified(t *testing.T) {
	_, issues, _ := plan.Build(context.Background(), []*rule.Rule{{ID: "c", Scope: "cluster"}}, []string{"example-prod"}, fakeDeps{number: "123", org: "111", clusterErr: errors.New("unavailable")})
	if len(issues) != 1 || issues[0].Kind != "clusters_unresolved" {
		t.Fatalf("issues = %#v", issues)
	}
}

func TestBuild_DuplicateProjectsProduceUniqueUnits(t *testing.T) {
	units, _, err := plan.Build(context.Background(), []*rule.Rule{{ID: "p", Scope: "project"}}, []string{"example-prod", "example-prod"}, fakeDeps{number: "123", org: "111"})
	if err != nil || len(units) != 1 {
		t.Fatalf("Build() = %#v, %v; want one unit", units, err)
	}
}

func TestBuild_MalformedClusterListYieldsOneProjectUnit(t *testing.T) {
	rules := []*rule.Rule{{ID: "c", Scope: "cluster"}}
	deps := fakeDeps{number: "123", org: "111", clusters: []any{map[string]any{"name": "c1", "location": "asia-east1"}, map[string]any{"name": "missing-location"}}}
	units, issues, err := plan.Build(context.Background(), rules, []string{"example-prod"}, deps)
	if err != nil || len(issues) != 1 || issues[0].Kind != "clusters_unresolved" || len(units) != 1 || units[0].Target.Key != "projects/example-prod" {
		t.Fatalf("Build() = units %#v, issues %#v, err %v", units, issues, err)
	}
}

func TestTarget_KindPerType(t *testing.T) {
	for _, tc := range []struct{ targetType, want string }{
		{"project", "cloudresourcemanager.googleapis.com/Project"},
		{"organization", "cloudresourcemanager.googleapis.com/Organization"},
		{"cluster", "container.googleapis.com/Cluster"},
	} {
		if got := (plan.Target{Type: tc.targetType}).Kind(); got != tc.want {
			t.Errorf("Kind(%q) = %q, want %q", tc.targetType, got, tc.want)
		}
	}
}
