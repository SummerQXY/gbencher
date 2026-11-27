package plan_test

import (
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/plan"
	"github.com/SummerQXY/gbencher/internal/rule"
)

func testGuard() plan.Guard {
	return plan.Guard{Allow: &rule.Allowlist{
		Gcloud: []rule.GcloudEntry{
			{Path: []string{"compute", "project-info", "describe"}, Bind: []rule.Bind{rule.BindProject}},
			{Path: []string{"projects", "describe"}, Bind: []rule.Bind{rule.BindProject}},
			{Path: []string{"projects", "list"}, Bind: []rule.Bind{rule.BindOrganization}},
			{Path: []string{"compute", "instances", "list"}, Bind: []rule.Bind{rule.BindDerived}},
			{Path: []string{"compute", "instances", "describe"}, Bind: []rule.Bind{rule.BindOrganization}},
			{Path: []string{"container", "clusters", "list"}, Bind: []rule.Bind{rule.BindProject}},
		},
		GcloudFlags:      []string{"--project", "--organization", "--filter", "--format", "--quiet"},
		KubectlVerbs:     []string{"get", "api-resources", "version"},
		KubectlResources: []string{"pods"},
		KubectlFlags:     []string{"--namespace", "-o"},
		REST:             []rule.RESTHost{{Host: "bigquery.googleapis.com", Methods: []string{"GET"}}, {Host: "admin.googleapis.com", Methods: []string{"GET"}}},
	}}
}

func targetProject() plan.Target {
	return plan.Target{Type: "project", Key: "projects/example-prod", ProjectID: "example-prod"}
}

func TestGuard_DeleteVerbRejected(t *testing.T) {
	err := testGuard().CheckGcloud([]string{"compute", "instances", "delete", "vm-1"}, targetProject(), false, false)
	if err == nil || !strings.Contains(err.Error(), "command not allowed") {
		t.Fatalf("CheckGcloud() error = %v, want command rejection", err)
	}
}

func TestGuard_PositionalProjectMismatchRejected(t *testing.T) {
	err := testGuard().CheckGcloud([]string{"compute", "project-info", "describe", "other"}, targetProject(), false, false)
	if err == nil {
		t.Fatal("CheckGcloud() accepted a different positional project")
	}
}

func TestGuard_FlagValueFormRejected(t *testing.T) {
	err := testGuard().CheckGcloud([]string{"projects", "describe", "--project", "other"}, targetProject(), false, false)
	if err == nil {
		t.Fatal("CheckGcloud() accepted a separated project flag value")
	}
}

func TestGuard_PositionalProjectCannotConflictWithProjectFlag(t *testing.T) {
	err := testGuard().CheckGcloud([]string{"projects", "describe", "other", "--project=example-prod"}, targetProject(), false, false)
	if err == nil {
		t.Fatal("CheckGcloud() accepted conflicting positional and flag projects")
	}
}

func TestGuard_DerivedOnlyWithForeach(t *testing.T) {
	argv := []string{"compute", "instances", "list"}
	if err := testGuard().CheckGcloud(argv, targetProject(), false, true); err != nil {
		t.Fatalf("CheckGcloud() rejected foreach command: %v", err)
	}
	if err := testGuard().CheckGcloud(argv, targetProject(), false, false); err == nil {
		t.Fatal("CheckGcloud() accepted a derived binding outside foreach")
	}
}

func TestGuard_CrossProjectAllowsOtherProjectAndReports(t *testing.T) {
	argv := []string{"container", "clusters", "list", "--project=other"}
	if err := testGuard().CheckGcloud(argv, targetProject(), true, false); err != nil {
		t.Fatalf("CheckGcloud() rejected cross-project command: %v", err)
	}
	if err := testGuard().CheckGcloud(argv, targetProject(), false, false); err == nil {
		t.Fatal("CheckGcloud() accepted cross-project command without declaration")
	}
	resourceArgv := []string{"projects", "describe", "example-prod", "--filter=projects/other"}
	if err := testGuard().CheckGcloud(resourceArgv, targetProject(), false, false); err == nil {
		t.Fatal("CheckGcloud() accepted a resource reference to another project")
	}
	if err := testGuard().CheckGcloud(resourceArgv, targetProject(), true, false); err != nil {
		t.Fatalf("CheckGcloud() rejected declared cross-project resource: %v", err)
	}
}

func TestGuard_ForbiddenFlagRejected(t *testing.T) {
	for _, flag := range []string{"-q", "--credential-file-override=f"} {
		argv := append([]string{"projects", "describe", "example-prod"}, flag)
		if err := testGuard().CheckGcloud(argv, targetProject(), false, false); err == nil {
			t.Errorf("CheckGcloud() accepted forbidden flag %q", flag)
		}
	}
	for _, flag := range []string{"-s", "-sapi.example.com"} {
		argv := []string{"get", "pods", flag}
		if err := testGuard().CheckKubectl(argv, plan.Target{Type: "cluster", ProjectID: "example-prod"}); err == nil {
			t.Errorf("CheckKubectl() accepted forbidden flag %q", flag)
		}
	}
}

func TestGuard_OrganizationTargetIgnoresProjectReferences(t *testing.T) {
	target := plan.Target{Type: "organization", Key: "organizations/111", Organization: "111"}
	if err := testGuard().CheckGcloud([]string{"compute", "instances", "describe", "--organization=111", "--format=projects/example-prod"}, target, false, false); err != nil {
		t.Fatalf("CheckGcloud() rejected project references under organization target: %v", err)
	}
}

func TestGuard_OrganizationFilterRequiresExactParentID(t *testing.T) {
	target := plan.Target{Type: "organization", Key: "organizations/111", Organization: "111"}
	for _, filter := range []string{
		"parent.id=111evil",
		"parent.id=111 OR parent.id=222",
		"parent.id=111 OR name=unrelated",
		"parent.id=111 || name=unrelated",
		"parent.id=111 or name=unrelated",
		"-parent.id=111",
		"-(parent.id=111)",
		"-((parent.id=111))",
		"name=unrelated AND -(parent.id=111)",
		"name=unrelated -parent.id=111",
		"name=unrelated -(parent.id=111)",
		`name="unrelated parent.id=111 project"`,
		"name=unrelated-parent.id=111",
	} {
		err := testGuard().CheckGcloud([]string{"projects", "list", "--filter=" + filter}, target, false, false)
		if err == nil {
			t.Errorf("CheckGcloud() accepted filter %q", filter)
		}
	}
	if err := testGuard().CheckGcloud([]string{"projects", "list", "--filter=parent.id=111"}, target, false, false); err != nil {
		t.Fatalf("CheckGcloud() rejected exact organization filter: %v", err)
	}
	for _, filter := range []string{
		"parent.id=111 AND name=unrelated-project",
		"parent.id=111 name=unrelated-project",
	} {
		if err := testGuard().CheckGcloud([]string{"projects", "list", "--filter=" + filter}, target, false, false); err != nil {
			t.Errorf("CheckGcloud() rejected ordinary hyphenated filter value %q: %v", filter, err)
		}
	}
}

func TestGuard_KubectlRejectsDeleteVerb(t *testing.T) {
	if err := testGuard().CheckKubectl([]string{"delete", "pods"}, plan.Target{Type: "cluster", ProjectID: "example-prod"}); err == nil {
		t.Fatal("CheckKubectl() accepted delete")
	}
}

func TestGuard_APIProjectScopeAndAllowlist(t *testing.T) {
	guard := testGuard()
	if err := guard.CheckAPI("GET", "https://bigquery.googleapis.com/projects/example-prod/datasets", targetProject()); err != nil {
		t.Fatalf("CheckAPI() rejected target project URL: %v", err)
	}
	if err := guard.CheckAPI("GET", "https://bigquery.googleapis.com/projects/example-prod?parent=projects%2Fexample-prod", targetProject()); err != nil {
		t.Fatalf("CheckAPI() rejected a matching query project: %v", err)
	}
	if err := guard.CheckAPI("GET", "https://bigquery.googleapis.com/projects/example-prod?parent=projects%2Fother", targetProject()); err == nil {
		t.Fatal("CheckAPI() accepted a query reference to another project")
	}
	if err := guard.CheckAPI("GET", "https://bigquery.googleapis.com/projects/example-prod?parent=%ZZ", targetProject()); err == nil {
		t.Fatal("CheckAPI() accepted invalid query encoding")
	}
	if err := guard.CheckAPI("GET", "https://bigquery.googleapis.com/projects/other/datasets", targetProject()); err == nil {
		t.Fatal("CheckAPI() accepted a different project")
	}
	if err := guard.CheckAPI("GET", "https://bigquery.googleapis.com/%70rojects/other/datasets", targetProject()); err == nil {
		t.Fatal("CheckAPI() accepted an encoded path to a different project")
	}
	if err := guard.CheckAPI("GET", "https://example.com/projects/example-prod/datasets", targetProject()); err == nil {
		t.Fatal("CheckAPI() accepted an unlisted host")
	}
}

func TestGuard_APIRejectsEncodedPathSeparatorWithoutPanic(t *testing.T) {
	if err := testGuard().CheckAPI("GET", "https://bigquery.googleapis.com/v2/projects%2Fother", targetProject()); err == nil {
		t.Fatal("CheckAPI() accepted encoded project path separator")
	}
}

func TestGuard_APIRejectsDeeplyEncodedProjectReferences(t *testing.T) {
	guard := testGuard()
	for _, rawURL := range []string{
		"https://bigquery.googleapis.com/v2/projects%252Fother/datasets",
		"https://bigquery.googleapis.com/v2/projects/example-prod/datasets?parent=projects%252Fother",
	} {
		if err := guard.CheckAPI("GET", rawURL, targetProject()); err == nil {
			t.Errorf("CheckAPI() accepted deeply encoded cross-project reference in %q", rawURL)
		}
	}
}

func TestGuard_APIRejectsExcessivelyEncodedProjectReferences(t *testing.T) {
	guard := testGuard()
	for _, rawURL := range []string{
		"https://bigquery.googleapis.com/v2/projects%252525252525252Fother/datasets",
		"https://bigquery.googleapis.com/v2/projects/example-prod/datasets?parent=projects%252525252525252Fother",
	} {
		if err := guard.CheckAPI("GET", rawURL, targetProject()); err == nil {
			t.Errorf("CheckAPI() accepted excessively encoded project reference in %q", rawURL)
		}
	}
	if err := guard.CheckAPI("GET", "https://bigquery.googleapis.com/v2/projects/example-prod/datasets?label=rate%25value", targetProject()); err != nil {
		t.Fatalf("CheckAPI() rejected a query value containing a literal percent sign: %v", err)
	}
}

func TestGuard_APIBodyRejectsDeeplyEncodedProjectReference(t *testing.T) {
	body := []byte(`{"parent":"projects%252525252Fother"}`)
	if err := testGuard().CheckAPIBody(body, targetProject()); err == nil {
		t.Fatal("CheckAPIBody() accepted a deeply encoded cross-project reference")
	}
}

func TestGuard_OrganizationTargetRejectsUnboundProjectAndMismatchedOrganizationReferences(t *testing.T) {
	target := plan.Target{Type: "organization", Key: "organizations/111", Organization: "111"}
	guard := testGuard()
	for _, rawURL := range []string{
		"https://bigquery.googleapis.com/projects/other/datasets",
		"https://bigquery.googleapis.com/v2/organizations/111/projects/other/datasets",
		"https://bigquery.googleapis.com/projects/other?parent=projects%2Fthird",
	} {
		if err := guard.CheckAPI("GET", rawURL, target); err == nil {
			t.Errorf("CheckAPI() accepted an unbound project reference in %q", rawURL)
		}
	}
	for _, rawURL := range []string{
		"https://bigquery.googleapis.com/v2/organizations/222/folders",
		"https://bigquery.googleapis.com/v2/folders?parent=organizations%2F222",
	} {
		if err := guard.CheckAPI("GET", rawURL, target); err == nil {
			t.Errorf("CheckAPI() accepted an organization reference outside the target in %q", rawURL)
		}
	}
	for _, rawURL := range []string{
		"https://bigquery.googleapis.com/v2/organizations/111/folders",
		"https://bigquery.googleapis.com/v2/folders?parent=organizations%2F111",
		"https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer",
	} {
		if err := guard.CheckAPI("GET", rawURL, target); err != nil {
			t.Errorf("CheckAPI() rejected a target-bound or Workspace request %q: %v", rawURL, err)
		}
	}
	if err := guard.CheckAPI("GET", "https://bigquery.googleapis.com/v2/folders?parent=%ZZ", target); err == nil {
		t.Fatal("CheckAPI() accepted invalid query encoding for organization target")
	}
}

func TestGuard_OrganizationTargetChecksBodyReferences(t *testing.T) {
	target := plan.Target{Type: "organization", Key: "organizations/111", Organization: "111"}
	guard := testGuard()
	for _, body := range [][]byte{
		[]byte(`{"parent":"projects/other"}`),
		[]byte(`{"parent":"organizations/222"}`),
		[]byte(`{"projects/other":"x"}`),
		[]byte(`{"organizations/222":"x"}`),
	} {
		if err := guard.CheckAPIBody(body, target); err == nil {
			t.Errorf("CheckAPIBody() accepted an unbound reference in %s", body)
		}
	}
	for _, body := range [][]byte{
		[]byte(`{"parent":"organizations/111"}`),
		[]byte(`{"customer":"my_customer"}`),
		[]byte(`{"organizations/111":"x"}`),
		[]byte(`{"ordinary":"x"}`),
	} {
		if err := guard.CheckAPIBody(body, target); err != nil {
			t.Errorf("CheckAPIBody() rejected a target-bound body %s: %v", body, err)
		}
	}
}

func TestGuard_ProjectTargetChecksBodyObjectKeys(t *testing.T) {
	target := targetProject()
	target.Organization = "111"
	guard := testGuard()
	for _, body := range [][]byte{
		[]byte(`{"projects/other":"x"}`),
		[]byte(`{"organizations/222":"x"}`),
	} {
		if err := guard.CheckAPIBody(body, target); err == nil {
			t.Errorf("CheckAPIBody() accepted an out-of-scope object key in %s", body)
		}
	}
	for _, body := range [][]byte{
		[]byte(`{"projects/example-prod":"x"}`),
		[]byte(`{"organizations/111":"x"}`),
		[]byte(`{"ordinary":"x"}`),
	} {
		if err := guard.CheckAPIBody(body, target); err != nil {
			t.Errorf("CheckAPIBody() rejected a target-bound object key in %s: %v", body, err)
		}
	}
}
