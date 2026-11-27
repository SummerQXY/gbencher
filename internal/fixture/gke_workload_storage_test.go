package fixture_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/fixture"
	"github.com/SummerQXY/gbencher/internal/rule"
)

var gkeWorkloadStorageBlockedInputs = map[string][]string{
	"cis-gke-5.7.1":  {"ctx.cluster.?loggingConfig", "ctx.cluster.?monitoringConfig"},
	"cis-gke-5.7.2":  {"ctx.cluster.?autopilot", "ctx.cluster.?nodePools", "p.?config.?imageType", "get daemonsets --namespace=", "data.cos_auditd_ds"},
	"cis-gke-5.8.1":  {"ctx.cluster.?masterAuth.?clientCertificateConfig", "ctx.cluster.?masterAuth.?clientCertificate", "ctx.cluster.?masterAuth.?clientKey"},
	"cis-gke-5.8.2":  {"ctx.cluster.?authenticatorGroupsConfig", "ctx.organization_domain", "get clusterrolebindings", "get rolebindings --all-namespaces", "data.crb", "data.rb"},
	"cis-gke-5.8.3":  {"ctx.cluster.?legacyAbac"},
	"cis-gke-5.9.2":  {"ctx.cluster.?nodePools", "r.?config.?bootDiskKmsKey"},
	"cis-gke-5.10.1": {"ctx.cluster.?enableKubernetesAlpha", "ctx.cluster.?expireTime"},
	"cis-gke-5.10.2": {"ctx.cluster.?autopilot", "ctx.cluster.?nodePools", "p.?config.?labels", "p.?config.?sandboxConfig"},
	"cis-gke-5.10.3": {"ctx.cluster.?securityPostureConfig.?mode", "ctx.cluster.?securityPostureConfig.?vulnerabilityMode"},
}

func TestGKEWorkloadStorageFixtureBatchCoversTenRules(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(gkeWorkloadStorageBlockedInputs)+1 != 10 {
		t.Fatalf("workload and storage source inventory has %d rules, want 10", len(gkeWorkloadStorageBlockedInputs)+1)
	}
	verification, err := rule.ComputeVerification(set, filepath.Join("..", "..", "testdata", "rules"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for ruleID, inputs := range gkeWorkloadStorageBlockedInputs {
		current, ok := set.Get(ruleID)
		if !ok {
			t.Errorf("rule %s not found", ruleID)
			continue
		}
		actual := ruleExpressions(current)
		for _, input := range inputs {
			if !strings.Contains(actual, input) {
				t.Errorf("rule %s does not reference required source %q", ruleID, input)
			}
		}
		if _, err := os.Stat(filepath.Join("..", "..", "testdata", "rules", ruleID)); !os.IsNotExist(err) {
			t.Errorf("blocked rule %s has a fixture directory", ruleID)
		}
		if got := verification.Rules[ruleID]; got != rule.VerificationNone {
			t.Errorf("blocked rule %s verification = %q, want none", ruleID, got)
		}
	}
	current, ok := set.Get("cis-gke-5.9.1")
	if !ok {
		t.Fatal("rule cis-gke-5.9.1 not found")
	}
	if len(current.Collect) != 1 || current.Collect[0].Kubectl != "get storageclasses -o json" {
		t.Fatalf("cis-gke-5.9.1 collectors = %+v, want one StorageClass list collector", current.Collect)
	}
	cases, err := fixture.LoadDir(filepath.Join("..", "..", "testdata", "rules", current.ID))
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 5 {
		t.Fatalf("cis-gke-5.9.1 has %d fixtures, want 5 required branches", len(cases))
	}
	disabledServiceCases := 0
	for _, input := range cases {
		if len(input.DisabledServices) == 0 {
			continue
		}
		disabledServiceCases++
		if len(input.DisabledServices) != 1 || input.DisabledServices[0] != "container.googleapis.com" {
			t.Errorf("disabled service fixture services = %v, want only container.googleapis.com", input.DisabledServices)
		}
		if len(input.Data) != 0 || len(input.CollectionErrors) != 0 {
			t.Errorf("disabled service fixture includes collector output or errors")
		}
	}
	if disabledServiceCases != 1 {
		t.Errorf("cis-gke-5.9.1 has %d disabled service fixtures, want 1", disabledServiceCases)
	}
	if got := verification.Rules[current.ID]; got != rule.VerificationFixture {
		t.Errorf("cis-gke-5.9.1 verification = %q, want fixture", got)
	}
}

func TestGKEWorkloadStorageFixturesUseSchemaInputs(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	current, ok := set.Get("cis-gke-5.9.1")
	if !ok {
		t.Fatal("rule cis-gke-5.9.1 not found")
	}
	cases, err := fixture.LoadDir(filepath.Join("..", "..", "testdata", "rules", current.ID))
	if err != nil {
		t.Fatal(err)
	}
	for caseIndex, input := range cases {
		if len(input.DisabledServices) > 0 {
			if len(input.DisabledServices) != 1 || input.DisabledServices[0] != "container.googleapis.com" {
				t.Errorf("case %d disabled services = %v, want only container.googleapis.com", caseIndex, input.DisabledServices)
			}
			if len(input.Meta.Provenance) != 0 {
				t.Errorf("case %d service-disabled provenance has %d entries, want none", caseIndex, len(input.Meta.Provenance))
			}
			continue
		}
		if got := input.Meta.Provenance["storage_classes"]; got != "schema" {
			t.Errorf("case %d storage_classes provenance = %q, want schema", caseIndex, got)
		}
		if len(input.Meta.Provenance) != 1 {
			t.Errorf("case %d provenance has %d entries, want one", caseIndex, len(input.Meta.Provenance))
		}
		classes, ok := input.Data["storage_classes"].(map[string]any)
		if !ok || classes["apiVersion"] != "v1" || classes["kind"] != "StorageClassList" {
			t.Errorf("case %d storage_classes is not a core/v1 StorageClassList", caseIndex)
		}
	}
}
func TestGKEWorkloadStorageFixturesCoverRequiredBranches(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	current, ok := set.Get("cis-gke-5.9.1")
	if !ok {
		t.Fatal("rule cis-gke-5.9.1 not found")
	}
	cases, err := fixture.LoadDir(filepath.Join("..", "..", "testdata", "rules", current.ID))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	seenDisabledService := false
	for caseIndex, input := range cases {
		if len(input.DisabledServices) > 0 {
			seenDisabledService = true
		}
		got, err := fixture.Evaluate(input, current)
		if err != nil {
			t.Fatalf("evaluate case %d: %v", caseIndex, err)
		}
		if len(got) != len(input.Expect) {
			t.Errorf("case %d produced %d results, want %d", caseIndex, len(got), len(input.Expect))
			continue
		}
		for i := range got {
			if got[i] != input.Expect[i] {
				t.Errorf("case %d result[%d] = %+v, want %+v", caseIndex, i, got[i], input.Expect[i])
			}
			seen[got[i].Status] = true
		}
	}
	for _, status := range []string{"PASS", "FAIL", "REVIEW", "NOT_APPLICABLE"} {
		if !seen[status] {
			t.Errorf("cis-gke-5.9.1 is missing required %s case", status)
		}
	}
	if !seenDisabledService {
		t.Error("cis-gke-5.9.1 is missing a disabled container API case")
	}
}
