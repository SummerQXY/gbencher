package fixture_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/rule"
)

var gkeRegistryIAMRuleSources = map[string][]string{
	"cis-gke-5.1.1": {"services", "repositories"},
	"cis-gke-5.1.2": {"repositories", "repo_iam_policies", "project_iam_policy"},
	"cis-gke-5.1.3": {"binauthz_policy", "ctx.cluster.binaryAuthorization", "ctx.cluster.location", "ctx.cluster.name"},
	"cis-gke-5.2.1": {"iam_policy", "ctx.cluster.autopilot", "ctx.cluster.name", "ctx.cluster.nodePools"},
	"cis-gke-5.2.2": {"ctx.cluster.autopilot", "ctx.cluster.name", "ctx.cluster.nodePools", "ctx.cluster.workloadIdentityConfig"},
}

var clusterSourcePathPattern = regexp.MustCompile(`(?:ctx|data)\.cluster(?:\.\??([A-Za-z_][A-Za-z0-9_]*))`)

func TestGKERegistryIAMFixtureBatchCoversFiveRules(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(gkeRegistryIAMRuleSources) != 5 {
		t.Fatalf("registry and IAM rule list has %d entries, want 5", len(gkeRegistryIAMRuleSources))
	}
	for ruleID := range gkeRegistryIAMRuleSources {
		current, ok := set.Get(ruleID)
		if !ok {
			t.Errorf("rule %s not found", ruleID)
			continue
		}
		gotSources := ruleFixtureSources(current)
		wantSources := append([]string(nil), gkeRegistryIAMRuleSources[ruleID]...)
		sort.Strings(gotSources)
		sort.Strings(wantSources)
		if strings.Join(gotSources, "\n") != strings.Join(wantSources, "\n") {
			t.Errorf("%s rule sources = %v, want %v", ruleID, gotSources, wantSources)
		}
		if _, err := os.Stat(filepath.Join("..", "..", "testdata", "rules", ruleID)); !os.IsNotExist(err) {
			t.Errorf("blocked rule %s has a fixture directory", ruleID)
		}
	}
	verification, err := rule.ComputeVerification(set, filepath.Join("..", "..", "testdata", "rules"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for ruleID := range gkeRegistryIAMRuleSources {
		if got := verification.Rules[ruleID]; got != rule.VerificationNone {
			t.Errorf("blocked rule %s has verification %q, want none", ruleID, got)
		}
	}
}

func ruleFixtureSources(current *rule.Rule) []string {
	sources := make([]string, 0, len(current.Collect)+4)
	for _, step := range current.Collect {
		sources = append(sources, step.ID)
	}
	expressions := []string{current.Check.Assert, current.Check.ReviewWhen}
	if current.Resource != nil {
		expressions = append(expressions, current.Resource.From, current.Resource.Filter, current.Resource.Name, current.Resource.Key)
	}
	expressions = append(expressions, current.Evidence...)
	clusterFields := make(map[string]struct{})
	for _, expression := range expressions {
		for _, match := range clusterSourcePathPattern.FindAllStringSubmatch(expression, -1) {
			clusterFields["ctx.cluster."+match[1]] = struct{}{}
		}
	}
	for field := range clusterFields {
		sources = append(sources, field)
	}
	return sources
}
