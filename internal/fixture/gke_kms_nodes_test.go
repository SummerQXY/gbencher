package fixture_test

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/rule"
)

var gkeKMSNodeRuleInputs = map[string]struct {
	expressions []string
	document    []string
}{
	"cis-gke-5.3.1": {
		expressions: []string{"ctx.cluster.?databaseEncryption.?state", "ctx.cluster.?databaseEncryption.?keyName", "ctx.cluster.?databaseEncryption.?currentState"},
		document:    []string{"databaseEncryption.state", "databaseEncryption.currentState", "databaseEncryption.keyName"},
	},
	"cis-gke-5.4.1": {
		expressions: []string{"ctx.cluster.?nodePools.orValue([])", "ctx.cluster.?autopilot.?enabled.orValue(false)", "ctx.cluster.workloadIdentityConfig.workloadPool", "r.?config.?workloadMetadataConfig.?mode", "disable-legacy-endpoints"},
		document:    []string{"nodePools", "workloadMetadataConfig.mode", "disable-legacy-endpoints", "workloadIdentityConfig.workloadPool"},
	},
	"cis-gke-5.5.1": {
		expressions: []string{"ctx.cluster.?nodePools.orValue([])", "r.?config.?imageType.orValue(\"\")"},
		document:    []string{"nodePools", "config.imageType"},
	},
	"cis-gke-5.5.2": {
		expressions: []string{"ctx.cluster.?nodePools.orValue([])", "r.?management.?autoRepair.orValue(false)"},
		document:    []string{"nodePools", "management.autoRepair"},
	},
	"cis-gke-5.5.3": {
		expressions: []string{"ctx.cluster.?nodePools.orValue([])", "r.?management.?autoUpgrade.orValue(false)", "ctx.cluster.releaseChannel"},
		document:    []string{"nodePools", "management.autoUpgrade", "releaseChannel"},
	},
	"cis-gke-5.5.4": {
		expressions: []string{"ctx.cluster.?releaseChannel.?channel.orValue(\"UNSPECIFIED\")"},
		document:    []string{"releaseChannel.channel"},
	},
	"cis-gke-5.5.5": {
		expressions: []string{"ctx.cluster.?autopilot.?enabled.orValue(false)", "ctx.cluster.?shieldedNodes.?enabled.orValue(false)"},
		document:    []string{"autopilot.enabled", "shieldedNodes.enabled"},
	},
	"cis-gke-5.5.6": {
		expressions: []string{"ctx.cluster.?nodePools.orValue([])", "r.?config.?shieldedInstanceConfig.?enableIntegrityMonitoring.orValue(false)"},
		document:    []string{"nodePools", "enableIntegrityMonitoring"},
	},
	"cis-gke-5.5.7": {
		expressions: []string{"ctx.cluster.?nodePools.orValue([])", "r.?config.?shieldedInstanceConfig.?enableSecureBoot.orValue(false)"},
		document:    []string{"nodePools", "enableSecureBoot"},
	},
}

var gkeKMSNodeClusterFields = map[string][]string{
	"cis-gke-5.3.1": {"databaseEncryption.currentState", "databaseEncryption.keyName", "databaseEncryption.state"},
	"cis-gke-5.4.1": {"autopilot.enabled", "name", "nodePools", "workloadIdentityConfig.workloadPool"},
	"cis-gke-5.5.1": {"autopilot.enabled", "name", "nodePools"},
	"cis-gke-5.5.2": {"autopilot.enabled", "name", "nodePools"},
	"cis-gke-5.5.3": {"autopilot.enabled", "name", "nodePools", "releaseChannel"},
	"cis-gke-5.5.4": {"releaseChannel.channel"},
	"cis-gke-5.5.5": {"autopilot.enabled", "shieldedNodes.enabled"},
	"cis-gke-5.5.6": {"autopilot.enabled", "name", "nodePools"},
	"cis-gke-5.5.7": {"autopilot.enabled", "name", "nodePools"},
}

var clusterFieldPattern = regexp.MustCompile(`ctx\.cluster(?:\.\??[A-Za-z_][A-Za-z0-9_]*)+`)

func TestGKEKMSNodeFixtureBatchCoversNineRules(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(gkeKMSNodeRuleInputs) != 9 {
		t.Fatalf("KMS and node rule list has %d entries, want 9", len(gkeKMSNodeRuleInputs))
	}
	for ruleID, inputs := range gkeKMSNodeRuleInputs {
		current, ok := set.Get(ruleID)
		if !ok {
			t.Errorf("rule %s not found", ruleID)
			continue
		}
		if current.Scope != "cluster" {
			t.Errorf("rule %s scope = %q, want cluster", ruleID, current.Scope)
		}
		if len(current.Collect) != 0 {
			t.Errorf("rule %s has explicit collect steps; expected engine-provided cluster context", ruleID)
		}
		actual := ruleExpressions(current)
		for _, expression := range inputs.expressions {
			if !strings.Contains(actual, expression) {
				t.Errorf("rule %s does not reference expected input expression %q", ruleID, expression)
			}
		}
	}
}

func TestGKEKMSNodeRulesHaveExactClusterFieldDependencies(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(gkeKMSNodeClusterFields) != 9 {
		t.Fatalf("cluster field inventory has %d rules, want 9", len(gkeKMSNodeClusterFields))
	}
	for ruleID, want := range gkeKMSNodeClusterFields {
		current, ok := set.Get(ruleID)
		if !ok {
			t.Errorf("rule %s not found", ruleID)
			continue
		}
		got := clusterFields(current)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s cluster fields = %v, want exactly %v", ruleID, got, want)
		}
	}
}

func clusterFields(current *rule.Rule) []string {
	return clusterFieldsFromText(ruleExpressions(current))
}

func clusterFieldsFromText(value string) []string {
	fields := make(map[string]struct{})
	for _, match := range clusterFieldPattern.FindAllString(value, -1) {
		path := strings.TrimPrefix(match, "ctx.cluster.")
		path = strings.ReplaceAll(path, "?", "")
		path = strings.TrimSuffix(path, ".orValue")
		fields[path] = struct{}{}
	}
	result := make([]string, 0, len(fields))
	for field := range fields {
		isPrefix := false
		for candidate := range fields {
			if strings.HasPrefix(candidate, field+".") {
				isPrefix = true
				break
			}
		}
		if isPrefix {
			continue
		}
		result = append(result, field)
	}
	sort.Strings(result)
	return result
}

func ruleSourceLine(doc, ruleID string) string {
	for _, line := range strings.Split(doc, "\n") {
		if strings.Contains(line, "`"+ruleID+"`") {
			return line
		}
	}
	return ""
}

func ruleExpressions(current *rule.Rule) string {
	var expressions []string
	for _, step := range current.Collect {
		expressions = append(expressions, step.Foreach, step.Gcloud, step.Kubectl)
	}
	if current.Resource != nil {
		expressions = append(expressions, current.Resource.From, current.Resource.Filter, current.Resource.Name, current.Resource.Key)
	}
	expressions = append(expressions, current.Check.Assert, current.Check.ReviewWhen)
	expressions = append(expressions, current.Evidence...)
	return strings.Join(expressions, "\n")
}
