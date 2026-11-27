package fixture_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/fixture"
	"github.com/SummerQXY/gbencher/internal/rule"
)

var gkeNetworkLoggingBlockedSources = map[string]struct {
	clusterFields []string
	collectors    map[string]string
}{
	"cis-gke-5.6.1": {
		clusterFields: []string{"networkConfig", "enableIntraNodeVisibility", "subnetwork"},
		collectors:    map[string]string{"subnet": "compute networks subnets describe"},
	},
	"cis-gke-5.6.2": {
		clusterFields: []string{"ipAllocationPolicy", "useIpAliases"},
	},
	"cis-gke-5.6.3": {
		clusterFields: []string{"privateClusterConfig", "controlPlaneEndpointsConfig", "masterAuthorizedNetworksConfig"},
	},
	"cis-gke-5.6.4": {
		clusterFields: []string{"privateClusterConfig", "controlPlaneEndpointsConfig", "masterAuthorizedNetworksConfig"},
	},
	"cis-gke-5.6.5": {
		clusterFields: []string{"nodePools", "privateClusterConfig", "defaultEnablePrivateNodes"},
	},
	"cis-gke-5.6.6": {
		clusterFields: []string{"networkConfig", "nodePools", "serviceAccount", "tags"},
		collectors:    map[string]string{"effective_firewalls": "compute networks get-effective-firewalls"},
	},
}

func TestGKENetworkLoggingFixtureBatchCoversSevenRules(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(gkeNetworkLoggingBlockedSources)+1 != 7 {
		t.Fatalf("network and logging rule list has %d entries, want 7", len(gkeNetworkLoggingBlockedSources)+1)
	}
	for ruleID, sources := range gkeNetworkLoggingBlockedSources {
		current, ok := set.Get(ruleID)
		if !ok {
			t.Errorf("rule %s not found", ruleID)
			continue
		}
		if len(current.Collect) != len(sources.collectors) {
			t.Errorf("rule %s has %d collectors, want %d", ruleID, len(current.Collect), len(sources.collectors))
		}
		for _, step := range current.Collect {
			command, ok := sources.collectors[step.ID]
			if !ok {
				t.Errorf("rule %s has unexpected collector %s", ruleID, step.ID)
				continue
			}
			if !strings.Contains(step.Gcloud, command) {
				t.Errorf("rule %s collector %s command = %q, want %q", ruleID, step.ID, step.Gcloud, command)
			}
		}
		for _, source := range sources.clusterFields {
			if !strings.Contains(ruleExpressions(current), source) {
				t.Errorf("rule %s does not reference cluster field %q", ruleID, source)
			}
		}
		if _, err := os.Stat(filepath.Join("..", "..", "testdata", "rules", ruleID)); !os.IsNotExist(err) {
			t.Errorf("blocked rule %s has a fixture directory", ruleID)
		}
	}
	current, ok := set.Get("cis-gke-5.6.7")
	if !ok {
		t.Fatal("rule cis-gke-5.6.7 not found")
	}
	cases, err := fixture.LoadDir(filepath.Join("..", "..", "testdata", "rules", current.ID))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for caseIndex, input := range cases {
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
			t.Errorf("cis-gke-5.6.7 is missing required %s case", status)
		}
	}
	verification, err := rule.ComputeVerification(set, filepath.Join("..", "..", "testdata", "rules"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for ruleID := range gkeNetworkLoggingBlockedSources {
		if got := verification.Rules[ruleID]; got != rule.VerificationNone {
			t.Errorf("blocked rule %s verification = %q, want none", ruleID, got)
		}
	}
	if got := verification.Rules["cis-gke-5.6.7"]; got != rule.VerificationFixture {
		t.Errorf("cis-gke-5.6.7 verification = %q, want fixture", got)
	}
}

func TestGKENetworkLoggingFixturesRespectResourceShape(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	current, ok := set.Get("cis-gke-5.6.7")
	if !ok {
		t.Fatal("rule cis-gke-5.6.7 not found")
	}
	cases, err := fixture.LoadDir(filepath.Join("..", "..", "testdata", "rules", current.ID))
	if err != nil {
		t.Fatal(err)
	}
	for caseIndex, input := range cases {
		if len(input.DisabledServices) > 0 {
			continue
		}
		ingresses, ok := input.Data["ingresses"].(map[string]any)
		if !ok || ingressListKind(ingresses) != "IngressList" {
			t.Errorf("case %d ingresses is not a networking.k8s.io/v1 IngressList", caseIndex)
			continue
		}
		certificates, ok := input.Data["managed_certs"].(map[string]any)
		if !ok || ingressListKind(certificates) != "ManagedCertificateList" {
			t.Errorf("case %d managed_certs is not a networking.gke.io/v1 ManagedCertificateList", caseIndex)
			continue
		}
		for _, object := range ingressListItems(t, caseIndex, ingresses) {
			if got, _ := object["apiVersion"].(string); got != "networking.k8s.io/v1" {
				t.Errorf("case %d Ingress apiVersion = %q", caseIndex, got)
			}
			if got, _ := object["kind"].(string); got != "Ingress" {
				t.Errorf("case %d Ingress kind = %q", caseIndex, got)
			}
			if !hasStringMetadata(object) {
				t.Errorf("case %d Ingress metadata lacks string name or namespace", caseIndex)
			}
			if _, ok := object["spec"].(map[string]any); !ok {
				t.Errorf("case %d Ingress spec is not an object", caseIndex)
			}
		}
		for _, object := range ingressListItems(t, caseIndex, certificates) {
			if got, _ := object["apiVersion"].(string); got != "networking.gke.io/v1" {
				t.Errorf("case %d ManagedCertificate apiVersion = %q", caseIndex, got)
			}
			if got, _ := object["kind"].(string); got != "ManagedCertificate" {
				t.Errorf("case %d ManagedCertificate kind = %q", caseIndex, got)
			}
			if !hasStringMetadata(object) {
				t.Errorf("case %d ManagedCertificate metadata lacks string name or namespace", caseIndex)
			}
			spec, ok := object["spec"].(map[string]any)
			domains, domainsOK := spec["domains"].([]any)
			if !ok || !domainsOK || len(domains) == 0 {
				t.Errorf("case %d ManagedCertificate spec.domains is not a non-empty list", caseIndex)
			}
			status, ok := object["status"].(map[string]any)
			if !ok {
				t.Errorf("case %d ManagedCertificate status is not an object", caseIndex)
			} else if _, ok := status["certificateStatus"].(string); !ok {
				t.Errorf("case %d ManagedCertificate status.certificateStatus is not a string", caseIndex)
			}
		}
	}
}

func ingressListItems(t *testing.T, caseIndex int, list map[string]any) []map[string]any {
	t.Helper()
	items, ok := list["items"].([]any)
	if !ok {
		t.Errorf("case %d resource list items is not an array", caseIndex)
		return nil
	}
	objects := make([]map[string]any, 0, len(items))
	for itemIndex, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			t.Errorf("case %d item %d is not an object", caseIndex, itemIndex)
			continue
		}
		objects = append(objects, object)
	}
	return objects
}

func hasStringMetadata(object map[string]any) bool {
	metadata, ok := object["metadata"].(map[string]any)
	if !ok {
		return false
	}
	_, nameOK := metadata["name"].(string)
	_, namespaceOK := metadata["namespace"].(string)
	return nameOK && namespaceOK
}

func ingressListKind(value map[string]any) string {
	apiVersion, _ := value["apiVersion"].(string)
	kind, _ := value["kind"].(string)
	if apiVersion == "networking.k8s.io/v1" && kind == "IngressList" {
		return kind
	}
	if apiVersion == "networking.gke.io/v1" && kind == "ManagedCertificateList" {
		return kind
	}
	return ""
}
