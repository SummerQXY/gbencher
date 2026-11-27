package fixture_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/fixture"
	"github.com/SummerQXY/gbencher/internal/report"
	"github.com/SummerQXY/gbencher/internal/rule"
)

var gkePolicyRuleIDs = []string{
	"cis-gke-4.2.1", "cis-gke-4.3.1", "cis-gke-4.3.2", "cis-gke-4.4.1",
	"cis-gke-4.4.2", "cis-gke-4.5.1", "cis-gke-4.6.1", "cis-gke-4.6.2",
	"cis-gke-4.6.3", "cis-gke-4.6.4",
}

var gkePolicyFixtureRuleIDs = []string{
	"cis-gke-4.2.1", "cis-gke-4.4.1", "cis-gke-4.6.1", "cis-gke-4.6.2",
	"cis-gke-4.6.3", "cis-gke-4.6.4",
}

var gkePolicyBlockedRuleIDs = []string{
	"cis-gke-4.3.1", "cis-gke-4.3.2", "cis-gke-4.4.2", "cis-gke-4.5.1",
}

func TestGKEPolicyAvailableFixturesCoverRequiredBranches(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(gkePolicyRuleIDs) != 10 {
		t.Fatalf("policy rule list has %d entries, want 10", len(gkePolicyRuleIDs))
	}
	for _, ruleID := range gkePolicyRuleIDs {
		if _, ok := set.Get(ruleID); !ok {
			t.Errorf("rule %s not found", ruleID)
		}
	}
	for _, ruleID := range gkePolicyFixtureRuleIDs {
		t.Run(ruleID, func(t *testing.T) {
			current, _ := set.Get(ruleID)
			cases, err := fixture.LoadDir(filepath.Join("..", "..", "testdata", "rules", ruleID))
			if err != nil {
				t.Fatal(err)
			}
			seen := make(map[string]bool)
			for _, input := range cases {
				got, err := fixture.Evaluate(input, current)
				if err != nil {
					t.Fatalf("evaluate fixture: %v", err)
				}
				want := append([]fixture.Expect(nil), input.Expect...)
				sort.Slice(got, func(i, j int) bool { return got[i].ResourceKey < got[j].ResourceKey })
				sort.Slice(want, func(i, j int) bool { return want[i].ResourceKey < want[j].ResourceKey })
				if len(got) != len(want) {
					t.Fatalf("got %d results, want %d", len(got), len(want))
				}
				for i := range got {
					if got[i] != want[i] {
						t.Fatalf("result[%d] = %+v, want %+v", i, got[i], want[i])
					}
					seen[got[i].Status] = true
				}
			}
			statuses := []string{"PASS", "FAIL"}
			if ruleID == "cis-gke-4.2.1" {
				statuses = []string{"PASS", "REVIEW"}
			}
			for _, status := range statuses {
				if !seen[status] {
					t.Errorf("missing %s fixture", status)
				}
			}
			emptyStatus := "NOT_APPLICABLE"
			if ruleID != "cis-gke-4.6.4" && !seen[emptyStatus] {
				t.Errorf("missing empty-population %s fixture", emptyStatus)
			}
			if strings.TrimSpace(current.Check.ReviewWhen) != "" && !seen["REVIEW"] {
				t.Error("missing REVIEW fixture for contextual rule")
			}
		})
	}

	verification, err := rule.ComputeVerification(set, filepath.Join("..", "..", "testdata", "rules"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, ruleID := range gkePolicyBlockedRuleIDs {
		if _, err := os.Stat(filepath.Join("..", "..", "testdata", "rules", ruleID)); !os.IsNotExist(err) {
			t.Errorf("rule %s has a public fixture directory without public fixture data", ruleID)
		}
		if got := verification.Rules[ruleID]; got != rule.VerificationNone {
			t.Errorf("rule %s verification = %q, want none without public fixtures", ruleID, got)
		}
	}
}

func TestGKEPolicyFixturesDeclareSourceProvenance(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, ruleID := range gkePolicyFixtureRuleIDs {
		current, ok := set.Get(ruleID)
		if !ok {
			t.Fatalf("rule %s not found", ruleID)
		}
		cases, err := fixture.LoadDir(filepath.Join("..", "..", "testdata", "rules", ruleID))
		if err != nil {
			t.Fatal(err)
		}
		for i, input := range cases {
			if len(input.Meta.Provenance) != len(current.Collect) {
				t.Errorf("%s case %d provenance has %d steps, want %d", ruleID, i, len(input.Meta.Provenance), len(current.Collect))
			}
			for _, step := range current.Collect {
				if got := input.Meta.Provenance[step.ID]; got != "schema" {
					t.Errorf("%s case %d step %s provenance = %q, want schema", ruleID, i, step.ID, got)
				}
			}
		}
	}
}

func TestGKEPolicyFixturesCoverOptionalFields(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, ruleID := range []string{"cis-gke-4.2.1", "cis-gke-4.6.1", "cis-gke-4.6.2", "cis-gke-4.6.3"} {
		current, _ := set.Get(ruleID)
		cases, err := fixture.LoadDir(filepath.Join("..", "..", "testdata", "rules", ruleID))
		if err != nil {
			t.Fatal(err)
		}
		foundOmittedOptional := false
		for _, input := range cases {
			if hasOptionalOmission(input.Data) {
				foundOmittedOptional = true
			}
			if _, err := fixture.Evaluate(input, current); err != nil {
				t.Errorf("%s optional-field case: %v", ruleID, err)
			}
		}
		if !foundOmittedOptional {
			t.Errorf("%s has no fixture with omitted optional Kubernetes fields", ruleID)
		}
	}
}

func TestGKEPolicyEmptyPopulationPassesForPodResourceRule(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	current, ok := set.Get("cis-gke-4.6.4")
	if !ok {
		t.Fatal("rule cis-gke-4.6.4 not found")
	}
	cases, err := fixture.LoadDir(filepath.Join("..", "..", "testdata", "rules", current.ID))
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range cases {
		pods, podsOK := input.Data["pods"].(map[string]any)["items"].([]any)
		replicasets, replicasetsOK := input.Data["replicasets"].(map[string]any)["items"].([]any)
		if !podsOK || !replicasetsOK || len(pods) != 0 || len(replicasets) != 0 {
			continue
		}
		got, err := fixture.Evaluate(input, current)
		if err != nil {
			t.Fatal(err)
		}
		want := fixture.Expect{
			RuleID:      current.ID,
			ResourceKey: "projects/example-project/locations/us-central1/clusters/example-cluster",
			Status:      "PASS",
		}
		if len(got) != 1 || got[0] != want {
			t.Fatalf("empty-population result = %+v, want [%+v]", got, want)
		}
		return
	}
	t.Fatal("missing schema-provenance fixture with empty Pods and ReplicaSets and target-level PASS")
}

func TestGKEPolicyPodKeysRemainStable(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, ruleID := range []string{"cis-gke-4.4.1", "cis-gke-4.6.2", "cis-gke-4.6.3", "cis-gke-4.6.4"} {
		current, ok := set.Get(ruleID)
		if !ok {
			t.Fatalf("rule %s not found", ruleID)
		}
		cases, err := fixture.LoadDir(filepath.Join("..", "..", "testdata", "rules", ruleID))
		if err != nil {
			t.Fatal(err)
		}
		foundRollout := false
		for _, input := range cases {
			pods, ok := input.Data["pods"].(map[string]any)["items"].([]any)
			if !ok || len(pods) != 2 {
				continue
			}
			replicasets, ok := input.Data["replicasets"].(map[string]any)["items"].([]any)
			if !ok || len(replicasets) != 2 {
				continue
			}
			foundRollout = true
			podReplicaSets := make(map[string]bool, 2)
			for _, pod := range pods {
				podObject := pod.(map[string]any)
				metadata := podObject["metadata"].(map[string]any)
				if metadata["namespace"] != "payments" || (metadata["name"] != "api-old" && metadata["name"] != "api-new") {
					t.Fatalf("rollout pod metadata = %v, want api-old/api-new in payments", metadata)
				}
				owners := metadata["ownerReferences"].([]any)
				if len(owners) != 1 {
					t.Fatalf("pod %s has %d owner references, want one ReplicaSet owner", metadata["name"], len(owners))
				}
				owner := owners[0].(map[string]any)
				if owner["kind"] != "ReplicaSet" || owner["controller"] != true {
					t.Fatalf("pod %s owner = %v, want controller ReplicaSet", metadata["name"], owner)
				}
				podReplicaSets[owner["name"].(string)] = true
			}
			if len(podReplicaSets) != 2 {
				t.Fatalf("rollout Pods reference %v, want two distinct ReplicaSets", podReplicaSets)
			}
			replicaSetNames := make(map[string]bool, 2)
			for _, item := range replicasets {
				replicaset := item.(map[string]any)
				metadata := replicaset["metadata"].(map[string]any)
				replicaSetNames[metadata["name"].(string)] = true
				if metadata["namespace"] != "payments" {
					t.Fatalf("ReplicaSet %s namespace = %v, want payments", metadata["name"], metadata["namespace"])
				}
				owners := metadata["ownerReferences"].([]any)
				if len(owners) != 1 {
					t.Fatalf("ReplicaSet %s has %d owner references, want one Deployment owner", metadata["name"], len(owners))
				}
				owner := owners[0].(map[string]any)
				if owner["kind"] != "Deployment" || owner["name"] != "api" || owner["controller"] != true {
					t.Fatalf("ReplicaSet %s owner = %v, want controller Deployment/api", metadata["name"], owner)
				}
			}
			if len(replicaSetNames) != 2 || !sameKeys(replicaSetNames, podReplicaSets) {
				t.Fatalf("ReplicaSet names %v do not match Pod owner names %v", replicaSetNames, podReplicaSets)
			}

			got, err := fixture.Evaluate(input, current)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 {
				t.Fatalf("rollout results = %+v, want two Pod results", got)
			}
			for _, result := range got {
				if result.ResourceKey != "payments/Deployment/api" || result.Status != "PASS" {
					t.Fatalf("rollout result = %+v, want stable PASS key", result)
				}
			}
			targetKey := "projects/example-project/locations/us-central1/clusters/example-cluster"
			resultItems := make([]report.Result, 0, len(got))
			for i, pod := range pods {
				metadata := pod.(map[string]any)["metadata"].(map[string]any)
				resultItems = append(resultItems, report.Result{
					Rule: report.RuleRef{
						ID: current.ID, Ref: current.Ref, Title: current.Title,
						Profile: current.Profile, Severity: current.Severity, Mode: current.Mode,
					},
					Target:     report.TargetRef{Type: "cluster", Key: targetKey, ProjectID: "example-project", Cluster: "example-cluster"},
					Resource:   report.ResourceRef{Kind: "k8s.io/Pod", Name: metadata["name"].(string), Key: got[i].ResourceKey},
					Collection: report.Collection{Status: "SUCCEEDED"},
					Assessment: report.Assessment{Status: got[i].Status},
				})
			}
			assembled, err := report.Assemble(report.Input{
				Rules:   []*rule.Rule{current},
				Units:   []report.UnitRef{{RuleID: current.ID, TargetKey: targetKey, Outcome: "evaluated"}},
				Results: resultItems,
			})
			if err != nil {
				t.Fatalf("merge ReplicaSet rollout: %v", err)
			}
			if len(assembled.Results) != 1 || assembled.Results[0].Resource.Members != 2 || assembled.Results[0].Assessment.Status != "PASS" {
				t.Fatalf("merged rollout result = %+v, want one PASS result with two members", assembled.Results)
			}
		}
		if !foundRollout {
			t.Errorf("%s has no two-Pod, two-ReplicaSet rollout fixture", ruleID)
		}
	}
}

func sameKeys(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if !right[key] {
			return false
		}
	}
	return true
}

func hasOptionalOmission(value any) bool {
	switch current := value.(type) {
	case map[string]any:
		if _, ok := current["name"]; ok {
			if _, labels := current["labels"]; !labels {
				return true
			}
			if _, annotations := current["annotations"]; !annotations {
				return true
			}
		}
		if _, ok := current["containers"]; ok {
			if _, securityContext := current["securityContext"]; !securityContext {
				return true
			}
			if _, env := current["env"]; !env {
				return true
			}
			if _, envFrom := current["envFrom"]; !envFrom {
				return true
			}
		}
		for _, child := range current {
			if hasOptionalOmission(child) {
				return true
			}
		}
	case []any:
		for _, child := range current {
			if hasOptionalOmission(child) {
				return true
			}
		}
	}
	return false
}
