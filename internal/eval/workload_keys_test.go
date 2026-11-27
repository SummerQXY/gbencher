package eval_test

import (
	"context"
	"testing"

	"github.com/SummerQXY/gbencher/internal/eval"
	"github.com/SummerQXY/gbencher/internal/rule"
)

func TestGKENodeResourceKeysUseNodePool(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"cis-gke-3.1.1", "cis-gke-3.1.2", "cis-gke-3.1.3", "cis-gke-3.1.4"} {
		t.Run(id, func(t *testing.T) {
			r, ok := set.Get(id)
			if !ok {
				t.Fatalf("rule %q not found", id)
			}
			got := expandKeys(t, r, map[string]any{"nodes": nodeList("node-before", "node-after")})
			want := []string{"pool-a", "pool-a"}
			if !equalStrings(got, want) {
				t.Fatalf("keys = %#v, want %#v", got, want)
			}
		})
	}
}

func TestGKEPodResourceKeysUseTopLevelController(t *testing.T) {
	pods := map[string]any{"items": []any{
		pod("shop", "web-old", "ReplicaSet", "web-7d9f"),
		pod("shop", "web-new", "ReplicaSet", "web-8a2c"),
		pod("shop", "worker", "ReplicaSet", "worker-6bc1"),
		pod("payments", "web", "ReplicaSet", "web-8a2c"),
		pod("shop", "api-deployment", "Deployment", "api"),
		pod("shop", "api-daemonset", "DaemonSet", "api"),
		pod("shop", "db-0", "StatefulSet", "db"),
	}}
	replicasets := map[string]any{"items": []any{
		replicaSet("shop", "web-7d9f", "Deployment", "web"),
		replicaSet("shop", "web-8a2c", "Deployment", "web"),
		replicaSet("shop", "worker-6bc1", "Deployment", "worker"),
		replicaSet("payments", "web-8a2c", "Deployment", "web"),
	}}
	want := []string{"shop/Deployment/web", "shop/Deployment/web", "shop/Deployment/worker", "payments/Deployment/web", "shop/Deployment/api", "shop/DaemonSet/api", "shop/StatefulSet/db"}
	for _, id := range podKeyRuleIDs {
		t.Run(id, func(t *testing.T) {
			got := expandKeys(t, loadPodKeyRule(t, id), map[string]any{"pods": pods, "replicasets": replicasets})
			if !equalStrings(got, want) {
				t.Fatalf("keys = %#v, want %#v", got, want)
			}
		})
	}
}

func TestGKEPodResourceKeysUseControllerOwnerReference(t *testing.T) {
	pods := map[string]any{"items": []any{
		podWithOwners("shop", "web", []any{
			ownerReference("Pod", "non-controller", false),
			ownerReference("ReplicaSet", "web-7d9f", true),
		}),
	}}
	replicasets := map[string]any{"items": []any{
		map[string]any{"metadata": map[string]any{
			"namespace": "shop",
			"name":      "web-7d9f",
			"ownerReferences": []any{
				ownerReference("StatefulSet", "non-controller", false),
				ownerReference("Deployment", "web", true),
			},
		}},
	}}
	want := []string{"shop/Deployment/web"}
	for _, id := range podKeyRuleIDs {
		t.Run(id, func(t *testing.T) {
			got := expandKeys(t, loadPodKeyRule(t, id), map[string]any{"pods": pods, "replicasets": replicasets})
			if !equalStrings(got, want) {
				t.Fatalf("keys = %#v, want %#v", got, want)
			}
		})
	}
}

func TestGKEPodResourceKeysHandleBarePods(t *testing.T) {
	pods := map[string]any{"items": []any{
		pod("shop", "manual", "", ""),
		pod("shop", "batch", "Job", "nightly"),
		pod("shop", "agent", "DaemonSet", "node-agent"),
	}}
	want := []string{"shop/manual", "shop/Job/nightly", "shop/DaemonSet/node-agent"}
	for _, id := range podKeyRuleIDs {
		t.Run(id, func(t *testing.T) {
			got := expandKeys(t, loadPodKeyRule(t, id), map[string]any{"pods": pods, "replicasets": map[string]any{"items": []any{}}})
			if !equalStrings(got, want) {
				t.Fatalf("keys = %#v, want %#v", got, want)
			}
		})
	}
}

func TestGKEPodResourceKeysResolveReplicaSetOwner(t *testing.T) {
	pods := map[string]any{"items": []any{
		pod("shop", "web-old", "ReplicaSet", "web-7d9f"),
		pod("shop", "web-new", "ReplicaSet", "web-8a2c"),
		pod("shop", "orphan", "ReplicaSet", "missing"),
		pod("shop", "standalone-rs-pod", "ReplicaSet", "standalone-rs"),
	}}
	replicasets := map[string]any{"items": []any{
		replicaSet("shop", "web-7d9f", "Deployment", "web"),
		replicaSet("shop", "web-8a2c", "Deployment", "web"),
		map[string]any{"metadata": map[string]any{"namespace": "shop", "name": "standalone-rs"}},
	}}
	want := []string{"shop/Deployment/web", "shop/Deployment/web", "shop/orphan", "shop/standalone-rs-pod"}
	for _, id := range podKeyRuleIDs {
		t.Run(id, func(t *testing.T) {
			got := expandKeys(t, loadPodKeyRule(t, id), map[string]any{"pods": pods, "replicasets": replicasets})
			if !equalStrings(got, want) {
				t.Fatalf("keys = %#v, want %#v", got, want)
			}
		})
	}
}

var podKeyRuleIDs = []string{"cis-gke-4.1.5", "cis-gke-4.4.1", "cis-gke-4.6.2", "cis-gke-4.6.3", "cis-gke-4.6.4"}

func loadPodKeyRule(t *testing.T, id string) *rule.Rule {
	t.Helper()
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	r, ok := set.Get(id)
	if !ok {
		t.Fatalf("rule %q not found", id)
	}
	return r
}

func expandKeys(t *testing.T, r *rule.Rule, values map[string]any) []string {
	t.Helper()
	d := eval.NewData()
	for key, value := range values {
		d.Set(key, value)
	}
	got, err := eval.ExpandResources(context.Background(), mustEnv(t), r, d, ctxOf(t), r.Params)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]string, len(got.Instances))
	for i, instance := range got.Instances {
		keys[i] = instance.Key
	}
	return keys
}

func nodeList(before, after string) map[string]any {
	return map[string]any{"items": []any{
		map[string]any{"metadata": map[string]any{"name": before, "labels": map[string]any{"cloud.google.com/gke-nodepool": "pool-a"}}},
		map[string]any{"metadata": map[string]any{"name": after, "labels": map[string]any{"cloud.google.com/gke-nodepool": "pool-a"}}},
	}}
}

func pod(namespace, name, ownerKind, ownerName string) map[string]any {
	metadata := map[string]any{"namespace": namespace, "name": name}
	if ownerKind != "" {
		metadata["ownerReferences"] = []any{ownerReference(ownerKind, ownerName, true)}
	}
	return map[string]any{"metadata": metadata}
}

func podWithOwners(namespace, name string, owners []any) map[string]any {
	return map[string]any{"metadata": map[string]any{
		"namespace":       namespace,
		"name":            name,
		"ownerReferences": owners,
	}}
}

func ownerReference(kind, name string, controller bool) map[string]any {
	return map[string]any{"kind": kind, "name": name, "controller": controller}
}

func replicaSet(namespace, name, ownerKind, ownerName string) map[string]any {
	return map[string]any{"metadata": map[string]any{
		"namespace":       namespace,
		"name":            name,
		"ownerReferences": []any{ownerReference(ownerKind, ownerName, true)},
	}}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
