package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKubeconfigUsesClusterEndpointAndCA(t *testing.T) {
	ca := base64.StdEncoding.EncodeToString([]byte("test-ca"))
	manager, err := NewKubeconfigManager(context.Background(), "/usr/bin/gbench", Options{Account: "scan@example.com", Impersonate: "scanner@example.iam.gserviceaccount.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	path, err := manager.Create(map[string]any{
		"name":     "cluster-a",
		"location": "region-a",
		"endpoint": "10.0.0.1",
		"masterAuth": map[string]any{
			"clusterCaCertificate": ca,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"https://10.0.0.1", ca, "/usr/bin/gbench", "__kube-credential", "--account=scan@example.com", "--impersonate-service-account=scanner@example.iam.gserviceaccount.com"} {
		if !strings.Contains(string(config), expected) {
			t.Errorf("kubeconfig does not contain %q", expected)
		}
	}
}

func TestKubeconfigDoesNotContainCredentialMaterial(t *testing.T) {
	manager, err := NewKubeconfigManager(context.Background(), "/usr/bin/gbench", Options{Account: "scan@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	path, err := manager.Create(map[string]any{
		"name": "cluster-a", "location": "region-a", "endpoint": "10.0.0.1",
		"masterAuth": map[string]any{"clusterCaCertificate": "Y2E="},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"ya29.secret-token", "Bearer ", "access-token", "token:"} {
		if strings.Contains(string(data), marker) {
			t.Errorf("kubeconfig contains credential marker %q", marker)
		}
	}
	info, err := os.Stat(manager.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("temporary directory mode = %o, want 700", info.Mode().Perm())
	}
}

func TestKubeconfigCleanupOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	manager, err := NewKubeconfigManager(ctx, "/usr/bin/gbench", Options{Account: "scan@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	dir := manager.Dir()
	if _, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	}
	cancel()
	waitForPathRemoval(t, dir)
}

func TestKubeconfigManagersUseIsolatedDirectories(t *testing.T) {
	first, err := NewKubeconfigManager(context.Background(), "/usr/bin/gbench", Options{Account: "scan@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewKubeconfigManager(context.Background(), "/usr/bin/gbench", Options{Account: "scan@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.Dir() == second.Dir() || first.CacheDir() == second.CacheDir() {
		t.Fatalf("concurrent managers share temporary state: %q", first.Dir())
	}
}

func TestKubeCredentialEmitsExecCredentialV1(t *testing.T) {
	data, err := ExecCredentialV1("ya29.test-token", time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var credential struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     struct {
			Token               string    `json:"token"`
			ExpirationTimestamp time.Time `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(data, &credential); err != nil {
		t.Fatal(err)
	}
	if credential.APIVersion != "client.authentication.k8s.io/v1" || credential.Kind != "ExecCredential" {
		t.Fatalf("ExecCredential type = %s/%s", credential.APIVersion, credential.Kind)
	}
	if credential.Status.Token != "ya29.test-token" || !credential.Status.ExpirationTimestamp.Equal(time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("ExecCredential status = %+v", credential.Status)
	}
}

func TestKubeCredentialDoesNotExposeToken(t *testing.T) {
	if _, err := ExecCredentialV1("", time.Time{}); err == nil {
		t.Fatal("ExecCredentialV1 accepted an empty token")
	}
	if _, err := ExecCredentialV1("ya29.test-token", time.Time{}); err == nil {
		t.Fatal("ExecCredentialV1 accepted a missing expiration")
	}
}

func waitForPathRemoval(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("temporary path still exists: %s", filepath.Base(path))
}
