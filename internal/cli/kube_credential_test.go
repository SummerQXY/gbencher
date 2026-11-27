package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/cli"
	"github.com/SummerQXY/gbencher/internal/collecttest"
)

func TestKubeCredentialUsesPinnedIdentity(t *testing.T) {
	const token = "ya29.synthetic-credential-token"
	callFile := t.TempDir() + "/calls"
	envFile := t.TempDir() + "/child-env"
	fake := collecttest.FakeGcloud(t, `printf '%s\n' "$*" >> '`+callFile+`'
env > '`+envFile+`'
case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  *"auth print-access-token"*) echo '`+token+`' ;;
  *) echo "unexpected gcloud arguments" >&2; exit 2 ;;
esac`)
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"__kube-credential", "--account=scan@example.com", "--impersonate-service-account=scanner@example.iam.gserviceaccount.com"}, nil, &stdout, &stderr, []string{"PATH=" + collecttest.PathWith(fake)})
	if code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), token) || strings.Contains(stderr.String(), token) {
		t.Fatalf("stdout/stderr do not isolate the credential: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	var response struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     struct {
			Token string `json:"token"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		t.Fatalf("invalid ExecCredential: %v (%q)", err, stdout.String())
	}
	if response.APIVersion != "client.authentication.k8s.io/v1" || response.Kind != "ExecCredential" || response.Status.Token != token {
		t.Fatalf("ExecCredential = %+v", response)
	}
	calls, err := os.ReadFile(callFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "--account=scan@example.com") || !strings.Contains(string(calls), "--impersonate-service-account=scanner@example.iam.gserviceaccount.com") {
		t.Fatalf("gcloud calls do not use pinned identity: %q", calls)
	}
	if strings.Contains(string(calls), token) {
		t.Fatal("token appeared in gcloud argv")
	}
	childEnv, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(childEnv), token) {
		t.Fatal("token appeared in the gcloud environment")
	}
}

func TestKubeCredentialFailureDoesNotExposeToken(t *testing.T) {
	const token = "ya29.failure-marker"
	fake := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  *"auth print-access-token"*) echo '`+token+`' >&2; exit 1 ;;
  *) exit 2 ;;
esac`)
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"__kube-credential", "--account=scan@example.com"}, nil, &stdout, &stderr, []string{"PATH=" + collecttest.PathWith(fake)})
	if code != 3 || strings.Contains(stdout.String(), token) || strings.Contains(stderr.String(), token) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestKubeCredentialIsHiddenFromHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"--help"}, nil, &stdout, &stderr, nil)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "__kube-credential") {
		t.Fatalf("internal command is visible in help: %q", stdout.String())
	}
}
