package cli_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/cli"
	"github.com/SummerQXY/gbencher/internal/collecttest"
)

func TestCollect_PrintsDataAndCollectorsToStdout(t *testing.T) {
	dir := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo scanner@example.com ;;
  *"compute firewall-rules list"*) echo '[{"name":"vm-a"}]' ;;
  *) echo '[]' ;;
esac`)
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"collect", "--rule=cis-gcp-3.6", "--project=example-prod", "--step=firewalls"}, nil, &stdout, &stderr, []string{"PATH=" + collecttest.PathWith(dir)})
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v output=%q", err, stdout.String())
	}
	if got["data"] == nil || got["collectors"] == nil {
		t.Fatalf("missing data or collectors: %v", got)
	}
}

func TestCollect_RejectsNonProjectScopeInM1(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"collect", "--rule=cis-gcp-2.2", "--project=example-prod"}, nil, &stdout, &stderr, fakeEnv(t))
	if code != 2 || !strings.Contains(stderr.String(), "project scope") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestCollect_RejectsNonGcloudStepsInM1(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"collect", "--rule=cis-gke-3.1.1", "--project=example-prod", "--step=nodes"}, nil, &stdout, &stderr, fakeEnv(t))
	if code != 2 || !strings.Contains(stderr.String(), "gcloud and REST steps only") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestCollect_SanitizeWritesMappingToStderr(t *testing.T) {
	dir := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo scanner@example.com ;;
  *"compute firewall-rules list"*) echo '[{"name":"vm-a","zone":"us-central1-a"}]' ;;
  *) echo '[]' ;;
esac`)
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"collect", "--rule=cis-gcp-3.6", "--project=sample-project", "--step=firewalls", "--sanitize"}, nil, &stdout, &stderr, []string{"PATH=" + collecttest.PathWith(dir)})
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "sample-project → example-prod") {
		t.Fatalf("replacement mapping missing from stderr: %q", stderr.String())
	}
	if strings.Contains(stdout.String(), "--project=sample-project") {
		t.Fatalf("unsanitized project remains in stdout: %q", stdout.String())
	}
}

func TestCollect_SanitizeUsesMetadataFromCollectedData(t *testing.T) {
	dir := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo scanner@example.com ;;
  *"compute firewall-rules list"*) echo '[{"name":"vm-a","projectNumber":987654321098,"organizationId":222222222222,"orgDomain":"tenant.internal.example"}]' ;;
  *) echo '[]' ;;
esac`)
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"collect", "--rule=cis-gcp-3.6", "--project=example-prod", "--step=firewalls", "--sanitize"}, nil, &stdout, &stderr, []string{"PATH=" + collecttest.PathWith(dir)})
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	for _, value := range []string{"987654321098", "222222222222", "tenant.internal.example"} {
		if strings.Contains(stdout.String(), value) {
			t.Errorf("unsanitized metadata %q remains in %s", value, stdout.String())
		}
	}
	if !strings.Contains(stderr.String(), "987654321098 → 123456789012") || !strings.Contains(stderr.String(), "222222222222 → 111111111111") || !strings.Contains(stderr.String(), "tenant.internal.example → example.com") {
		t.Fatalf("metadata mappings missing: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "best-effort") || !strings.Contains(stderr.String(), "manually review") {
		t.Fatalf("missing best-effort warning: %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "not identified") {
		t.Fatalf("recognized metadata reported missing: %q", stderr.String())
	}
}

func TestCollect_SanitizeWarnsWhenMetadataIsNotRecognized(t *testing.T) {
	dir := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo scanner@example.com ;;
  *"compute firewall-rules list"*) echo '[{"name":"vm-a"}]' ;;
  *) echo '[]' ;;
esac`)
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"collect", "--rule=cis-gcp-3.6", "--project=example-prod", "--step=firewalls", "--sanitize"}, nil, &stdout, &stderr, []string{"PATH=" + collecttest.PathWith(dir)})
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "best-effort") || !strings.Contains(stderr.String(), "manually review") {
		t.Fatalf("missing best-effort review warning: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "not identified in collected data: project number, organization ID, organization domain") {
		t.Fatalf("missing metadata fields were not identified: %q", stderr.String())
	}
}

func TestCollect_SanitizeScrubsAllCollectedMetadataValues(t *testing.T) {
	dir := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo scanner@example.com ;;
  *"compute firewall-rules list"*) echo '[{"projectNumber":"987654321098","organizationId":"222222222222","orgDomain":"first.internal.example"},{"projectNumber":"876543210987","organizationId":"333333333333","orgDomain":"second.internal.example"}]' ;;
  *) echo '[]' ;;
esac`)
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"collect", "--rule=cis-gcp-3.6", "--project=sample-project", "--step=firewalls", "--sanitize"}, nil, &stdout, &stderr, []string{"PATH=" + collecttest.PathWith(dir)})
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	for _, original := range []string{"987654321098", "876543210987", "222222222222", "333333333333", "first.internal.example", "second.internal.example"} {
		if strings.Contains(stdout.String(), original) {
			t.Errorf("unsanitized metadata %q remains in %s", original, stdout.String())
		}
		if !strings.Contains(stderr.String(), original+" → ") {
			t.Errorf("mapping for %q is missing from %q", original, stderr.String())
		}
	}
	if !strings.Contains(stderr.String(), "multiple values found and included") {
		t.Fatalf("missing multi-value metadata note: %q", stderr.String())
	}
}

func TestCollect_SanitizeAlwaysWarnsBestEffort(t *testing.T) {
	dir := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo scanner@example.com ;;
  *"compute firewall-rules list"*) echo '[{"projectNumber":"987654321098","organizationId":"222222222222","orgDomain":"tenant.internal.example"}]' ;;
  *) echo '[]' ;;
esac`)
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"collect", "--rule=cis-gcp-3.6", "--project=sample-project", "--step=firewalls", "--sanitize"}, nil, &stdout, &stderr, []string{"PATH=" + collecttest.PathWith(dir)})
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "best-effort") || !strings.Contains(stderr.String(), "manually review") {
		t.Fatalf("missing best-effort review warning: %q", stderr.String())
	}
}
