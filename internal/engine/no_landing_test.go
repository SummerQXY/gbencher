package engine_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/cli"
	"github.com/SummerQXY/gbencher/internal/collecttest"
	"github.com/SummerQXY/gbencher/schemas"
)

func TestScan_KubectlTempFilesAreRemoved(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	tmp := filepath.Join(root, "tmp")
	config := filepath.Join(root, "config")
	for _, dir := range []string{home, tmp, config} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TMPDIR", tmp)
	gcloud := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo "scanner@example.com" ;;
  *"projects describe example-prod"*) echo '{"projectNumber":"123456789012"}' ;;
  *"projects get-ancestors example-prod"*) echo '[]' ;;
  *"services list --enabled"*) echo '[]' ;;
  *"container clusters list"*) echo '[{"name":"cluster-a","location":"region-a","endpoint":"192.0.2.10","masterAuth":{"clusterCaCertificate":"Y2E="}}]' ;;
  *) echo '[]' ;;
esac`)
	kubectlDir := t.TempDir()
	kubectlPath := filepath.Join(kubectlDir, "kubectl")
	kubectlScript := "#!/bin/sh\ncase \"$*\" in\n  *--client*) echo '{\"clientVersion\":{\"gitVersion\":\"v1.33.0\"}}' ;;\n  *version*) echo '{\"clientVersion\":{\"gitVersion\":\"v1.33.0\"},\"serverVersion\":{\"gitVersion\":\"v1.33.0\"}}' ;;\n  *) echo '{\"items\":[]}' ;;\nesac\n"
	if err := os.WriteFile(kubectlPath, []byte(kubectlScript), 0o700); err != nil {
		t.Fatal(err)
	}
	env := []string{
		"PATH=" + kubectlDir + string(os.PathListSeparator) + collecttest.PathWith(gcloud),
		"HOME=" + home,
		"TMPDIR=" + tmp,
		"CLOUDSDK_CONFIG=" + config,
	}
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--account=scanner@example.com", "--rule=cis-gke-4.1.1", "--enable=kubectl", "--format=json"}, nil, &stdout, &stderr, env)
	if code != 0 && code != 1 && code != 4 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if err := schemas.ValidateJSON("report", stdout.Bytes()); err != nil {
		t.Fatalf("report schema: %v", err)
	}
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary directory not empty after scan: %v", entries)
	}
}

func TestScan_NoLandingAndRedactsSecretMarkers(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	tmp := filepath.Join(root, "tmp")
	config := filepath.Join(root, "config")
	for _, dir := range []string{home, tmp, config} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(root, "report.json")
	callLogDir := filepath.Join(t.TempDir(), "gcloud-calls")
	if err := os.Mkdir(callLogDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fake := collecttest.FakeGcloud(t, `call_file=$(mktemp `+shellQuote(filepath.Join(callLogDir, "call.XXXXXX"))+`) || exit 90
{
  printf 'CALL\n'
  for arg in "$@"; do printf 'ARG\t%s\n' "$arg"; done
} > "$call_file"
case "$*" in
  "--version") printf 'CHECK\tPRECHECK\n' >> "$call_file"; echo "Google Cloud SDK 1.2.3" ;;
  "config get account") printf 'CHECK\tPRECHECK\n' >> "$call_file"; echo "scanner@example.com" ;;
  *)
    quiet_count=0
    account_count=0
    valid=1
    for arg in "$@"; do
      case "$arg" in
        "--quiet") quiet_count=$((quiet_count + 1)) ;;
        --quiet*) valid=0 ;;
        "--account=scanner@example.com") account_count=$((account_count + 1)) ;;
        --account=*) valid=0 ;;
      esac
    done
    [ "$quiet_count" -eq 1 ] || valid=0
    [ "$account_count" -eq 1 ] || valid=0
    [ "$CLOUDSDK_CORE_DISABLE_FILE_LOGGING" = "1" ] || valid=0
    [ "$CLOUDSDK_CORE_DISABLE_USAGE_REPORTING" = "true" ] || valid=0
    [ "$CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK" = "1" ] || valid=0
    [ "$CLOUDSDK_CORE_DISABLE_PROMPTS" = "1" ] || valid=0
    [ -z "${CLOUDSDK_CORE_LOG_HTTP+x}" ] || valid=0
    [ "$HOME" = "`+home+`" ] || valid=0
    [ "$TMPDIR" = "`+tmp+`" ] || valid=0
    [ "$CLOUDSDK_CONFIG" = "`+config+`" ] || valid=0
    if [ "$valid" -eq 1 ]; then check=VALID; else check=INVALID; fi
    printf 'CHECK\t%s\n' "$check" >> "$call_file"
    [ "$valid" -eq 1 ] || { echo "invalid child argv or environment" >&2; exit 91; }
    case "$*" in
      *"projects get-iam-policy example-prod"*) echo '{"bindings":[{"role":"roles/viewer","members":["user:ya29.synthetic-token","user:AIzaSyntheticKey123456789","user:-----BEGIN PRIVATE KEY-----\\nsynthetic\\n-----END PRIVATE KEY-----"]}]}' ;;
  *"org-policies describe constraints/iam.allowedPolicyMemberDomains"*) echo '{}' ;;
  *"projects describe example-prod"*) echo '{"projectNumber":"123456789012"}' ;;
  *"projects get-ancestors example-prod"*) echo '[{"id":"example-prod","type":"project"},{"id":"111111111111","type":"organization"}]' ;;
  *"organizations describe 111111111111"*) echo '{"displayName":"example.com"}' ;;
  *"services list --enabled"*) echo '[]' ;;
  *"container clusters list"*) echo '[]' ;;
  *) echo '[]' ;;
    esac ;;
esac`)
	env := []string{
		"PATH=" + collecttest.PathWith(fake),
		"HOME=" + home,
		"TMPDIR=" + tmp,
		"CLOUDSDK_CONFIG=" + config,
		"CLOUDSDK_CORE_LOG_HTTP=1",
	}
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--account=scanner@example.com", "--output=" + output, "--format=json"}, nil, &stdout, &stderr, env)
	if code != 0 && code != 1 && code != 4 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	assertGcloudCallLog(t, callLogDir)
	doc, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateJSON("report", doc); err != nil {
		t.Fatalf("report schema: %v", err)
	}
	// Workspace-dependent IAM output is not collected unless its capability is enabled.
	for _, marker := range []string{"ya29.synthetic-token", "AIzaSyntheticKey123456789", "-----BEGIN PRIVATE KEY-----"} {
		if strings.Contains(string(doc), marker) {
			t.Errorf("report contains secret marker %q", marker)
		}
	}
	var report map[string]any
	if err := json.Unmarshal(doc, &report); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "report.json" && entry.Name() != "home" && entry.Name() != "tmp" && entry.Name() != "config" {
			t.Errorf("unexpected path created: %s", entry.Name())
		}
	}
	for _, dir := range []string{home, tmp, config} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("unexpected files in isolated directory %s: %v", filepath.Base(dir), entries)
		}
	}
}

func assertGcloudCallLog(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("fake gcloud recorded no calls")
	}
	validated := 0
	for _, entry := range entries {
		if entry.IsDir() {
			t.Errorf("unexpected directory in call log: %s", entry.Name())
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) < 3 || lines[0] != "CALL" {
			t.Errorf("malformed call record %s: %q", entry.Name(), data)
			continue
		}
		var args []string
		check := ""
		for _, line := range lines[1:] {
			if strings.HasPrefix(line, "ARG\t") {
				args = append(args, strings.TrimPrefix(line, "ARG\t"))
			}
			if strings.HasPrefix(line, "CHECK\t") {
				check = strings.TrimPrefix(line, "CHECK\t")
			}
		}
		joined := strings.Join(args, " ")
		if check == "PRECHECK" {
			if joined != "--version" && joined != "config get account" {
				t.Errorf("unexpected preflight call argv %q", args)
			}
			continue
		}
		if check != "VALID" {
			t.Errorf("scan command validation failed: check=%q argv=%q", check, args)
			continue
		}
		quietCount, accountCount := 0, 0
		for _, arg := range args {
			switch arg {
			case "--quiet":
				quietCount++
			case "--account=scanner@example.com":
				accountCount++
			}
			if strings.HasPrefix(arg, "--quiet") && arg != "--quiet" {
				t.Errorf("non-exact quiet flag in argv %q", args)
			}
			if strings.HasPrefix(arg, "--account=") && arg != "--account=scanner@example.com" {
				t.Errorf("unexpected account flag in argv %q", args)
			}
		}
		if quietCount != 1 || accountCount != 1 {
			t.Errorf("argv %q has quiet count %d and account count %d", args, quietCount, accountCount)
		}
		validated++
	}
	if validated == 0 {
		t.Fatal("fake gcloud recorded no validated scan command")
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
