package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/cli"
	"github.com/SummerQXY/gbencher/internal/collecttest"
)

func TestAuthCheck_JSONReportsProjectAndQuota(t *testing.T) {
	env := authCheckEnv(t, false, false)
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"auth", "check", "--project=example-prod", "--quota-project=example-sec", "--format=json"}, nil, &stdout, &stderr, env)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var got struct {
		Gcloud struct {
			Found   bool   `json:"found"`
			Version string `json:"version"`
		} `json:"gcloud"`
		Identity struct {
			Account      string  `json:"account"`
			Impersonated *string `json:"impersonated"`
			QuotaProject *string `json:"quota_project"`
		} `json:"identity"`
		Projects []struct {
			ID               string `json:"id"`
			OK               bool   `json:"ok"`
			Number           string `json:"number"`
			Organization     string `json:"organization"`
			ServicesReadable bool   `json:"services_readable"`
			QuotaUseOK       *bool  `json:"quota_use_ok"`
		} `json:"projects"`
		Kubectl struct {
			Found bool `json:"found"`
		} `json:"kubectl"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v (%q)", err, stdout.String())
	}
	if !got.Gcloud.Found || got.Gcloud.Version != "1.2.3" || got.Identity.Account != "scanner@example.com" {
		t.Fatalf("gcloud or identity = %+v %+v", got.Gcloud, got.Identity)
	}
	if got.Identity.QuotaProject == nil || *got.Identity.QuotaProject != "example-sec" {
		t.Fatalf("quota project = %v", got.Identity.QuotaProject)
	}
	if len(got.Projects) != 1 {
		t.Fatalf("projects = %+v", got.Projects)
	}
	project := got.Projects[0]
	if project.ID != "example-prod" || !project.OK || project.Number != "123456789012" || project.Organization != "111111111111" || !project.ServicesReadable || project.QuotaUseOK == nil || !*project.QuotaUseOK {
		t.Fatalf("project = %+v", project)
	}
}

func TestAuthCheck_NoAccountExitsThree(t *testing.T) {
	dir := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo "" ;;
  *) exit 1 ;;
esac`)
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"auth", "check", "--project=example-prod"}, nil, &stdout, &stderr, []string{"PATH=" + collecttest.PathWith(dir)})
	if code != 3 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "no configured gcloud account") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestAuthCheck_ProjectForbiddenExitsOne(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"auth", "check", "--project=example-prod", "--format=json"}, nil, &stdout, &stderr, authCheckEnv(t, true, false))
	if code != 1 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var got struct {
		Projects []struct {
			OK bool `json:"ok"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v (%q)", err, stdout.String())
	}
	if len(got.Projects) != 1 || got.Projects[0].OK {
		t.Fatalf("projects = %+v", got.Projects)
	}
	if strings.Contains(stderr.String(), "ya29.secret-token") || !strings.Contains(stderr.String(), "[REDACTED]") {
		t.Fatalf("error was not redacted: %q", stderr.String())
	}
}

func TestAuthCheck_KubectlMissingIsReportedNotFatal(t *testing.T) {
	env := authCheckEnv(t, false, false)
	path := strings.TrimPrefix(env[0], "PATH=")
	binDir := strings.Split(path, string(os.PathListSeparator))[0]
	if err := os.Remove(filepath.Join(binDir, "kubectl")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"auth", "check", "--project=example-prod", "--format=json"}, nil, &stdout, &stderr, env)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var got struct {
		Kubectl struct {
			Found bool `json:"found"`
		} `json:"kubectl"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v (%q)", err, stdout.String())
	}
	if got.Kubectl.Found {
		t.Fatalf("kubectl = %+v", got.Kubectl)
	}
}

func TestAuthCheck_GcloudUsesSafeEnvironmentOverrides(t *testing.T) {
	script := `if [ "$CLOUDSDK_CORE_DISABLE_FILE_LOGGING" != "1" ] || [ "$CLOUDSDK_CORE_DISABLE_USAGE_REPORTING" != "true" ] || [ "$CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK" != "1" ] || [ "$CLOUDSDK_CORE_DISABLE_PROMPTS" != "1" ]; then
  echo "missing safe gcloud environment" >&2
  exit 9
fi
case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo "scanner@example.com" ;;
  "projects describe "*) echo '{"projectNumber":"123456789012"}' ;;
  "projects get-ancestors "*) echo '[{"id":"111111111111","type":"organization"}]' ;;
  "services list --enabled --project="*) echo '[]' ;;
  *) exit 2 ;;
esac`
	dir := collecttest.FakeGcloud(t, script)
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"auth", "check", "--project=example-prod", "--format=json"}, nil, &stdout, &stderr, []string{"PATH=" + collecttest.PathWith(dir)})
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestAuthCheck_KubectlVersionFailureIsReported(t *testing.T) {
	cases := []struct {
		name, script, format string
	}{
		{name: "command failure json", format: "json", script: "#!/bin/sh\nprintf 'ya29.secret-token\\033[31m\\n' >&2\nexit 1\n"},
		{name: "unrecognized command failure json", format: "json", script: "#!/bin/sh\nprintf 'opaque-private-marker-7f3c9a\\n' >&2\nexit 1\n"},
		{name: "multiline failure table", format: "table", script: "#!/bin/sh\nprintf 'ya29.secret-token\\033[31mfirst\\nforged\\tcolumn\\342\\200\\250section\\342\\200\\251end\\n' >&2\nexit 1\n"},
		{name: "invalid output table", format: "table", script: "#!/bin/sh\nprintf 'not-json\\n'\n"},
		{name: "missing version json", format: "json", script: "#!/bin/sh\nprintf '{\"clientVersion\":{}}\\n'\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := authCheckEnv(t, false, false)
			path := strings.TrimPrefix(env[0], "PATH=")
			binDir := strings.Split(path, string(os.PathListSeparator))[0]
			if err := os.WriteFile(filepath.Join(binDir, "kubectl"), []byte(tc.script), 0o700); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := cli.Execute([]string{"auth", "check", "--project=example-prod", "--format=" + tc.format}, nil, &stdout, &stderr, env)
			if code != 0 {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
			if tc.format == "json" {
				var got struct {
					Kubectl struct {
						Found        bool   `json:"found"`
						VersionError string `json:"version_error"`
					} `json:"kubectl"`
				}
				if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
					t.Fatalf("invalid JSON: %v (%q)", err, stdout.String())
				}
				if !got.Kubectl.Found || got.Kubectl.VersionError == "" || strings.Contains(got.Kubectl.VersionError, "ya29.secret-token") || strings.Contains(got.Kubectl.VersionError, "opaque-private-marker-7f3c9a") || strings.ContainsRune(got.Kubectl.VersionError, '\x1b') {
					t.Fatalf("kubectl = %+v", got.Kubectl)
				}
			} else {
				if !strings.Contains(stdout.String(), "kubectl") {
					t.Fatalf("table did not report kubectl failure: %q", stdout.String())
				}
				if strings.Contains(tc.name, "invalid output") && !strings.Contains(stdout.String(), "invalid JSON") {
					t.Fatalf("table did not explain malformed output: %q", stdout.String())
				}
				if strings.Count(stdout.String(), "\n") != 5 || strings.Count(stdout.String(), "\t") != 16 || strings.ContainsAny(stdout.String(), "\u2028\u2029") {
					t.Fatalf("table contains injected rows or separators: %q", stdout.String())
				}
			}
		})
	}
}

func TestAuthCheck_ReportsClusterProbeResults(t *testing.T) {
	env := authCheckEnv(t, false, true)
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"auth", "check", "--project=example-prod", "--enable=kubectl", "--format=json"}, nil, &stdout, &stderr, env)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var got struct {
		Kubectl struct {
			Clusters []struct {
				Project  string `json:"project"`
				Name     string `json:"name"`
				Location string `json:"location"`
				Outcome  string `json:"outcome"`
			} `json:"clusters"`
		} `json:"kubectl"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v (%q)", err, stdout.String())
	}
	if len(got.Kubectl.Clusters) != 1 {
		t.Fatalf("clusters = %+v", got.Kubectl.Clusters)
	}
	cluster := got.Kubectl.Clusters[0]
	if cluster.Project != "example-prod" || cluster.Name != "cluster-a" || cluster.Location != "region-a" || cluster.Outcome != "reachable" {
		t.Fatalf("cluster = %+v", cluster)
	}
}

func TestAuthCheck_KubectlErrorsDoNotExposeUnrecognizedOutput(t *testing.T) {
	const marker = "opaque-private-marker-7f3c9a"
	for _, tc := range []struct {
		name          string
		failInventory bool
	}{
		{name: "probe error"},
		{name: "cluster inventory error", failInventory: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gcloudScript := `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo "scanner@example.com" ;;
  *"projects describe example-prod"*) echo '{"projectNumber":"123456789012"}' ;;
  *"projects get-ancestors example-prod"*) echo '[{"id":"example-prod","type":"project"},{"id":"111111111111","type":"organization"}]' ;;
  *"services list --enabled"*) echo '[]' ;;
  *"container clusters list"*) `
			if tc.failInventory {
				gcloudScript += `echo '` + marker + `' >&2; exit 1 ;;
`
			} else {
				gcloudScript += `echo '[{"name":"cluster-a","location":"region-a","endpoint":"192.0.2.10","masterAuth":{"clusterCaCertificate":"Y2E="}}]' ;;
`
			}
			gcloudScript += `  *) echo '[]' ;;
esac`
			gcloud := collecttest.FakeGcloud(t, gcloudScript)
			kubectlDir := t.TempDir()
			kubectlPath := filepath.Join(kubectlDir, "kubectl")
			kubectlScript := `#!/bin/sh
case "$*" in
  *--client*) echo '{"clientVersion":{"gitVersion":"v1.33.0"}}' ;;
  *--kubeconfig=*) echo '` + marker + `' >&2; exit 1 ;;
  *) exit 2 ;;
esac
`
			if err := os.WriteFile(kubectlPath, []byte(kubectlScript), 0o700); err != nil {
				t.Fatal(err)
			}
			env := []string{"PATH=" + kubectlDir + string(os.PathListSeparator) + collecttest.PathWith(gcloud)}
			var stdout, stderr bytes.Buffer
			code := cli.Execute([]string{"auth", "check", "--project=example-prod", "--enable=kubectl", "--format=json"}, nil, &stdout, &stderr, env)
			if code == 0 {
				t.Fatalf("code=0, want failure; report=%q", stdout.String())
			}
			if strings.Contains(stdout.String(), marker) || strings.Contains(stderr.String(), marker) {
				t.Fatalf("private marker leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			var got struct {
				Kubectl struct {
					Clusters []struct {
						Outcome string `json:"outcome"`
						Error   string `json:"error"`
					} `json:"clusters"`
				} `json:"kubectl"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatalf("invalid JSON: %v (%q)", err, stdout.String())
			}
			if len(got.Kubectl.Clusters) != 1 || got.Kubectl.Clusters[0].Outcome != "error" || got.Kubectl.Clusters[0].Error == "" {
				t.Fatalf("cluster probe error result = %+v", got.Kubectl.Clusters)
			}
		})
	}
}

func TestAuthCheck_TableSanitizesAllStringCells(t *testing.T) {
	dir := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
	  "config get account") printf 'scanner@example.com\nforged\taccount\n' ;;
  "projects describe "*) echo '{"projectNumber":"123456789012"}' ;;
  "projects get-ancestors "*) printf '[{"id":"111111111111\\nforged\\torganization\\u2028line\\u2029end","type":"organization"}]' ;;
  "services list --enabled --project="*) echo '[]' ;;
  *) exit 2 ;;
esac`)
	kubectl := filepath.Join(dir, "kubectl")
	if err := os.WriteFile(kubectl, []byte("#!/bin/sh\nprintf '{\"clientVersion\":{\"gitVersion\":\"v1.2\\\\nforged\\\\tversion\\\\u2028line\\\\u2029end\"}}\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"auth", "check", "--project=example-prod", "--format=table"}, nil, &stdout, &stderr, []string{"PATH=" + dir})
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if strings.Count(stdout.String(), "\n") != 5 || strings.Count(stdout.String(), "\t") != 16 || strings.ContainsAny(stdout.String(), "\u2028\u2029") {
		t.Fatalf("table contains injected rows or separators: %q", stdout.String())
	}
}

func TestAuthCheck_ProjectOutputIsSortedAndDeduplicated(t *testing.T) {
	dir := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo "scanner@example.com" ;;
  "projects describe "*) echo '{"projectNumber":"123456789012"}' ;;
  "projects get-ancestors "*) echo '[{"id":"111111111111","type":"organization"}]' ;;
  "services list --enabled --project="*) echo '[]' ;;
  *) echo "unexpected gcloud invocation: $*" >&2; exit 2 ;;
esac`)
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"auth", "check", "--project=example-prod", "--project=example-dev", "--project=example-prod", "--format=json"}, nil, &stdout, &stderr, []string{"PATH=" + collecttest.PathWith(dir)})
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var got struct {
		Projects []struct {
			ID string `json:"id"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v (%q)", err, stdout.String())
	}
	if len(got.Projects) != 2 || got.Projects[0].ID != "example-dev" || got.Projects[1].ID != "example-prod" {
		t.Fatalf("projects = %+v", got.Projects)
	}
}

func authCheckEnv(t *testing.T, forbidden, withKubectl bool) []string {
	t.Helper()
	script := `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo "scanner@example.com" ;;
	  "projects describe example-prod --format=json --quiet --account=scanner@example.com") echo '{"projectNumber":"123456789012"}' ;;
	  "projects describe example-prod --format=json --quiet --account=scanner@example.com --billing-project=example-sec") echo '{"projectNumber":"123456789012"}' ;;
	  "projects get-ancestors example-prod --format=json --quiet --account=scanner@example.com") echo '[{"id":"example-prod","type":"project"},{"id":"111111111111","type":"organization"}]' ;;
	  "projects get-ancestors example-prod --format=json --quiet --account=scanner@example.com --billing-project=example-sec") echo '[{"id":"example-prod","type":"project"},{"id":"111111111111","type":"organization"}]' ;;
	  "services list --enabled --project=example-prod --format=json --quiet --account=scanner@example.com") echo '[]' ;;
	  "services list --enabled --project=example-prod --format=json --quiet --account=scanner@example.com --billing-project=example-sec") echo '[]' ;;
	  *"container clusters list"*) echo '[{"name":"cluster-a","location":"region-a","endpoint":"192.0.2.10","masterAuth":{"clusterCaCertificate":"Y2E="}}]' ;;
	  "logging metrics list --project=example-prod --limit=1 --format=json --quiet --account=scanner@example.com --billing-project=example-sec") echo '[]' ;;
  *) echo "unexpected gcloud invocation: $*" >&2; exit 2 ;;
esac`
	if forbidden {
		script = strings.Replace(script, `  "projects describe example-prod --format=json --quiet --account=scanner@example.com") echo '{"projectNumber":"123456789012"}' ;;`, `  "projects describe example-prod --format=json --quiet --account=scanner@example.com") echo 'ERROR: (gcloud.projects.describe) PERMISSION_DENIED ya29.secret-token' >&2; exit 1 ;;`, 1)
	}
	dir := collecttest.FakeGcloud(t, script)
	path := dir
	if withKubectl {
		kubectlDir := t.TempDir()
		kubectl := filepath.Join(kubectlDir, "kubectl")
		if err := os.WriteFile(kubectl, []byte("#!/bin/sh\ncase \"$*\" in\n  *--kubeconfig=*) echo '{\"clientVersion\":{\"gitVersion\":\"v1.33.19\"},\"serverVersion\":{\"gitVersion\":\"v1.33.0\"}}' ;;\n  *) echo '{\"clientVersion\":{\"gitVersion\":\"v1.33.19\"}}' ;;\nesac\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		path = kubectlDir + string(os.PathListSeparator) + path
	}
	return []string{"PATH=" + path}
}
