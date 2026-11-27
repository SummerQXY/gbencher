package cli_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/SummerQXY/gbencher/internal/cli"
	"github.com/SummerQXY/gbencher/internal/collecttest"
)

func TestScan_OutputRefusedWhenExists(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "r.json")
	if err := os.WriteFile(out, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--output=" + out}, nil, &bytes.Buffer{}, &errb, fakeEnv(t))
	if code != 2 || !strings.Contains(errb.String(), "already exists") {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
}

func TestScan_OutputRefusedWhenSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	out := filepath.Join(dir, "link.json")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, out); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	var errb bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--output=" + out, "--force"}, nil, &bytes.Buffer{}, &errb, fakeEnv(t))
	if code != 2 || !strings.Contains(errb.String(), "symlink") {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
}

func TestScan_InvalidProjectIDExitsTwo(t *testing.T) {
	for _, project := range []string{"Example_Prod", "p"} {
		var errb bytes.Buffer
		code := cli.Execute([]string{"scan", "--project=" + project}, nil, &bytes.Buffer{}, &errb, fakeEnv(t))
		if code != 2 || !strings.Contains(errb.String(), "project") {
			t.Errorf("project %q: code=%d err=%q", project, code, errb.String())
		}
	}
}

func TestScan_EmptyStdinProfileExitsTwo(t *testing.T) {
	var errb bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--profile=-"}, bytes.NewReader(nil), &bytes.Buffer{}, &errb, fakeEnv(t))
	if code != 2 || !strings.Contains(errb.String(), "profile") {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
}

func TestScan_UnknownRulePatternExitsTwo(t *testing.T) {
	var errb bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--rule=cis-gcp-unknown"}, nil, &bytes.Buffer{}, &errb, fakeEnv(t))
	if code != 2 || !strings.Contains(errb.String(), "matched no rules") {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
}

func TestScan_ProfileFromStdinAndRuleFilter(t *testing.T) {
	profile := "dsl_version: 1\ninclude: [cis-gcp-1.12]\n"
	var stderr bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--profile=-", "--rule=cis-gcp-1.12"}, strings.NewReader(profile), &bytes.Buffer{}, &stderr, fakeEnv(t))
	if code == 2 || strings.Contains(stderr.String(), "matched no rules") {
		t.Fatalf("profile/filter rejected: code=%d stderr=%q", code, stderr.String())
	}
}

func TestScan_JSONToStdoutWhenNoOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--account=scanner@example.com", "--rule=cis-gcp-1.12", "--format=json"}, nil, &stdout, &stderr, successEnv(t))
	if code != 0 && code != 1 && code != 4 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var value any
	if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
		t.Fatalf("stdout is not one JSON document: %v (%q)", err, stdout.String())
	}
	var report struct {
		Scan struct {
			Selection struct {
				Benchmarks []string `json:"benchmarks"`
				Levels     []string `json:"levels"`
			} `json:"selection"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Scan.Selection.Benchmarks) != 1 || report.Scan.Selection.Benchmarks[0] != "cis-gcp-foundation@5.0.0" || len(report.Scan.Selection.Levels) != 1 || report.Scan.Selection.Levels[0] != "L2" {
		t.Fatalf("selection metadata does not reflect the filtered rules: %+v", report.Scan.Selection)
	}
	if strings.TrimSpace(stdout.String()) == "" || stdout.String()[len(stdout.String())-1] != '\n' {
		t.Fatalf("stdout must end with one newline: %q", stdout.String())
	}
}

func TestScan_ShowPassFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--account=scanner@example.com", "--rule=cis-gcp-1.12", "--show-pass"}, nil, &stdout, &stderr, successEnv(t))
	if code == 2 || code == 3 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PASS") {
		t.Fatalf("table did not show PASS: %q", stdout.String())
	}
}

func TestScan_NoReportOnExitThree(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.json")
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--output=" + out}, nil, &stdout, &stderr, fakeEnv(t))
	if code != 3 || stdout.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("output exists after failed scan: %v", err)
	}
}

func TestScan_OutputDirUnavailableExitsThree(t *testing.T) {
	parent := t.TempDir()
	out := filepath.Join(parent, "missing", "report.json")
	var stderr bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--output=" + out}, nil, &bytes.Buffer{}, &stderr, fakeEnv(t))
	if code != 3 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestScan_OutputDirNotWritableExitsThree(t *testing.T) {
	parent := t.TempDir()
	notDir := filepath.Join(parent, "file")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--output=" + filepath.Join(notDir, "report.json")}, nil, &bytes.Buffer{}, &stderr, fakeEnv(t))
	if code != 3 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestScan_RulesDirOverridesAndIsLinted(t *testing.T) {
	t.Run("override", func(t *testing.T) {
		dir := t.TempDir()
		source, err := os.ReadFile("../../rules/cis-gcp-foundation-v5.0.0/1-iam.yaml")
		if err != nil {
			t.Fatal(err)
		}
		updated := strings.ReplaceAll(string(source), "title: Ensure That Separation of Duties Is Enforced While", "title: Ensure That Separation of Duties Is Verified While")
		if updated == string(source) {
			t.Fatal("rule title to override was not found")
		}
		if err := os.WriteFile(filepath.Join(dir, "1-iam.yaml"), []byte(updated), 0o600); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(updated, "Verified While") {
			t.Fatalf("external source was not changed")
		}
		var stdout, stderr bytes.Buffer
		code := cli.Execute([]string{"scan", "--project=example-prod", "--account=scanner@example.com", "--rule=cis-gcp-1.12", "--rules-dir=" + dir, "--format=json"}, nil, &stdout, &stderr, successEnv(t))
		if code != 0 && code != 1 && code != 4 {
			t.Fatalf("code=%d stderr=%q", code, stderr.String())
		}
		var output struct {
			Scan struct {
				Tool struct {
					RulesetSource string `json:"ruleset_source"`
				} `json:"tool"`
			} `json:"scan"`
			RuleSummaries []struct {
				Title string `json:"title"`
			} `json:"rule_summaries"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
			t.Fatal(err)
		}
		if output.Scan.Tool.RulesetSource != "external" || len(output.RuleSummaries) != 1 || !strings.Contains(output.RuleSummaries[0].Title, "Verified") {
			t.Fatalf("external override missing: %+v", output)
		}
	})
	t.Run("bad command", func(t *testing.T) {
		dir := t.TempDir()
		source, err := os.ReadFile("../../testdata/lint/command-not-allowed.yaml")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), source, 0o600); err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		code := cli.Execute([]string{"scan", "--project=example-prod", "--rules-dir=" + dir}, nil, &bytes.Buffer{}, &stderr, fakeEnv(t))
		if code != 2 || !strings.Contains(stderr.String(), "lint") {
			t.Fatalf("code=%d stderr=%q", code, stderr.String())
		}
	})
	t.Run("empty directory", func(t *testing.T) {
		var stderr bytes.Buffer
		code := cli.Execute([]string{"scan", "--project=example-prod", "--rules-dir=" + t.TempDir()}, nil, &bytes.Buffer{}, &stderr, fakeEnv(t))
		if code != 2 || !strings.Contains(stderr.String(), "lint") {
			t.Fatalf("code=%d stderr=%q", code, stderr.String())
		}
	})
}

func TestScan_ExitFourStillWritesReport(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.json")
	var stderr bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--account=scanner@example.com", "--rule=cis-gke-3.1.1", "--output=" + out, "--format=json"}, nil, &bytes.Buffer{}, &stderr, successEnv(t))
	if code != 4 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("invalid report: %v", err)
	}
}

func TestScan_InterruptExits130AndLeavesNoFile(t *testing.T) {
	runScanSignalTest(t, "TestScan_InterruptExits130AndLeavesNoFile", syscall.SIGINT, 130)
}

func TestScan_TerminateExits143AndLeavesNoFile(t *testing.T) {
	runScanSignalTest(t, "TestScan_TerminateExits143AndLeavesNoFile", syscall.SIGTERM, 143)
}

func runScanSignalTest(t *testing.T, testName string, sig syscall.Signal, wantCode int) {
	t.Helper()
	if os.Getenv("GBENCH_SCAN_SIGNAL_HELPER") == "1" {
		out := os.Getenv("GBENCH_SCAN_SIGNAL_OUTPUT")
		code := cli.Execute([]string{"scan", "--project=example-prod", "--output=" + out}, nil, &bytes.Buffer{}, &bytes.Buffer{}, os.Environ())
		os.Exit(code)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "report.json")
	marker := filepath.Join(dir, "gcloud-started")
	script := `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo "scanner@example.com" ;;
  *) touch ` + strconv.Quote(marker) + `; sleep 30 ;;
esac`
	gcloudDir := collecttest.FakeGcloud(t, script)
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = append(os.Environ(), "GBENCH_SCAN_SIGNAL_HELPER=1", "GBENCH_SCAN_SIGNAL_OUTPUT="+out, "PATH="+collecttest.PathWith(gcloudDir))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatal("fake gcloud did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Signal(sig); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != wantCode {
		t.Fatalf("process exit=%v, want %d", err, wantCode)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("output exists after interrupt: %v", err)
	}
}

func fakeEnv(t *testing.T) []string {
	t.Helper()
	dir := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo "" ;;
  *) exit 1 ;;
esac`)
	return []string{"PATH=" + collecttest.PathWith(dir)}
}

func successEnv(t *testing.T) []string {
	t.Helper()
	dir := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "projects describe example-prod --format=json --quiet --account=scanner@example.com") echo '{"projectNumber":"123456789012"}' ;;
  "projects get-ancestors example-prod --format=json --quiet --account=scanner@example.com") echo '[{"id":"example-prod","type":"project"},{"id":"111111111111","type":"organization"}]' ;;
  *"projects get-iam-policy example-prod"*) echo '{"bindings":[]}' ;;
  *"container clusters list --project=example-prod"*) echo '[{"name":"cluster-a","location":"asia-east1"}]' ;;
  *"services list --enabled --project=example-prod"*) echo '[]' ;;
  *) echo '[]' ;;
esac`)
	return []string{"PATH=" + collecttest.PathWith(dir)}
}
