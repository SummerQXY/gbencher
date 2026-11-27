package cli_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/SummerQXY/gbencher/internal/cli"
	"github.com/SummerQXY/gbencher/internal/collecttest"
	"github.com/SummerQXY/gbencher/schemas"
)

func TestScan_InterruptCleansTemporaryDirectory(t *testing.T) {
	if os.Getenv("GBENCH_INTERRUPT_HELPER") == "1" {
		out := os.Getenv("GBENCH_INTERRUPT_OUTPUT")
		code := cli.Execute([]string{"scan", "--project=example-prod", "--account=scanner@example.com", "--output=" + out}, nil, &bytes.Buffer{}, &bytes.Buffer{}, os.Environ())
		os.Exit(code)
	}

	for _, tc := range []struct {
		name string
		sig  syscall.Signal
		code int
	}{{"sigint", syscall.SIGINT, 130}, {"sigterm", syscall.SIGTERM, 143}} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tmp := filepath.Join(root, "tmp")
			home := filepath.Join(root, "home")
			config := filepath.Join(root, "config")
			for _, dir := range []string{tmp, home, config} {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			output := filepath.Join(root, "report.json")
			started := filepath.Join(root, "gcloud-started")
			fake := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo "scanner@example.com" ;;
  *) touch `+shellQuote(started)+`; sleep 30 ;;
esac`)
			cmd := exec.Command(os.Args[0], "-test.run=^TestScan_InterruptCleansTemporaryDirectory$")
			cmd.Env = append(os.Environ(),
				"GBENCH_INTERRUPT_HELPER=1",
				"GBENCH_INTERRUPT_OUTPUT="+output,
				"PATH="+collecttest.PathWith(fake),
				"HOME="+home,
				"TMPDIR="+tmp,
				"CLOUDSDK_CONFIG="+config,
			)
			var combined bytes.Buffer
			cmd.Stdout = &combined
			cmd.Stderr = &combined
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, err := os.Stat(started); err == nil {
					break
				}
				if time.Now().After(deadline) {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
					t.Fatalf("fake gcloud did not start; output=%q", combined.String())
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := cmd.Process.Signal(tc.sig); err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatalf("signal failed: %v; output=%q", err, combined.String())
			}
			err := cmd.Wait()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != tc.code {
				t.Fatalf("process exit=%v, want %d; output=%q", err, tc.code, combined.String())
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("output exists after interrupt: %v", err)
			}
			entries, err := os.ReadDir(tmp)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("temporary directory not empty after interrupt: %v", entries)
			}
		})
	}
}

func TestScan_KubectlSignalCleanupRemovesTempFilesAndDoesNotCreateOutput(t *testing.T) {
	if os.Getenv("GBENCH_KUBECTL_INTERRUPT_HELPER") == "1" {
		out := os.Getenv("GBENCH_KUBECTL_INTERRUPT_OUTPUT")
		code := cli.Execute([]string{"scan", "--project=example-prod", "--account=scanner@example.com", "--rule=cis-gke-4.1.1", "--enable=kubectl", "--output=" + out}, nil, &bytes.Buffer{}, &bytes.Buffer{}, os.Environ())
		os.Exit(code)
	}

	for _, tc := range []struct {
		name string
		sig  syscall.Signal
		code int
	}{{"sigint", syscall.SIGINT, 130}, {"sigterm", syscall.SIGTERM, 143}} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tmp := filepath.Join(root, "tmp")
			home := filepath.Join(root, "home")
			config := filepath.Join(root, "config")
			for _, dir := range []string{tmp, home, config} {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			output := filepath.Join(root, "report.json")
			started := filepath.Join(root, "kubectl-started")
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
			kubectlScript := "#!/bin/sh\ncase \"$*\" in\n  *--client*) echo '{\"clientVersion\":{\"gitVersion\":\"v1.33.0\"}}' ;;\n  *--kubeconfig=*) touch " + shellQuote(started) + "; sleep 30 ;;\n  *) echo '{\"items\":[]}' ;;\nesac\n"
			if err := os.WriteFile(kubectlPath, []byte(kubectlScript), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestScan_KubectlSignalCleanupRemovesTempFilesAndDoesNotCreateOutput$")
			cmd.Env = append(os.Environ(),
				"GBENCH_KUBECTL_INTERRUPT_HELPER=1",
				"GBENCH_KUBECTL_INTERRUPT_OUTPUT="+output,
				"PATH="+kubectlDir+string(os.PathListSeparator)+collecttest.PathWith(gcloud),
				"HOME="+home,
				"TMPDIR="+tmp,
				"CLOUDSDK_CONFIG="+config,
			)
			var combined bytes.Buffer
			cmd.Stdout = &combined
			cmd.Stderr = &combined
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(8 * time.Second)
			for {
				if _, err := os.Stat(started); err == nil {
					break
				}
				if time.Now().After(deadline) {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
					t.Fatalf("fake kubectl did not start; output=%q", combined.String())
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := cmd.Process.Signal(tc.sig); err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatalf("signal failed: %v; output=%q", err, combined.String())
			}
			err := cmd.Wait()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != tc.code {
				t.Fatalf("process exit=%v, want %d; output=%q", err, tc.code, combined.String())
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("output exists after interruption: %v", err)
			}
			entries, err := os.ReadDir(tmp)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("temporary directory not empty after interruption: %v", entries)
			}
		})
	}
}

func TestScan_ContractJSONOmitsKnownSecretMarkers(t *testing.T) {
	fake := collecttest.FakeGcloud(t, `case "$*" in
  "--version") echo "Google Cloud SDK 1.2.3" ;;
  "config get account") echo "scanner@example.com" ;;
  *"projects describe example-prod"*) echo '{"projectNumber":"123456789012"}' ;;
  *"projects get-ancestors example-prod"*) echo '[{"id":"example-prod","type":"project"},{"id":"111111111111","type":"organization"}]' ;;
  *"services list --enabled"*) echo '[]' ;;
  *"container clusters list"*) echo '[]' ;;
  *) echo '[]' ;;
esac`)
	var out, stderr bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--account=scanner@example.com", "--format=json"}, nil, &out, &stderr, []string{"PATH=" + collecttest.PathWith(fake)})
	if code != 0 && code != 1 && code != 4 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if err := schemasValidateReport(out.Bytes()); err != nil {
		t.Fatalf("report schema: %v", err)
	}
	assertNoSecretMarkers(t, out.String())

	var catalogOut bytes.Buffer
	if code := cli.Execute([]string{"rules", "list", "--format=json"}, nil, &catalogOut, &bytes.Buffer{}, nil); code != 0 {
		t.Fatalf("catalog code=%d", code)
	}
	if err := schemas.ValidateJSON("catalog", catalogOut.Bytes()); err != nil {
		t.Fatalf("catalog schema: %v", err)
	}
	assertNoSecretMarkers(t, catalogOut.String())
}

func schemasValidateReport(data []byte) error {
	return schemas.ValidateJSON("report", data)
}

func assertNoSecretMarkers(t *testing.T, data string) {
	t.Helper()
	for _, marker := range []string{"ya29.synthetic-token", "AIzaSyntheticKey123456789", "-----BEGIN PRIVATE KEY-----"} {
		if strings.Contains(data, marker) {
			t.Errorf("JSON contains secret marker %q", marker)
		}
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
