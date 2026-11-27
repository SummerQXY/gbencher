package collect_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/collecttest"
)

// run creates a fake gcloud script, wires it through an OSRunner, and returns
// the result. It is the common test harness for runner tests.
func run(t *testing.T, script string, limits collect.Limits) (collect.Output, error) {
	t.Helper()
	dir := collecttest.FakeGcloud(t, script)
	r := collect.OSRunner{}
	e := collect.Exec{
		Path: filepath.Join(dir, "gcloud"),
		Env:  []string{fmt.Sprintf("PATH=%s", collecttest.PathWith(dir))},
	}
	return r.Run(context.Background(), e, limits)
}

func TestOSRunner_TimeoutKillsProcessGroup(t *testing.T) {
	start := time.Now()
	out, err := run(t, `sleep 30; echo done`, collect.Limits{Timeout: 100 * time.Millisecond, MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if !out.TimedOut {
		t.Fatalf("expected TimedOut=true, got %+v", out)
	}
	if out.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code after SIGKILL, got %+v", out)
	}
	if strings.Contains(string(out.Stdout), "done") {
		t.Fatal("echo output after sleep should not appear; child survived the kill")
	}
	// The call must return within a small multiple of the timeout even if
	// grandchildren hold output pipes open.
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Run took %v; expected return within 500ms after a 100ms timeout", elapsed)
	}
}

// TestOSRunner_ProcessGroupKillKillsGrandchildren verifies that cancellation
// kills the entire process group, not just the direct child. The background
// process signals readiness before cancellation and waits for release before
// writing its marker, so the test controls exactly when a surviving child runs.
func TestOSRunner_ProcessGroupKillKillsGrandchildren(t *testing.T) {
	markerDir := t.TempDir()
	ready := filepath.Join(markerDir, "ready")
	release := filepath.Join(markerDir, "release")
	marker := filepath.Join(markerDir, "marker")

	script := `( touch "$READY"; while [ ! -e "$RELEASE" ]; do sleep 0.01; done; echo x > "$MARK" ) & sleep 30`
	scriptDir := collecttest.FakeGcloud(t, script)

	r := collect.OSRunner{}
	e := collect.Exec{
		Path: filepath.Join(scriptDir, "gcloud"),
		Env: []string{
			fmt.Sprintf("PATH=%s", collecttest.PathWith(scriptDir)),
			fmt.Sprintf("READY=%s", ready),
			fmt.Sprintf("RELEASE=%s", release),
			fmt.Sprintf("MARK=%s", marker),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type runResult struct {
		out collect.Output
		err error
	}
	result := make(chan runResult, 1)
	go func() {
		out, err := r.Run(ctx, e, collect.Limits{Timeout: 30 * time.Second, MaxOutput: 1 << 20})
		result <- runResult{out: out, err: err}
	}()

	readyDeadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(readyDeadline) {
			cancel()
			<-result
			t.Fatal("background process did not signal readiness")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	var run runResult
	select {
	case run = <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return promptly after parent cancellation")
	}
	if run.err != nil {
		t.Fatal(run.err)
	}
	if run.out.TimedOut {
		t.Fatal("expected TimedOut=false when parent context is cancelled")
	}
	if run.out.ExitCode == 0 {
		t.Fatal("expected non-zero exit code after parent cancellation")
	}

	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	markerDeadline := time.Now().Add(500 * time.Millisecond)
	for {
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("marker file exists: background grandchild survived process-group cancellation")
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat marker: %v", err)
		}
		if time.Now().After(markerDeadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestOSRunner_ParentCancellationNotTimedOut verifies that when the caller
// cancels the context, TimedOut stays false. The mutant that drops the
// ctx.Err() == nil guard would wrongly report TimedOut=true on parent
// cancellation.
func TestOSRunner_ParentCancellationNotTimedOut(t *testing.T) {
	dir := collecttest.FakeGcloud(t, "sleep 30")
	r := collect.OSRunner{}
	e := collect.Exec{
		Path: filepath.Join(dir, "gcloud"),
		Env:  []string{fmt.Sprintf("PATH=%s", collecttest.PathWith(dir))},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	out, err := r.Run(ctx, e, collect.Limits{Timeout: 30 * time.Second, MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	if out.TimedOut {
		t.Fatalf("expected TimedOut=false when parent cancels, got %+v", out)
	}
	if out.ExitCode == 0 {
		t.Fatal("expected non-zero exit code after parent cancellation kills child")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Run took %v after parent cancellation; expected prompt return", elapsed)
	}
}

// TestOSRunner_WaitDelayEnsuresPromptReturn verifies that cmd.WaitDelay
// reports incomplete output and cleans up a background grandchild that keeps
// stdout open after the direct child exits.
func TestOSRunner_WaitDelayEnsuresPromptReturn(t *testing.T) {
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	release := filepath.Join(dir, "release")
	marker := filepath.Join(dir, "marker")
	script := `( touch "$READY"; while [ ! -e "$RELEASE" ]; do sleep 0.01; done; echo x > "$MARK" ) & while [ ! -e "$READY" ]; do sleep 0.01; done; echo hi`
	scriptDir := collecttest.FakeGcloud(t, script)
	e := collect.Exec{
		Path: filepath.Join(scriptDir, "gcloud"),
		Env: []string{
			fmt.Sprintf("PATH=%s", collecttest.PathWith(scriptDir)),
			fmt.Sprintf("READY=%s", ready),
			fmt.Sprintf("RELEASE=%s", release),
			fmt.Sprintf("MARK=%s", marker),
		},
	}
	start := time.Now()
	out, err := (collect.OSRunner{}).Run(context.Background(), e, collect.Limits{Timeout: 5 * time.Second, MaxOutput: 1 << 20})
	elapsed := time.Since(start)
	if releaseErr := os.WriteFile(release, nil, 0o600); releaseErr != nil {
		t.Fatal(releaseErr)
	}
	markerDeadline := time.Now().Add(500 * time.Millisecond)
	markerExists := false
	for time.Now().Before(markerDeadline) {
		if _, statErr := os.Stat(marker); statErr == nil {
			markerExists = true
			break
		} else if !os.IsNotExist(statErr) {
			t.Fatalf("stat marker: %v", statErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("expected exec.ErrWaitDelay for incomplete output, got %v; output=%+v", err, out)
	}
	if markerExists {
		t.Fatal("marker file exists: background grandchild survived WaitDelay cleanup")
	}
	if string(out.Stdout) != "hi\n" {
		t.Fatalf("expected stdout 'hi\\n', got %q", string(out.Stdout))
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("Run took %v; WaitDelay should ensure prompt return when grandchild holds stdout", elapsed)
	}
}

func TestOSRunner_OutputLimitTruncates(t *testing.T) {
	// dd writes 2 MiB of zero bytes; tr converts them to 'x'.
	script := `dd if=/dev/zero bs=1048576 count=2 2>/dev/null | tr '\0' x`
	out, err := run(t, script, collect.Limits{Timeout: 10 * time.Second, MaxOutput: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Truncated {
		t.Fatalf("expected Truncated=true when MaxOutput=1024 and child writes 2 MiB, got %+v", out)
	}
	if len(out.Stdout) != 1024 {
		t.Fatalf("expected stdout length exactly 1024 (MaxOutput), got %d", len(out.Stdout))
	}
}

func TestOSRunner_ExitCodeCaptured(t *testing.T) {
	out, err := run(t, `echo boom >&2; exit 7`, collect.Limits{Timeout: 5 * time.Second, MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode != 7 {
		t.Fatalf("expected ExitCode=7, got %+v", out)
	}
	if !strings.Contains(string(out.Stderr), "boom") {
		t.Fatalf("expected stderr to contain 'boom', got %q", string(out.Stderr))
	}
}

func TestOSRunner_StdinDelivered(t *testing.T) {
	dir := collecttest.FakeGcloud(t, "cat")
	r := collect.OSRunner{}
	e := collect.Exec{
		Path:  filepath.Join(dir, "gcloud"),
		Stdin: []byte("hello-stdin\n"),
		Env:   []string{fmt.Sprintf("PATH=%s", collecttest.PathWith(dir))},
	}
	out, err := r.Run(context.Background(), e, collect.Limits{Timeout: 5 * time.Second, MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Stdout) != "hello-stdin\n" {
		t.Fatalf("expected stdout 'hello-stdin\\n', got %q", string(out.Stdout))
	}
}

func TestOSRunner_MissingExecutableReturnsError(t *testing.T) {
	r := collect.OSRunner{}
	e := collect.Exec{Path: "/nonexistent/path/command"}
	_, err := r.Run(context.Background(), e, collect.Limits{Timeout: 5 * time.Second, MaxOutput: 1 << 20})
	if err == nil {
		t.Fatal("expected error for non-existent executable")
	}
}

// TestOSRunner_StdoutExactnessStress runs a script that prints 60 120 bytes
// (120 lines of 501 bytes each) 100 times and asserts the output length is
// exact every time. The old pipe + goroutine design lost the tail of stdout
// in probabilistic fashion (~2 out of 400 runs). Setup is shared across
// iterations to keep the test under 3 s.
func TestOSRunner_StdoutExactnessStress(t *testing.T) {
	// 120 lines of 500 zero-padded digits plus newline = 501 bytes per line.
	script := `i=0; while [ "$i" -lt 120 ]; do printf '%0500d\n' 0; i=$((i+1)); done`
	dir := collecttest.FakeGcloud(t, script)
	r := collect.OSRunner{}
	e := collect.Exec{
		Path: filepath.Join(dir, "gcloud"),
		Env:  []string{fmt.Sprintf("PATH=%s", collecttest.PathWith(dir))},
	}
	limits := collect.Limits{Timeout: 30 * time.Second, MaxOutput: 1 << 20}
	const expected = 120 * 501
	for n := 0; n < 100; n++ {
		out, err := r.Run(context.Background(), e, limits)
		if err != nil {
			t.Fatalf("iteration %d: %v", n, err)
		}
		if len(out.Stdout) != expected {
			t.Fatalf("iteration %d: expected %d bytes, got %d", n, expected, len(out.Stdout))
		}
	}
}

func TestOSRunner_StderrExceedsCapDoesNotTruncate(t *testing.T) {
	// Write 65 KiB to stderr, then print a known string to stdout.  Only
	// stdout exceeding MaxOutput should set Truncated.
	script := `dd if=/dev/zero bs=1024 count=65 2>/dev/null | tr '\0' x >&2; echo ok`
	out, err := run(t, script, collect.Limits{Timeout: 10 * time.Second, MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode != 0 {
		t.Fatalf("expected ExitCode=0, got %d", out.ExitCode)
	}
	if out.Truncated {
		t.Fatal("Truncated must be false when only stderr exceeds its 64 KiB cap; Truncated tracks stdout alone")
	}
	if len(out.Stderr) != 65536 {
		t.Fatalf("expected stderr length exactly 65536 (64 KiB), got %d", len(out.Stderr))
	}
	if string(out.Stdout) != "ok\n" {
		t.Fatalf("expected stdout 'ok\\n', got %q", string(out.Stdout))
	}
}

func TestOSRunner_NilEnvIsEmpty(t *testing.T) {
	// t.Setenv sets a variable in the Go process. With nil Env the child
	// must NOT inherit it — nil means an empty environment.
	t.Setenv("TEST_VAR", "inherited")
	dir := collecttest.FakeGcloud(t, `echo "[${TEST_VAR}]"`)
	r := collect.OSRunner{}
	e := collect.Exec{
		Path: filepath.Join(dir, "gcloud"),
		Env:  nil,
	}
	out, err := r.Run(context.Background(), e, collect.Limits{Timeout: 5 * time.Second, MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out.Stdout)) != "[]" {
		t.Fatalf("expected '[]' (empty env, no inheritance), got %q", string(out.Stdout))
	}
}

func TestOSRunner_ZeroTimeoutDoesNotTimeout(t *testing.T) {
	out, err := run(t, `echo ok`, collect.Limits{Timeout: 0, MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if out.TimedOut {
		t.Fatal("expected TimedOut=false when Timeout=0")
	}
	if out.ExitCode != 0 {
		t.Fatalf("expected ExitCode=0, got %d", out.ExitCode)
	}
	if strings.TrimSpace(string(out.Stdout)) != "ok" {
		t.Fatalf("expected 'ok', got %q", string(out.Stdout))
	}
}

func TestChildEnv_WhitelistAndOverride(t *testing.T) {
	base := []string{
		"SECRET=xxx",
		"PATH=/usr/bin:/bin",
		"HOME=/home/user",
		"LANG=en_US.UTF-8",
	}
	overrides := map[string]string{
		"PATH": "/fake",
	}
	result := collect.ChildEnv(base, overrides)
	if len(result) != 3 {
		t.Fatalf("expected 3 entries (PATH, HOME, LANG), got %d: %v", len(result), result)
	}
	// Verify ordering: sorted by name.
	if result[0] != "HOME=/home/user" {
		t.Fatalf("expected HOME first, got %q", result[0])
	}
	if result[1] != "LANG=en_US.UTF-8" {
		t.Fatalf("expected LANG second, got %q", result[1])
	}
	if result[2] != "PATH=/fake" {
		t.Fatalf("expected PATH=/fake (override), got %q", result[2])
	}
	// SECRET must not appear.
	for _, e := range result {
		if strings.HasPrefix(e, "SECRET=") {
			t.Fatalf("SECRET was not filtered out: %v", result)
		}
	}
}

func TestChildEnv_KeepsOnlyRuntimeCloudSdkVariables(t *testing.T) {
	base := []string{
		// These CLOUDSDK_ variables must be dropped (not in the allowlist).
		"CLOUDSDK_CORE_ACCOUNT=acc",
		"CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT=sa",
		"CLOUDSDK_AUTH_AUTHORITY_SELECTOR=sel",
		"CLOUDSDK_AUTH_AUTHORIZATION_TOKEN_FILE=tok",
		"CLOUDSDK_CORE_UNIVERSE_DOMAIN=dom",
		"CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE=ep",
		"CLOUDSDK_CORE_PROJECT=proj",
		"CLOUDSDK_PROXY_TYPE=type",
		// GOOGLE_APPLICATION_CREDENTIALS must be dropped.
		"GOOGLE_APPLICATION_CREDENTIALS=creds",
		// These CLOUDSDK_ variables are in the allowlist.
		"CLOUDSDK_CONFIG=cfg",
		"CLOUDSDK_PYTHON=py",
	}
	// An override that is not in the allowlist is kept because overrides
	// always win — but in this case we are adding a variable.
	overrides := map[string]string{
		"CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
	}
	result := collect.ChildEnv(base, overrides)
	// Expected: CLOUDSDK_CONFIG, CLOUDSDK_PYTHON, plus the override.
	if len(result) != 3 {
		t.Fatalf("expected 3 entries, got %d: %v", len(result), result)
	}
	has := func(name string) bool {
		for _, e := range result {
			if strings.HasPrefix(e, name+"=") {
				return true
			}
		}
		return false
	}
	if !has("CLOUDSDK_CONFIG") {
		t.Fatal("CLOUDSDK_CONFIG missing")
	}
	if !has("CLOUDSDK_PYTHON") {
		t.Fatal("CLOUDSDK_PYTHON missing")
	}
	if !has("CLOUDSDK_CORE_DISABLE_PROMPTS") {
		t.Fatal("CLOUDSDK_CORE_DISABLE_PROMPTS override missing")
	}
	// Verify the excluded variables are absent.
	forbidden := []string{
		"CLOUDSDK_CORE_ACCOUNT",
		"CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT",
		"CLOUDSDK_AUTH_AUTHORITY_SELECTOR",
		"CLOUDSDK_AUTH_AUTHORIZATION_TOKEN_FILE",
		"CLOUDSDK_CORE_UNIVERSE_DOMAIN",
		"CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE",
		"CLOUDSDK_CORE_PROJECT",
		"CLOUDSDK_PROXY_TYPE",
		"GOOGLE_APPLICATION_CREDENTIALS",
	}
	for _, name := range forbidden {
		if has(name) {
			t.Fatalf("%s should have been filtered out, got %v", name, result)
		}
	}
}

// TestChildEnv_ExactAllowlistSet verifies the exact whitelist set, covering
// LC_ prefix matching (kept), non-prefix "LC_" or "LCX" names (dropped),
// and both upper- and lower-case proxy variables (all kept). The result is
// pinned element-by-element to catch mutants that drop the lower-case proxy
// cases or the LC_ prefix check.
func TestChildEnv_ExactAllowlistSet(t *testing.T) {
	base := []string{
		"LC_ALL=en_US.UTF-8",
		"LC_CTYPE=UTF-8",
		"XLC_VAR=bad", // LC_ appears in middle, not at start
		"LCX_VAR=bad", // LCX prefix, not LC_
		"http_proxy=http://proxy",
		"https_proxy=https://proxy",
		"no_proxy=localhost",
		"HTTP_PROXY=HTTP://PROXY",
		"HTTPS_PROXY=HTTPS://PROXY",
		"NO_PROXY=LOCALHOST",
		"SECRET=xxx",
	}
	result := collect.ChildEnv(base, nil)
	expected := []string{
		"HTTPS_PROXY=HTTPS://PROXY",
		"HTTP_PROXY=HTTP://PROXY",
		"LC_ALL=en_US.UTF-8",
		"LC_CTYPE=UTF-8",
		"NO_PROXY=LOCALHOST",
		"http_proxy=http://proxy",
		"https_proxy=https://proxy",
		"no_proxy=localhost",
	}
	if len(result) != len(expected) {
		t.Fatalf("expected %d entries, got %d: %v", len(expected), len(result), result)
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Fatalf("result[%d]: expected %q, got %q", i, expected[i], result[i])
		}
	}
}
