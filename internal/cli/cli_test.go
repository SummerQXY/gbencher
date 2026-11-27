package cli_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/cli"
)

// fixtureRoot is the directory of the lint fixtures, relative to this package.
const fixtureRoot = "../../testdata/lint/"

func TestRulesLint_CleanDirExitsZero(t *testing.T) {
	var out, errb bytes.Buffer
	code := cli.Execute([]string{"rules", "lint", fixtureRoot + "clean-dir"}, nil, &out, &errb, nil)
	if code != 0 || out.Len() != 0 {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
}

func TestRulesLint_FindingsExitOneAndPrintCode(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(fixtureRoot + "cel-compile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cel-compile.yaml"), src, 0644); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := cli.Execute([]string{"rules", "lint", dir}, nil, &out, &errb, nil)
	if code != 1 {
		t.Errorf("exit code: %d, want 1", code)
	}
	if !strings.Contains(out.String(), "cel-compile") {
		t.Errorf("stdout does not contain cel-compile: %q", out.String())
	}
}

func TestRulesLint_MissingPathExitsTwo(t *testing.T) {
	path := "/no/such/path/for/lint/test"
	var out, errb bytes.Buffer
	code := cli.Execute([]string{"rules", "lint", path}, nil, &out, &errb, nil)
	if code != 2 {
		t.Errorf("exit code: %d, want 2", code)
	}
	if !strings.Contains(errb.String(), path) {
		t.Errorf("stderr does not contain %q: %q", path, errb.String())
	}
}

func TestRulesLint_UsesTheEmbeddedAllowlist(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(fixtureRoot + "command-not-allowed.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "command-not-allowed.yaml"), src, 0644); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := cli.Execute([]string{"rules", "lint", dir}, nil, &out, &errb, nil)
	if code != 1 {
		t.Errorf("exit code: %d, want 1", code)
	}
	if !strings.Contains(out.String(), "command-not-allowed") {
		t.Errorf("stdout does not contain command-not-allowed: %q", out.String())
	}
}

func TestRulesLint_EmptyDirIsAFinding(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	code := cli.Execute([]string{"rules", "lint", dir}, nil, &out, &errb, nil)
	if code != 1 {
		t.Errorf("exit code: %d, want 1", code)
	}
	wantOut := "lint: no-rule-files: no rule files found in " + dir + "\n"
	if out.String() != wantOut {
		t.Errorf("stdout: got %q, want %q", out.String(), wantOut)
	}
	wantErr := "lint: 1 finding(s) in " + dir + "\n"
	if errb.String() != wantErr {
		t.Errorf("stderr: got %q, want %q", errb.String(), wantErr)
	}
}

func TestExecute_UnknownSubcommandExitsTwo(t *testing.T) {
	var out, errb bytes.Buffer
	code := cli.Execute([]string{"nope"}, nil, &out, &errb, nil)
	if code != 2 {
		t.Errorf("exit code: %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "gbench:") {
		t.Errorf("stderr does not contain gbench:: %q", errb.String())
	}
}

func TestExecute_HelpExitsZero(t *testing.T) {
	var out, errb bytes.Buffer
	code := cli.Execute([]string{"help"}, nil, &out, &errb, nil)
	if code != 0 {
		t.Errorf("exit code: %d, want 0", code)
	}
}

func TestExecute_UnknownRulesSubcommandExitsTwo(t *testing.T) {
	// An unknown subcommand under rules exits 2 with the typo in stderr.
	var out, errb bytes.Buffer
	code := cli.Execute([]string{"rules", "bogus"}, nil, &out, &errb, nil)
	if code != 2 {
		t.Fatalf("exit code: %d, want 2: out=%q err=%q", code, out.String(), errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout not empty: %q", out.String())
	}
	if !strings.Contains(errb.String(), "bogus") {
		t.Errorf("stderr does not contain bogus: %q", errb.String())
	}

	// Bare rules still exits 0 and prints help to stdout.
	out.Reset()
	errb.Reset()
	code = cli.Execute([]string{"rules"}, nil, &out, &errb, nil)
	if code != 0 {
		t.Errorf("bare rules exit code: %d, want 0", code)
	}
	if out.Len() == 0 {
		t.Errorf("bare rules stdout is empty")
	}
}

func TestRulesLint_DefaultScansTheEmbeddedCorpus(t *testing.T) {
	var out, errb bytes.Buffer
	code := cli.Execute([]string{"rules", "lint"}, nil, &out, &errb, nil)
	if code == 2 {
		t.Fatalf("exit code 2, want 0 or 1: out=%q err=%q", out.String(), errb.String())
	}
	if strings.Contains(out.String(), "no-rule-files") {
		t.Errorf("stdout contains no-rule-files: %q", out.String())
	}
	if !strings.Contains(errb.String(), "embedded rules") {
		t.Errorf("stderr does not contain 'embedded rules': %q", errb.String())
	}
}

func TestRulesTest_ExitsOneOnMismatch(t *testing.T) {
	dir := t.TempDir()
	content := `{"target":{"type":"project","project_id":"example-prod"},"data":{"firewalls":[{"name":"allow-ssh","direction":"INGRESS","sourceRanges":["0.0.0.0/0"],"allowed":[{"IPProtocol":"tcp","ports":["22"]}]}]},"expect":[{"rule_id":"cis-gcp-3.6","resource_key":"projects/example-prod/allow-ssh","status":"PASS"}],"meta":{"provenance":{"firewalls":"handwritten"}}}`
	if err := os.WriteFile(filepath.Join(dir, "mismatch.json"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := cli.Execute([]string{"rules", "test", dir}, nil, &out, &errb, nil)
	if code != 1 {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "expected=PASS actual=FAIL") {
		t.Fatalf("missing mismatch details: %q", out.String())
	}
}

func TestRulesTest_UnknownRuleInFixtureIsError(t *testing.T) {
	dir := t.TempDir()
	content := `{"target":{"type":"project","project_id":"example-prod"},"data":{},"expect":[{"rule_id":"unknown-rule","resource_key":"example","status":"PASS"}],"meta":{"provenance":{}}}`
	if err := os.WriteFile(filepath.Join(dir, "unknown.json"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := cli.Execute([]string{"rules", "test", dir}, nil, &out, &errb, nil)
	if code != 2 || !strings.Contains(errb.String(), `unknown rule "unknown-rule"`) {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
}

func TestRulesTest_DefaultFixturesPass(t *testing.T) {
	var out, errb bytes.Buffer
	code := cli.Execute([]string{"rules", "test", "../../testdata/rules"}, nil, &out, &errb, nil)
	fixtures, err := filepath.Glob("../../testdata/rules/*/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || !strings.Contains(errb.String(), fmt.Sprintf("%d fixture(s) passed", len(fixtures))) {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
}
