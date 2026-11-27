package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/cli"
	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/rules"
	"github.com/SummerQXY/gbencher/schemas"
)

func TestRulesListJSON_HasVerificationAndParamTypes(t *testing.T) {
	var out bytes.Buffer
	if code := cli.Execute([]string{"rules", "list", "--format=json"}, nil, &out, &bytes.Buffer{}, nil); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if err := schemas.ValidateJSON("catalog", out.Bytes()); err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(out.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	for _, current := range catalog.Rules {
		if current["verification"] == nil {
			t.Fatalf("missing verification: %v", current["id"])
		}
		params, ok := current["params"].(map[string]any)
		if !ok {
			t.Fatalf("params has type %T", current["params"])
		}
		for name, param := range params {
			value, ok := param.(map[string]any)
			if !ok || value["type"] == nil {
				t.Fatalf("param %s has no type: %#v", name, param)
			}
		}
	}
}

func TestRulesList_FiltersUseOrWithinFlagAndAndAcrossFlags(t *testing.T) {
	var out bytes.Buffer
	args := []string{"rules", "list", "--format=json", "--benchmark=cis-gcp-foundation@5.0.0", "--benchmark=cis-gke@2.0.0", "--level=L1", "--level=L2", "--mode=deterministic", "--scope=project", "--verification=none"}
	if code := cli.Execute(args, nil, &out, &bytes.Buffer{}, nil); code != 0 {
		t.Fatalf("code=%d", code)
	}
	var value struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(out.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if len(value.Rules) == 0 {
		t.Fatal("combined filters returned no rules")
	}
	for _, current := range value.Rules {
		benchmark := current["benchmark"].(map[string]any)
		base := benchmark["id"].(string) + "@" + benchmark["version"].(string)
		if base != "cis-gcp-foundation@5.0.0" && base != "cis-gke@2.0.0" {
			t.Errorf("unexpected benchmark %s", base)
		}
		if current["mode"] != "deterministic" || current["scope"] != "project" || current["verification"] != "none" {
			t.Errorf("rule violates AND filters: %#v", current)
		}
	}
}

func TestRulesList_RejectsUnknownFilterValues(t *testing.T) {
	for _, flag := range []string{"--level=bad", "--mode=bad", "--scope=bad", "--verification=bad", "--benchmark=missing@1.0"} {
		var stderr bytes.Buffer
		if code := cli.Execute([]string{"rules", "list", flag}, nil, &bytes.Buffer{}, &stderr, nil); code != 2 {
			t.Errorf("%s: code=%d stderr=%q", flag, code, stderr.String())
		}
	}
}

func TestRulesShow_RendersRESTAndKubectlSteps(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	var apiRule, kubectlRule string
	for _, current := range set.Rules {
		for _, step := range current.Collect {
			if step.API != nil && apiRule == "" {
				apiRule = current.ID
			}
			if step.Kubectl != "" && kubectlRule == "" {
				kubectlRule = current.ID
			}
		}
	}
	for _, id := range []string{apiRule, kubectlRule} {
		if id == "" {
			t.Fatal("corpus does not contain both REST and kubectl rules")
		}
		var out bytes.Buffer
		if code := cli.Execute([]string{"rules", "show", id, "--project=example-prod"}, nil, &out, &bytes.Buffer{}, nil); code != 0 {
			t.Fatalf("%s: code=%d", id, code)
		}
		if !strings.Contains(out.String(), "commands:") {
			t.Errorf("%s: missing commands section", id)
		}
	}
	var apiOut bytes.Buffer
	if code := cli.Execute([]string{"rules", "show", apiRule, "--project=example-prod"}, nil, &apiOut, &bytes.Buffer{}, nil); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(apiOut.String(), "GET https://") {
		t.Fatalf("REST step not shown: %q", apiOut.String()[max(0, apiOut.Len()-500):])
	}
	var kubectlOut bytes.Buffer
	if code := cli.Execute([]string{"rules", "show", kubectlRule, "--project=example-prod"}, nil, &kubectlOut, &bytes.Buffer{}, nil); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(kubectlOut.String(), "kubectl ") {
		t.Fatalf("kubectl step not shown: %q", kubectlOut.String()[max(0, kubectlOut.Len()-500):])
	}
}

func TestRulesLint_WriteVerificationDoesNotUpdateOnFindings(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	entry := set.Rules[0]
	data, err := rules.FS.ReadFile(entry.SourceFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, entry.SourceFile)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, entry.SourceFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("rules: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	verification := []byte("rules:\n  " + entry.ID + ": fixture\n")
	verificationPath := filepath.Join(dir, "verification.yaml")
	if err := os.WriteFile(verificationPath, verification, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"rules", "lint", dir, "--write-verification"}, nil, &stdout, &stderr, nil)
	if code != 1 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	after, err := os.ReadFile(verificationPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, verification) {
		t.Fatalf("verification changed on lint findings: %q", after)
	}
}

func TestVersion_PrintsRulesetHash(t *testing.T) {
	var out bytes.Buffer
	if code := cli.Execute([]string{"version"}, nil, &out, &bytes.Buffer{}, nil); code != 0 {
		t.Fatalf("code=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "ruleset_hash: sha256:") || !strings.Contains(out.String(), "schema_version:") {
		t.Fatalf("version output lacks metadata: %q", out.String())
	}
}

func TestDryRun_MakesNoExternalCalls(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "called")
	program := filepath.Join(dir, "gcloud")
	script := "#!/bin/sh\nprintf called >> '" + strings.ReplaceAll(marker, "'", "'\\''") + "'\nexit 0\n"
	if err := os.WriteFile(program, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--dry-run", "--format=json"}, nil, &out, &errb, []string{"PATH=" + dir})
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errb.String())
	}
	var value map[string]any
	if err := json.Unmarshal(out.Bytes(), &value); err != nil {
		t.Fatalf("dry-run output is not JSON: %v", err)
	}
	if len(value["units"].([]any)) == 0 {
		t.Fatal("dry-run returned no units")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("gcloud was called: %v", err)
	}
}

func TestDryRun_JSONListsCapabilityGaps(t *testing.T) {
	var out, errb bytes.Buffer
	code := cli.Execute([]string{"scan", "--project=example-prod", "--dry-run", "--format=json", "--rule=cis-gke-*"}, nil, &out, &errb, fakeEnv(t))
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errb.String())
	}
	if !strings.Contains(out.String(), `"capability_satisfied":false`) {
		t.Fatalf("dry-run did not list disabled capabilities: %q", out.String()[:min(out.Len(), 500)])
	}
}

func TestDryRun_LowerBoundIsZeroWhenUnitCannotRun(t *testing.T) {
	args := []string{"scan", "--project=example-prod", "--dry-run", "--rule=cis-gke-5.6.7"}
	var jsonOut, stderr bytes.Buffer
	if code := cli.Execute(append(args, "--format=json"), nil, &jsonOut, &stderr, nil); code != 0 {
		t.Fatalf("JSON code=%d stderr=%q", code, stderr.String())
	}
	var plan struct {
		Units []struct {
			CapabilitySatisfied bool   `json:"capability_satisfied"`
			TargetStatus        string `json:"target_status"`
			Commands            []any  `json:"commands"`
			Count               int    `json:"command_count_lower_bound"`
			Basis               string `json:"command_count_basis"`
		} `json:"units"`
	}
	if err := json.Unmarshal(jsonOut.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Units) != 1 {
		t.Fatalf("units=%d", len(plan.Units))
	}
	unit := plan.Units[0]
	if unit.CapabilitySatisfied || unit.TargetStatus != "requires_cluster_enumeration" {
		t.Fatalf("unit status = %+v", unit)
	}
	if len(unit.Commands) == 0 {
		t.Fatal("static command listing was dropped")
	}
	if unit.Count != 0 {
		t.Fatalf("lower bound=%d with a known capability gap", unit.Count)
	}
	if unit.Basis != "capability_gap" {
		t.Fatalf("count basis=%q", unit.Basis)
	}

	var tableOut bytes.Buffer
	if code := cli.Execute(append(args, "--format=table"), nil, &tableOut, &bytes.Buffer{}, nil); code != 0 {
		t.Fatalf("table code=%d", code)
	}
	if !strings.Contains(tableOut.String(), "0 command(s) minimum (capability_gap)") {
		t.Fatalf("table count differs from JSON: %q", tableOut.String())
	}
}

func TestVerification_StaleFileIsFinding(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, r := range set.Rules {
		data, readErr := rules.FS.ReadFile(r.SourceFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, r.SourceFile)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, r.SourceFile), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stale := "rules:\n"
	for i, r := range set.Rules {
		level := "none"
		if i == 0 {
			level = "fixture"
		}
		stale += "  " + r.ID + ": " + level + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "verification.yaml"), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, loadErr := rule.LoadVerificationFS(os.DirFS(dir))
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if loaded.Rules[set.Rules[0].ID] != rule.VerificationFixture {
		t.Fatal("stale fixture level was not parsed")
	}
	var out, errb bytes.Buffer
	code := cli.Execute([]string{"rules", "lint", dir}, nil, &out, &errb, nil)
	if code != 1 || !strings.Contains(out.String(), "verification-stale") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errb.String())
	}
}
