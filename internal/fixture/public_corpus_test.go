package fixture_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/rule"
)

func TestPublicFixtureCorpusExcludesCapturedSources(t *testing.T) {
	root := "../../testdata/rules"
	count := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var payload struct {
			Meta struct {
				Provenance map[string]string `json:"provenance"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			return err
		}
		for step, provenance := range payload.Meta.Provenance {
			if provenance == "captured" || provenance == "captured+mutated" {
				t.Errorf("%s contains non-public provenance for %s", path, step)
			}
		}
		count++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("public fixture corpus is empty")
	}
}

func TestPublicVerificationMatchesFixtures(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	computed, err := rule.ComputeVerification(set, "../../testdata/rules", nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := rule.LoadVerification()
	if err != nil {
		t.Fatal(err)
	}
	if !rule.VerificationEqual(computed, *manifest) {
		t.Fatal("embedded verification levels do not match the public fixture corpus")
	}
}

func TestVerificationAdvancesWithSyntheticCases(t *testing.T) {
	set := &rule.Set{Rules: []*rule.Rule{
		{ID: "example-a", Check: rule.Check{Assert: "true"}},
		{ID: "example-b", Check: rule.Check{Assert: "true"}},
		{ID: "example-c", Check: rule.Check{Assert: "true"}},
		{ID: "example-d", Check: rule.Check{Assert: "true"}},
	}}
	root := t.TempDir()
	assertLevels := func(want int) {
		t.Helper()
		got, err := rule.ComputeVerification(set, root, nil)
		if err != nil {
			t.Fatal(err)
		}
		fixtures := 0
		for _, level := range got.Rules {
			if level == rule.VerificationFixture {
				fixtures++
			}
		}
		if fixtures != want {
			t.Fatalf("fixture verification count = %d, want %d", fixtures, want)
		}
	}
	assertLevels(0)
	writeSyntheticPassFailCases(t, root, set.Rules[0].ID)
	writeSyntheticPassFailCases(t, root, set.Rules[1].ID)
	assertLevels(2)
	writeSyntheticPassFailCases(t, root, set.Rules[2].ID)
	assertLevels(3)
	writeSyntheticPassFailCases(t, root, set.Rules[3].ID)
	assertLevels(4)
}

func writeSyntheticPassFailCases(t *testing.T, root, ruleID string) {
	t.Helper()
	dir := filepath.Join(root, ruleID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"PASS", "FAIL"} {
		payload := map[string]any{
			"target": map[string]any{"type": "project", "project_id": "example-project"},
			"data":   map[string]any{},
			"expect": []map[string]string{{"rule_id": ruleID, "resource_key": "projects/example-project", "status": status}},
			"meta":   map[string]any{"provenance": map[string]string{}},
		}
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		name := strings.ToLower(status) + ".json"
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
