package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/SummerQXY/gbencher/internal/fixture"
	"github.com/SummerQXY/gbencher/internal/rule"
)

func rulesTestCmd(stdout, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "test [path]",
		Short: "Evaluate offline rule fixtures",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "testdata/rules"
			if len(args) == 1 {
				path = args[0]
			}
			return runRulesTest(path, stdout, stderr)
		},
	}
}

func runRulesTest(path string, stdout, stderr io.Writer) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s: not a directory", path)
	}
	set, err := rule.LoadEmbedded()
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	files, err := fixtureFiles(path)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("%s: no fixture files found", path)
	}
	failures := 0
	for start := 0; start < len(files); {
		dir := filepath.Dir(files[start])
		end := start
		for end < len(files) && filepath.Dir(files[end]) == dir {
			end++
		}
		cases, err := fixture.LoadDir(dir)
		if err != nil {
			return err
		}
		if len(cases) != end-start {
			return fmt.Errorf("fixture directory %s changed while reading", dir)
		}
		for i, current := range cases {
			file := files[start+i]
			if len(current.Expect) == 0 {
				return fmt.Errorf("fixture %s: expect must not be empty", file)
			}
			byRule := make(map[string][]fixture.Expect)
			for _, expected := range current.Expect {
				byRule[expected.RuleID] = append(byRule[expected.RuleID], expected)
			}
			for ruleID, expected := range byRule {
				selected, ok := set.Get(ruleID)
				if !ok {
					return fmt.Errorf("fixture %s: unknown rule %q", file, ruleID)
				}
				actual, err := fixture.Evaluate(current, selected)
				if err != nil {
					return fmt.Errorf("fixture %s rule %s: %w", file, ruleID, err)
				}
				if equalExpected(actual, expected) {
					continue
				}
				actualByResource := make(map[string]string, len(actual))
				expectedByResource := make(map[string]string, len(expected))
				for _, result := range actual {
					actualByResource[result.ResourceKey] = result.Status
				}
				for _, want := range expected {
					expectedByResource[want.ResourceKey] = want.Status
				}
				keys := make(map[string]struct{}, len(actualByResource)+len(expectedByResource))
				for key := range actualByResource {
					keys[key] = struct{}{}
				}
				for key := range expectedByResource {
					keys[key] = struct{}{}
				}
				orderedKeys := make([]string, 0, len(keys))
				for key := range keys {
					orderedKeys = append(orderedKeys, key)
				}
				sort.Strings(orderedKeys)
				for _, key := range orderedKeys {
					want, wantOK := expectedByResource[key]
					got, gotOK := actualByResource[key]
					if !wantOK {
						want = "<no expectation>"
					}
					if !gotOK {
						got = "<no result>"
					}
					if want != got {
						fmt.Fprintf(stdout, "FAIL %s %s resource=%s expected=%s actual=%s\n", ruleID, filepath.Base(file), key, want, got)
						failures++
					}
				}
			}
		}
		start = end
	}
	if failures > 0 {
		fmt.Fprintf(stderr, "rules test: %d mismatch(es) across %d fixture(s)\n", failures, len(files))
		return &exitError{code: 1}
	}
	fmt.Fprintf(stderr, "rules test: %d fixture(s) passed\n", len(files))
	return nil
}

func fixtureFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk fixture directory %s: %w", root, err)
	}
	sort.Strings(files)
	return files, nil
}

func equalExpected(actual, expected []fixture.Expect) bool {
	left := append([]fixture.Expect(nil), actual...)
	right := append([]fixture.Expect(nil), expected...)
	less := func(items []fixture.Expect) func(int, int) bool {
		return func(i, j int) bool {
			if items[i].ResourceKey != items[j].ResourceKey {
				return items[i].ResourceKey < items[j].ResourceKey
			}
			if items[i].RuleID != items[j].RuleID {
				return items[i].RuleID < items[j].RuleID
			}
			return items[i].Status < items[j].Status
		}
	}
	sort.Slice(left, less(left))
	sort.Slice(right, less(right))
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
