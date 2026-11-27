package eval_test

import (
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/eval"
	"github.com/SummerQXY/gbencher/internal/fixture"
	"github.com/SummerQXY/gbencher/internal/rule"
)

func TestEnv_M3RuleCorpusFitsFinalCostLimit(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	verification, err := rule.LoadVerification()
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob("../../testdata/rules/*/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("fixture corpus is empty")
	}
	sort.Strings(files)
	type measurement struct {
		evaluations int
		expressions map[string]struct{}
		siteCounts  map[string]int
		peak        uint64
		peakRule    string
		peakSite    string
	}
	all := measurement{expressions: make(map[string]struct{}), siteCounts: make(map[string]int)}
	gke := measurement{expressions: make(map[string]struct{}), siteCounts: make(map[string]int)}
	var currentRule string
	rulesByID := make(map[string]*rule.Rule, len(set.Rules))
	for _, selected := range set.Rules {
		rulesByID[selected.ID] = selected
	}
	env, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	env.SetCostObserver(func(expr string, cost uint64) {
		key := currentRule + "\x00" + expr
		all.evaluations++
		all.expressions[key] = struct{}{}
		for _, site := range expressionSites(rulesByID[currentRule], expr) {
			all.siteCounts[site]++
		}
		if strings.HasPrefix(currentRule, "cis-gke-") {
			gke.evaluations++
			gke.expressions[key] = struct{}{}
			for _, site := range expressionSites(rulesByID[currentRule], expr) {
				gke.siteCounts[site]++
			}
		}
		if cost > all.peak {
			all.peak = cost
			all.peakRule = currentRule
			all.peakSite = strings.Join(expressionSites(rulesByID[currentRule], expr), ",")
		}
		if strings.HasPrefix(currentRule, "cis-gke-") && cost > gke.peak {
			gke.peak = cost
			gke.peakRule = currentRule
			gke.peakSite = strings.Join(expressionSites(rulesByID[currentRule], expr), ",")
		}
	})
	seenDirs := make(map[string]struct{})
	fixtureFiles := 0
	fixtureDirs := 0
	gkeFiles := 0
	gkeDirs := make(map[string]struct{})
	gkeRulesWithFixtures := make(map[string]struct{})
	for _, file := range files {
		dir := filepath.Dir(file)
		if _, seen := seenDirs[dir]; seen {
			continue
		}
		seenDirs[dir] = struct{}{}
		fixtureDirs++
		cases, err := fixture.LoadDir(dir)
		if err != nil {
			t.Fatalf("load %s: %v", file, err)
		}
		fixtureFiles += len(cases)
		if strings.Contains(dir, "cis-gke-") {
			gkeFiles += len(cases)
			gkeDirs[dir] = struct{}{}
		}
		for _, current := range cases {
			byRule := make(map[string][]fixture.Expect)
			for _, expected := range current.Expect {
				byRule[expected.RuleID] = append(byRule[expected.RuleID], expected)
			}
			for ruleID, expected := range byRule {
				selected, ok := set.Get(ruleID)
				if !ok {
					t.Fatalf("fixture %s references unknown rule %s", file, ruleID)
				}
				currentRule = ruleID
				actual, err := fixture.EvaluateWithEnv(current, selected, env)
				if err != nil {
					t.Fatalf("fixture %s rule %s: %v", file, ruleID, err)
				}
				sort.Slice(actual, func(i, j int) bool {
					if actual[i].ResourceKey != actual[j].ResourceKey {
						return actual[i].ResourceKey < actual[j].ResourceKey
					}
					if actual[i].RuleID != actual[j].RuleID {
						return actual[i].RuleID < actual[j].RuleID
					}
					return actual[i].Status < actual[j].Status
				})
				sort.Slice(expected, func(i, j int) bool {
					if expected[i].ResourceKey != expected[j].ResourceKey {
						return expected[i].ResourceKey < expected[j].ResourceKey
					}
					if expected[i].RuleID != expected[j].RuleID {
						return expected[i].RuleID < expected[j].RuleID
					}
					return expected[i].Status < expected[j].Status
				})
				if !reflect.DeepEqual(actual, expected) {
					t.Fatalf("fixture %s rule %s: got %+v, want %+v", file, ruleID, actual, expected)
				}
				if strings.HasPrefix(ruleID, "cis-gke-") {
					gkeRulesWithFixtures[ruleID] = struct{}{}
				}
			}
		}
	}
	setRules := 0
	gkeVerificationFixture := 0
	gkeForeachSites := 0
	var gkeFixtureDirsWithoutVerification []string
	for id, level := range verification.Rules {
		if strings.HasPrefix(id, "cis-gke-") && level == rule.VerificationFixture {
			gkeVerificationFixture++
		}
	}
	for dir := range gkeDirs {
		id := filepath.Base(dir)
		if verification.Rules[id] != rule.VerificationFixture {
			gkeFixtureDirsWithoutVerification = append(gkeFixtureDirsWithoutVerification, id)
		}
	}
	sort.Strings(gkeFixtureDirsWithoutVerification)
	for _, selected := range set.Rules {
		if strings.HasPrefix(selected.ID, "cis-gke-") {
			setRules++
			for _, step := range selected.Collect {
				if step.Foreach != "" {
					gkeForeachSites++
				}
			}
		}
	}
	t.Logf("fixture_files=%d fixture_dirs=%d gke_files=%d gke_dirs=%d gke_rules_with_fixtures=%d gke_verification_fixture=%d gke_fixture_dirs_without_verification=%v gke_rules_in_set=%d gke_foreach_sites_not_run_by_fixture_evaluator=%d", fixtureFiles, fixtureDirs, gkeFiles, len(gkeDirs), len(gkeRulesWithFixtures), gkeVerificationFixture, gkeFixtureDirsWithoutVerification, setRules, gkeForeachSites)
	t.Logf("all_expression_evaluations=%d all_unique_rule_expressions=%d all_peak_cost=%d all_peak_rule=%s all_peak_site=%s site_counts=%v", all.evaluations, len(all.expressions), all.peak, all.peakRule, all.peakSite, all.siteCounts)
	t.Logf("gke_expression_evaluations=%d gke_unique_rule_expressions=%d gke_peak_cost=%d gke_peak_rule=%s gke_peak_site=%s site_counts=%v", gke.evaluations, len(gke.expressions), gke.peak, gke.peakRule, gke.peakSite, gke.siteCounts)
	if fixtureFiles != len(files) {
		t.Fatalf("loaded %d fixture files, discovered %d", fixtureFiles, len(files))
	}
	if all.evaluations == 0 || all.peak == 0 {
		t.Fatal("fixture corpus did not produce CEL cost observations")
	}
	if all.siteCounts["collect.foreach"] != 0 || gke.siteCounts["collect.foreach"] != 0 {
		t.Fatal("fixture evaluation attributed a cost to an unexecuted collect.foreach expression")
	}
	if all.peak*10 > 1_000_000 || gke.peak*10 > 1_000_000 {
		t.Fatalf("observed peak exceeds the tenfold margin of the 1,000,000 limit: all=%d gke=%d", all.peak, gke.peak)
	}
	if gkeForeachSites > 0 {
		t.Logf("measurement blocker: fixture evaluator does not execute %d GKE collect.foreach sites", gkeForeachSites)
	}
}

func expressionSites(current *rule.Rule, expr string) []string {
	if current == nil {
		return nil
	}
	var sites []string
	if current.Resource != nil {
		if current.Resource.From == expr {
			sites = append(sites, "resource.from")
		}
		if current.Resource.Filter == expr {
			sites = append(sites, "resource.filter")
		}
		if current.Resource.Name == expr {
			sites = append(sites, "resource.name")
		}
		if current.Resource.Key == expr {
			sites = append(sites, "resource.key")
		}
	}
	if current.Check.Assert == expr {
		sites = append(sites, "check.assert")
	}
	if current.Check.ReviewWhen == expr {
		sites = append(sites, "check.review_when")
	}
	for _, evidence := range current.Evidence {
		if evidence == expr {
			sites = append(sites, "evidence")
		}
	}
	return sites
}

func TestEnv_CostLimitFailsClosedAtBoundary(t *testing.T) {
	e, err := eval.NewEnv()
	if err != nil {
		t.Fatal(err)
	}
	d := eval.NewData()
	d.Set("a", strings.Repeat("a", 50_000))
	params := map[string]any{"pattern": strings.Repeat("a", 1_000)}
	if _, err := e.Bool(nil, "data.a.matches(params.pattern)", d, nil, eval.Context{}, params); err == nil || !strings.Contains(strings.ToLower(err.Error()), "cost") {
		t.Fatal("oversized expression input passed the CEL cost limit")
	}
}
