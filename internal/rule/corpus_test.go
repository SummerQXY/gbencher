package rule_test

import (
	"io/fs"
	"strings"
	"testing"
	"unicode"

	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/internal/rule/lint"
	"github.com/SummerQXY/gbencher/profiles"
	"github.com/SummerQXY/gbencher/rules"
	"github.com/SummerQXY/gbencher/schemas"
)

func TestCorpusLoads(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	if set.Source != "embedded" {
		t.Errorf("Source = %q, want embedded", set.Source)
	}

	// Count rules per benchmark and unique files.
	fileSet := make(map[string]bool)
	var gcpRules, gkeRules int
	for _, r := range set.Rules {
		fileSet[r.SourceFile] = true
		switch {
		case strings.HasPrefix(r.Benchmark.ID, "cis-gcp-foundation"):
			gcpRules++
		case strings.HasPrefix(r.Benchmark.ID, "cis-gke"):
			gkeRules++
		default:
			t.Errorf("%s: unexpected benchmark id %q", r.ID, r.Benchmark.ID)
		}
	}
	if gcpRules != 93 {
		t.Errorf("GCP rules = %d, want 93", gcpRules)
	}
	if gkeRules != 54 {
		t.Errorf("GKE rules = %d, want 54", gkeRules)
	}
	if total := gcpRules + gkeRules; total != 147 {
		t.Errorf("total rules = %d, want 147", total)
	}
	if n := len(fileSet); n != 13 {
		t.Errorf("file count = %d, want 13", n)
	}
}

func TestCorpusLintClean(t *testing.T) {
	// Re-load the corpus to get files and violations for the lint check.
	files, violations, err := rule.LoadFiles(rules.FS)
	if err != nil {
		t.Fatalf("LoadFiles: %v", err)
	}
	allow, err := rule.LoadAllowlist()
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	fs := lint.Run(files, violations, lint.Options{Allow: allow})
	if len(fs) != 0 {
		t.Fatalf("lint findings in embedded rules:\n%s", lint.FormatText(fs))
	}
}

// TestAllowlistMatchesCorpus checks two directions:
//  1. Every gcloud step in the corpus has its command path in the allowlist, every kubectl verb
//     and resource is allowed, and every REST host is listed. "Allowed" uses the Allowlist's own
//     matching code (MatchGcloud, KubectlAllowed, RESTAllowed).
//  2. Every entry in the allowlist's gcloud section is used by at least one step — "used" means
//     MatchGcloud returns ok for that entry's path against the step's argv, where argv is built
//     by splitting the template with strings.Fields (the same splitting ParseAllowlist uses).
//     kubectl verbs, kubectl resources and REST hosts are not checked in reverse: the engine's
//     own probes use api-resources and version (spec 4.3), hosts may be listed for rules not yet
//     present, and resources such as replicasets are added for later milestones (R7).
//     The engine_gcloud entries are excluded because they are for the engine, not rules.
func TestAllowlistMatchesCorpus(t *testing.T) {
	al := loadAllowlist(t)
	pc := loadCorpus(t)

	usedGcloud := make(map[string]bool)  // joined path -> true
	usedKubectl := make(map[string]bool) // verb:resource -> true
	usedREST := make(map[string]bool)    // host -> true

	for _, r := range pc.AllRules {
		for _, s := range r.Collect {
			switch {
			case s.Gcloud != "":
				words := strings.Fields(s.Gcloud)
				if len(words) == 0 {
					continue
				}
				entry, _, ok := al.MatchGcloud(words, false)
				if !ok {
					t.Errorf("%s: %s: gcloud command %q is not in the allowlist", r.ID, s.ID, s.Gcloud)
					continue
				}
				key := strings.Join(entry.Path, " ")
				usedGcloud[key] = true

			case s.Kubectl != "":
				words := strings.Fields(s.Kubectl)
				if len(words) < 1 {
					continue
				}
				verb := words[0]
				resource := ""
				if len(words) > 1 && !allowlistResourceFreeVerb(verb) {
					resource = words[1]
				}
				if !al.KubectlAllowed(verb, resource) {
					t.Errorf("%s: %s: kubectl verb=%q resource=%q is not in the allowlist", r.ID, s.ID, verb, resource)
					continue
				}
				usedKubectl[verb+":"+resource] = true

			case s.API != nil:
				rawURL := s.API.URL
				if err := al.RESTAllowed(s.API.Method, rawURL); err != nil {
					t.Errorf("%s: %s: REST %s <url> is not in the allowlist: %v", r.ID, s.ID, s.API.Method, err)
				}
				if idx := strings.Index(rawURL, "://"); idx >= 0 {
					hostPart := rawURL[idx+3:]
					if si := strings.Index(hostPart, "/"); si >= 0 {
						hostPart = hostPart[:si]
					}
					if qi := strings.Index(hostPart, "?"); qi >= 0 {
						hostPart = hostPart[:qi]
					}
					usedREST[hostPart] = true
				}
			}
		}
	}

	// Reverse check: every gcloud allowlist entry must be used by at least one step.
	// kubectl verbs and resources are not checked in reverse: the engine's own
	// probes use api-resources and version (spec 4.3), and rules added later (R7
	// adds a get replicasets step) may introduce new uses. REST hosts are also not
	// checked in reverse: a host may be listed for rules not yet present.
	for _, ge := range al.Gcloud {
		key := strings.Join(ge.Path, " ")
		if !usedGcloud[key] {
			t.Errorf("allowlist gcloud entry %q is not used by any corpus step", key)
		}
	}
}

// TestCorpusNoHanText asserts that every embedded file that is code or data of
// the product contains no Han (CJK ideograph) characters. Comments in rule and
// profile files must be in English; the assertion guards against non-English
// text leaking into the shipped corpus.
func TestCorpusNoHanText(t *testing.T) {
	// Negative control: pin the Han-line helper against inline strings so that a
	// helper that always returns clean fails.
	controls := []struct {
		name     string
		text     string
		offend   bool
		offendLn int
	}{
		{
			name:   "clean English comment",
			text:   "# This is a comment in English\n",
			offend: false,
		},
		{
			name:     "Han character in a comment",
			text:     "# \u8fd9\u662f\u4e00\u4e2a\u6ce8\u91ca\n",
			offend:   true,
			offendLn: 1,
		},
		{
			name:     "Han character on a later line",
			text:     "# First line is clean\n# Second line contains \u4e2d\u6587\n",
			offend:   true,
			offendLn: 2,
		},
	}
	for _, c := range controls {
		got := firstHanLine([]byte(c.text))
		if c.offend && got != c.offendLn {
			t.Errorf("%s: firstHanLine = %d, want %d", c.name, got, c.offendLn)
		}
		if !c.offend && got != 0 {
			t.Errorf("%s: firstHanLine = %d, want 0 (clean)", c.name, got)
		}
	}

	check := func(name string, data []byte) {
		if ln := firstHanLine(data); ln != 0 {
			t.Errorf("%s: line %d contains a Han character", name, ln)
		}
	}

	// rules.FS: every YAML file under the embedded rule corpus.
	if err := fs.WalkDir(rules.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(rules.FS, path)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", path, err)
		}
		check("rules:"+path, data)
		return nil
	}); err != nil {
		t.Fatalf("WalkDir rules.FS: %v", err)
	}

	// profiles.Default: the default scan profile.
	check("profiles:default.yaml", profiles.Default)

	// schemas.FS: every JSON schema document.
	if err := fs.WalkDir(schemas.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(schemas.FS, path)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", path, err)
		}
		check("schemas:"+path, data)
		return nil
	}); err != nil {
		t.Fatalf("WalkDir schemas.FS: %v", err)
	}
}

// firstHanLine returns the 1-based line number of the first line in data that
// contains a Han character. It returns 0 if no line contains one.
func firstHanLine(data []byte) int {
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		for _, r := range line {
			if unicode.Is(unicode.Han, r) {
				return i + 1
			}
		}
	}
	return 0
}

// allowlistResourceFreeVerb reports whether a kubectl verb takes no resource (mirrors allowlist logic).
func allowlistResourceFreeVerb(verb string) bool {
	return verb == "api-resources" || verb == "version"
}
