package rule_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/SummerQXY/gbencher/internal/rule"
)

const fixtureDir = "../../testdata/loader/"

// hashFormat is the shape of Rule.Hash and Set.Hash.
var hashFormat = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func ptr[T any](v T) *T { return &v }

// dump renders a value as indented JSON so that a mismatch between decoded structures is
// readable, including the values behind pointers.
func dump(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%+v", v)
	}
	return string(b)
}

// mustParse parses data and fails the test unless the YAML itself could be parsed.
func mustParse(t *testing.T, name string, data []byte) (*rule.File, []rule.Violation) {
	t.Helper()
	f, vs, err := rule.ParseFile(name, data)
	if err != nil || f == nil {
		t.Fatalf("ParseFile(%s): file=%v err=%v", name, f, err)
	}
	return f, vs
}

// parseWithin calls ParseFile and fails the test when it does not return within limit, so a
// regression that expands aliases hangs one test for seconds instead of the whole run.
func parseWithin(t *testing.T, limit time.Duration, name string, data []byte) (*rule.File, []rule.Violation, error) {
	t.Helper()
	type result struct {
		f   *rule.File
		vs  []rule.Violation
		err error
	}
	done := make(chan result, 1)
	go func() {
		f, vs, err := rule.ParseFile(name, data)
		done <- result{f, vs, err}
	}()
	select {
	case r := <-done:
		return r.f, r.vs, r.err
	case <-time.After(limit):
		t.Fatalf("ParseFile(%s) did not return within %v", name, limit)
		return nil, nil, nil
	}
}

// wantHardError fails the test unless ParseFile rejected data with an error and returned no
// file and no violations, which is how an unparseable document must look to a caller.
func wantHardError(t *testing.T, name string, data []byte) error {
	t.Helper()
	f, vs, err := parseWithin(t, 10*time.Second, name, data)
	if err == nil {
		t.Fatalf("want an error, got file=%v violations=%+v", f, vs)
	}
	if f != nil || vs != nil {
		t.Errorf("an error must come with no file and no violations, got file=%v violations=%+v", f, vs)
	}
	return err
}

// ruleBody renders one valid rule as an item of a rules list. The limit param lets a test
// change the content of the rule without changing its identity.
func ruleBody(id string, limit int) string {
	ref := strings.TrimPrefix(id, "cis-example-")
	return fmt.Sprintf(`  - id: %s
    ref: %q
    title: Ensure example resources are configured
    profile: L1
    cis_assessment: automated
    mode: deterministic
    severity: medium
    scope: project
    collect:
      - id: items
        gcloud: compute instances list --project={{ .project }} --format=json
    params:
      limit: %d
    check:
      assert: size(data.items) <= params.limit
    remediation: Reduce the number of items.
    notes: Inline fixture for loader tests.
`, id, ref, limit)
}

// fileBody renders a rule file around rules produced by ruleBody.
func fileBody(version string, rules ...string) string {
	return fmt.Sprintf("dsl_version: 1\nbenchmark: {id: cis-example, version: %q}\nrules:\n%s", version, strings.Join(rules, ""))
}

// padTo appends a trailing comment so that the document is exactly size bytes long.
func padTo(doc []byte, size int) []byte {
	pad := size - len(doc)
	out := slices.Clone(doc)
	out = append(out, '#')
	return append(out, bytes.Repeat([]byte{'x'}, pad-1)...)
}

// keyLines renders n mapping entries, k0 to k<n-1> with null values, one per line and each
// indented by indent.
func keyLines(indent string, n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "%sk%d:\n", indent, i)
	}
	return b.String()
}

// flowKeys renders a flow mapping of n keys with null values, all on one line.
func flowKeys(n int) string {
	var b strings.Builder
	b.WriteByte('{')
	for i := range n {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "k%d", i)
	}
	b.WriteByte('}')
	return b.String()
}

func ruleIDs(rules []*rule.Rule) []string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids
}

func TestParseFile_RefStaysStringAndViolationHasPath(t *testing.T) {
	f, vs, err := rule.ParseFile("bad-ref.yaml", mustRead(t, "../../testdata/loader/invalid-ref-float.yaml"))
	if err != nil || f == nil {
		t.Fatalf("want best-effort file, got err=%v", err)
	}
	if len(vs) == 0 || !strings.Contains(vs[0].Path, "/rules/0/ref") {
		t.Fatalf("want ref violation with path, got %+v", vs)
	}

	// The unquoted number is the only defect of the fixture. It is reported as a number
	// where a string is required, not read as the string "6.1", and the rest of the file
	// still decodes.
	if len(vs) != 1 || vs[0].Path != "/rules/0/ref" || !strings.Contains(vs[0].Message, "want string") {
		t.Errorf("want exactly one violation at /rules/0/ref about the type, got %+v", vs)
	}
	if len(f.Rules) != 1 || f.Rules[0].ID != "cis-example-6.1" {
		t.Errorf("the rest of the file must still decode, got %s", dump(f.Rules))
	}

	src := string(mustRead(t, fixtureDir+"invalid-ref-float.yaml"))
	for _, c := range []struct {
		ref       string
		violation bool
	}{
		{"6.1", true},
		{"6.10", true},
		{"6", true},
		{`"6.1"`, false},
		{`'6.10'`, false},
	} {
		t.Run("ref "+c.ref, func(t *testing.T) {
			doc := strings.Replace(src, "ref: 6.1\n", "ref: "+c.ref+"\n", 1)
			if doc == src && c.ref != "6.1" {
				t.Fatal("fixture no longer contains the line the test rewrites")
			}
			_, vs := mustParse(t, "ref.yaml", []byte(doc))
			if got := len(vs) > 0; got != c.violation {
				t.Errorf("ref %s: violation=%v, want %v (%+v)", c.ref, got, c.violation, vs)
			}
		})
	}
}

// wantValidMinimal is the file testdata/loader/valid-minimal.yaml must decode to. Hash is
// left empty: it is checked separately, because it depends on the hashing recipe and not on
// the decoding.
func wantValidMinimal(name string) *rule.File {
	bench := rule.Benchmark{ID: "cis-example", Version: "1.0.0", Section: "1", Title: "Example Rules"}
	return &rule.File{
		Name:       name,
		DSLVersion: 1,
		Benchmark:  bench,
		Rules: []*rule.Rule{
			{
				ID:            "cis-example-1.1",
				Ref:           "1.1",
				Title:         "Ensure example firewall rules are restricted",
				Profile:       "L1",
				CISAssessment: "automated",
				Mode:          "contextual",
				Severity:      "medium",
				Scope:         "project",
				Services:      []string{"compute.googleapis.com"},
				Requires:      []string{"kubectl"},
				Collect: []rule.Step{
					{
						ID:           "firewalls",
						Gcloud:       "compute firewall-rules list --project={{ .project }} --format=json",
						Parse:        "json",
						OnError:      "empty",
						CrossProject: true,
					},
					{
						ID:      "details",
						Foreach: "data.firewalls",
						As:      "fw",
						Attach:  "details",
						Gcloud:  "compute firewall-rules describe {{ .fw.name }} --project={{ .project }} --format=json",
					},
					{
						ID:       "nodes",
						Kubectl:  "get nodes -o json",
						Requires: []string{"kubectl"},
					},
				},
				Resource: &rule.Resource{
					From:   "data.firewalls",
					Filter: `r.direction == "INGRESS"`,
					Kind:   "compute.googleapis.com/Firewall",
					Name:   "r.name",
					Key:    "r.name",
					Empty:  "pass",
				},
				Params: map[string]any{
					"freshness_days": 30,
					"namespace":      "default",
					"ratio":          0.5,
					"enabled":        true,
					"ports":          []any{22, 2222},
					"severity_rank":  map[string]any{"warning": 7, "error": 8},
				},
				ParamsConstraints: map[string]rule.ParamConstraint{
					"freshness_days": {Minimum: ptr(1.0), Maximum: ptr(365.0)},
					"namespace":      {Pattern: "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", MaxLength: ptr(63)},
					"level":          {Enum: []any{"strict", "relaxed"}},
				},
				Check: rule.Check{
					Assert:        "!r.?disabled.orValue(false)",
					ReviewWhen:    "params.enabled",
					Message:       "Firewall rule {{ .r.name }} is not restricted",
					ReviewMessage: "Confirm firewall rule {{ .r.name }}",
				},
				Evidence:    []string{"r.name", "r.network"},
				Remediation: "Delete or restrict the firewall rule.",
				References:  []string{"https://example.com/docs/firewalls"},
				Notes:       "Fixture for loader tests.",
				Tags:        []string{"network", "example"},
				Benchmark:   bench,
				SourceFile:  name,
			},
			{
				ID:            "cis-example-1.2",
				Ref:           "1.2",
				Title:         "Ensure the organization settings are configured",
				Profile:       "L2",
				CISAssessment: "manual",
				Mode:          "deterministic",
				Severity:      "low",
				Scope:         "organization",
				EvaluatePer:   "project",
				Requires:      []string{"workspace-admin"},
				Collect: []rule.Step{
					{
						ID: "settings",
						API: &rule.APIStep{
							Method:    "POST",
							URL:       "https://example.googleapis.com/v1/organizations/{{ .organization }}/settings:search",
							Body:      map[string]any{"pageSize": 50, "query": "state=ACTIVE"},
							Paginate:  true,
							ListField: "settings",
							Scopes:    []string{"https://www.googleapis.com/auth/example.readonly"},
						},
					},
				},
				Check:       rule.Check{Assert: "size(data.settings) > 0"},
				Remediation: "Configure the organization settings.",
				Notes:       "Aggregate rule without a resource section.",
				Benchmark:   bench,
				SourceFile:  name,
			},
		},
	}
}

func TestParseFile_ValidFileDecodesAllFields(t *testing.T) {
	const name = "cis-example/valid-minimal.yaml"
	f, vs := mustParse(t, name, mustRead(t, fixtureDir+"valid-minimal.yaml"))
	if len(vs) != 0 {
		t.Fatalf("the valid fixture must have no violations, got %+v", vs)
	}

	want := wantValidMinimal(name)
	if f.Name != want.Name || f.DSLVersion != want.DSLVersion || f.Benchmark != want.Benchmark {
		t.Errorf("file header = {%q %d %+v}, want {%q %d %+v}",
			f.Name, f.DSLVersion, f.Benchmark, want.Name, want.DSLVersion, want.Benchmark)
	}
	if len(f.Rules) != len(want.Rules) {
		t.Fatalf("decoded %d rules, want %d: %s", len(f.Rules), len(want.Rules), dump(f.Rules))
	}
	for i, w := range want.Rules {
		got := f.Rules[i]
		if !hashFormat.MatchString(got.Hash) {
			t.Errorf("rule %s: hash %q is not sha256:<64 lowercase hex>", w.ID, got.Hash)
		}
		w.Hash = got.Hash
		// DeepEqual over the whole rule: a field that is missing a decode tag, or that
		// lands in the wrong place, shows up here.
		if !reflect.DeepEqual(got, w) {
			t.Errorf("rule %s decoded wrongly\n got: %s\nwant: %s", w.ID, dump(got), dump(w))
		}
	}
	if f.Rules[0].Hash == f.Rules[1].Hash {
		t.Error("two different rules share a hash")
	}
}

func TestParseFile_DuplicateKeyIsError(t *testing.T) {
	cases := []struct {
		name string
		doc  []byte
		want string
	}{
		{
			"repeated key inside a rule",
			mustRead(t, fixtureDir+"invalid-duplicate-key.yaml"),
			`yaml-duplicate-key: line 11: mapping key "severity" already defined at line 10`,
		},
		{
			"repeated top-level key",
			[]byte("dsl_version: 1\nrules: []\nrules: []\n"),
			`yaml-duplicate-key: line 3: mapping key "rules" already defined at line 2`,
		},
		{
			"repeated key in a nested mapping",
			[]byte("params:\n  a: 1\n  b: 2\n  a: 3\n"),
			`yaml-duplicate-key: line 4: mapping key "a" already defined at line 2`,
		},
		{
			"repeated key in a flow mapping",
			[]byte("params: {a: 1, a: 2}\n"),
			`yaml-duplicate-key: line 1: mapping key "a" already defined at line 1`,
		},
		{
			"quoted and plain spelling of one key",
			[]byte("id: x\n\"id\": y\n"),
			`yaml-duplicate-key: line 2: mapping key "id" already defined at line 1`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := wantHardError(t, "dup.yaml", c.doc)
			if err.Error() != c.want {
				t.Errorf("error = %q, want %q", err.Error(), c.want)
			}
		})
	}

	// The same key in sibling mappings is not a repeat: every rule of the valid fixture has
	// an id, a ref and a title.
	t.Run("same key in sibling mappings is fine", func(t *testing.T) {
		if _, _, err := rule.ParseFile("ok.yaml", mustRead(t, fixtureDir+"valid-minimal.yaml")); err != nil {
			t.Fatalf("valid fixture rejected: %v", err)
		}
	})
}

func TestParseFile_TabIndentIsError(t *testing.T) {
	cases := []struct {
		name       string
		doc        []byte
		wantPrefix string
	}{
		{
			"tab where block indentation is expected",
			mustRead(t, fixtureDir+"invalid-tab-indent.yaml"),
			"yaml-syntax: line 13:",
		},
		{
			// The parser names the line its scan started on, so only the class is pinned.
			"tab inside an indented block",
			[]byte("rules:\n  - id: x\n\tref: \"1\"\n"),
			"yaml-syntax: line ",
		},
		{
			"unterminated flow sequence",
			[]byte("params: [1, 2\nrules: []\n"),
			"yaml-syntax: line ",
		},
		{
			// A second document would never be validated, so it is refused outright.
			"two documents in one file",
			[]byte("dsl_version: 1\n---\ndsl_version: 1\n"),
			"yaml-syntax: more than one document",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := wantHardError(t, "syntax.yaml", c.doc)
			if !strings.HasPrefix(err.Error(), c.wantPrefix) {
				t.Errorf("error = %q, want prefix %q", err.Error(), c.wantPrefix)
			}
		})
	}
}

func TestParseFile_AliasBombIsRejected(t *testing.T) {
	valid := mustRead(t, fixtureDir+"valid-minimal.yaml")
	const limit = 1 << 20

	cases := []struct {
		name       string
		doc        []byte
		wantPrefix string
	}{
		{"nested aliases that expand to 9^9 strings", mustRead(t, fixtureDir+"invalid-alias-bomb.yaml"), "yaml-alias: line 6:"},
		{"anchor and alias", []byte("a: &x [1]\nb: *x\n"), "yaml-alias: line 1:"},
		{"anchor on a scalar, never referenced", []byte("a: &x 1\n"), "yaml-alias: line 1:"},
		{"anchor on a mapping inside a rule list", []byte("rules:\n  - &r\n    id: x\n"), "yaml-alias: line 2:"},
		{
			// Not valid YAML if it were parsed (the nesting is far too deep), so seeing the
			// size error shows that the size is checked before any parsing.
			"2 MiB file",
			bytes.Repeat([]byte("["), 2*limit),
			"yaml-too-large",
		},
		{"one byte over the size limit", padTo(valid, limit+1), "yaml-too-large"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := wantHardError(t, "bomb.yaml", c.doc)
			if !strings.HasPrefix(err.Error(), c.wantPrefix) {
				t.Errorf("error = %q, want prefix %q", err.Error(), c.wantPrefix)
			}
		})
	}

	t.Run("exactly the size limit is accepted", func(t *testing.T) {
		doc := padTo(valid, limit)
		if len(doc) != limit {
			t.Fatalf("test document is %d bytes, want %d", len(doc), limit)
		}
		f, vs := mustParse(t, "limit.yaml", doc)
		if len(f.Rules) != 2 || len(vs) != 0 {
			t.Errorf("document at the limit: %d rules, violations %+v", len(f.Rules), vs)
		}
	})
}

// The YAML decoder compares the keys of a mapping pairwise before it decodes the mapping, so
// a file well under the size limit that is one big mapping can keep it busy for a minute or
// more. The walk over the node tree refuses such a mapping before anything is decoded.
func TestParseFile_ManyKeyMappingIsRejectedQuickly(t *testing.T) {
	const (
		maxKeys = 1000
		bound   = 5 * time.Second
		tooBig  = 116490 // keys that still fit in a file under the size limit
	)
	if rule.MaxMappingKeys != maxKeys {
		t.Fatalf("rule.MaxMappingKeys = %d, want %d", rule.MaxMappingKeys, maxKeys)
	}

	// A valid one-rule file whose params are replaced by generated keys. The block form puts
	// one key per line below "params:"; the flow form puts them all on the "params:" line.
	doc := fileBody("1.0.0", ruleBody("cis-example-1.1", 5))
	const stock = "    params:\n      limit: 5\n"
	at := strings.Index(doc, stock)
	if at < 0 {
		t.Fatal("the rule template no longer has the params block this test replaces")
	}
	head, tail := doc[:at], doc[at+len(stock):]
	paramsLine := strings.Count(head, "\n") + 1
	blockParams := func(n int) string { return head + "    params:\n" + keyLines("      ", n) + tail }
	flowParams := func(n int) string { return head + "    params: " + flowKeys(n) + "\n" + tail }

	tooMany := func(line, keys int) string {
		return fmt.Sprintf("yaml-too-large: line %d: mapping has %d keys, limit is %d", line, keys, maxKeys)
	}
	cases := []struct {
		name       string
		doc        string
		want       string // exact error text; empty when the document must be accepted
		wantParams int    // number of params the single rule must decode to; 0 to skip
	}{
		{"top level, at the limit", keyLines("", maxKeys), "", 0},
		{"top level, one over", keyLines("", maxKeys+1), tooMany(1, maxKeys+1), 0},
		{"params, at the limit", blockParams(maxKeys), "", maxKeys},
		{"params, one over", blockParams(maxKeys + 1), tooMany(paramsLine+1, maxKeys+1), 0},
		{"flow mapping, at the limit", flowParams(maxKeys), "", maxKeys},
		{"flow mapping, one over", flowParams(maxKeys + 1), tooMany(paramsLine, maxKeys+1), 0},
		{"top level, just under the size limit", keyLines("", tooBig), tooMany(1, tooBig), 0},
		{"params, just under the size limit", flowParams(tooBig), tooMany(paramsLine, tooBig), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if len(c.doc) > 1<<20 {
				t.Fatalf("test document is %d bytes; it must stay under the size limit so that the key limit is what rejects it", len(c.doc))
			}
			start := time.Now()
			f, vs, err := parseWithin(t, bound, "keys.yaml", []byte(c.doc))
			t.Logf("%d bytes handled in %v", len(c.doc), time.Since(start).Round(time.Millisecond))

			// The shape check alone applies the same limits.
			shape := rule.CheckYAMLShape([]byte(c.doc))
			switch {
			case c.want == "" && shape != nil:
				t.Errorf("CheckYAMLShape = %v, want nil", shape)
			case c.want != "" && (shape == nil || shape.Error() != c.want):
				t.Errorf("CheckYAMLShape = %v, want %q", shape, c.want)
			}

			if c.want != "" {
				if err == nil || err.Error() != c.want {
					t.Fatalf("error = %v, want %q", err, c.want)
				}
				if f != nil || vs != nil {
					t.Errorf("an error must come with no file and no violations, got file=%v violations=%+v", f, vs)
				}
				return
			}
			if err != nil || f == nil {
				t.Fatalf("want the document accepted, got file=%v err=%v", f, err)
			}
			if c.wantParams > 0 {
				if len(vs) != 0 {
					t.Errorf("a valid rule with %d params has violations: %+v", c.wantParams, vs)
				}
				if len(f.Rules) != 1 || len(f.Rules[0].Params) != c.wantParams {
					t.Errorf("want one rule with %d params, got %d rules", c.wantParams, len(f.Rules))
				}
			}
		})
	}

	// CheckYAMLShape is the part of ParseFile that rejects an unusable document, and it must
	// say the same thing for every kind of limit, not only the key count.
	t.Run("CheckYAMLShape agrees with ParseFile", func(t *testing.T) {
		docs := []struct {
			name     string
			doc      []byte
			rejected bool
		}{
			{"valid file", mustRead(t, fixtureDir+"valid-minimal.yaml"), false},
			{"empty file", nil, false},
			{"anchor and alias", []byte("a: &x [1]\nb: *x\n"), true},
			{"repeated key", mustRead(t, fixtureDir+"invalid-duplicate-key.yaml"), true},
			{"tab indentation", mustRead(t, fixtureDir+"invalid-tab-indent.yaml"), true},
			{"two documents", []byte("a: 1\n---\nb: 2\n"), true},
			{"over the size limit", bytes.Repeat([]byte("#"), 1<<20+1), true},
		}
		for _, d := range docs {
			shape := rule.CheckYAMLShape(d.doc)
			_, _, parse := rule.ParseFile("shape.yaml", d.doc)
			if (shape != nil) != d.rejected {
				t.Errorf("%s: CheckYAMLShape = %v, rejected = %v, want %v", d.name, shape, shape != nil, d.rejected)
			}
			if fmt.Sprint(shape) != fmt.Sprint(parse) {
				t.Errorf("%s: CheckYAMLShape = %v but ParseFile = %v", d.name, shape, parse)
			}
		}
	})
}

func TestParseFile_SchemaViolationsCarryFileName(t *testing.T) {
	const name = "cis-example/bad.yaml"

	cases := []struct {
		name      string
		doc       string
		wantPaths []string // violation paths in order
	}{
		{"unquoted ref", string(mustRead(t, fixtureDir+"invalid-ref-float.yaml")), []string{"/rules/0/ref"}},
		{
			// Violations come back ordered by path, the root first.
			"several defects",
			strings.Replace(strings.Replace(string(mustRead(t, fixtureDir+"invalid-ref-float.yaml")),
				"dsl_version: 1\n", "", 1), "severity: medium", "severity: urgent", 1),
			[]string{"", "/rules/0/ref", "/rules/0/severity"},
		},
		{"empty file", "", []string{""}},
		{"comment-only file", "# nothing here\n", []string{""}},
		{"list at the root", "- a\n- b\n", []string{""}},
		// The document is valid YAML but cannot be checked: JSON has no non-string keys.
		{"non-string mapping key", "1: a\n", []string{""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, vs := mustParse(t, name, []byte(c.doc))
			if f.Name != name {
				t.Errorf("File.Name = %q, want %q", f.Name, name)
			}
			var paths []string
			for _, v := range vs {
				if v.File != name {
					t.Errorf("violation %+v does not carry the file name %q", v, name)
				}
				if v.Message == "" {
					t.Errorf("violation %+v has no message", v)
				}
				paths = append(paths, v.Path)
			}
			if !slices.Equal(paths, c.wantPaths) {
				t.Errorf("violation paths = %q, want %q (%+v)", paths, c.wantPaths, vs)
			}
		})
	}
}

func TestLoadFS_DuplicateRuleIDAcrossFilesIsError(t *testing.T) {
	valid := mustRead(t, fixtureDir+"valid-minimal.yaml")

	t.Run("same ids in two files", func(t *testing.T) {
		fsys := fstest.MapFS{
			"cis-example/one.yaml": {Data: valid},
			"cis-other/two.yaml":   {Data: valid},
		}
		set, err := rule.LoadFS(fsys, "external")
		if err == nil || set != nil {
			t.Fatalf("want an error and no set, got set=%v err=%v", set, err)
		}
		var ve *rule.ViolationsError
		if !errors.As(err, &ve) {
			t.Fatalf("want *rule.ViolationsError, got %T: %v", err, err)
		}
		// Both rules of the second file repeat an id of the first.
		if len(ve.Violations) != 2 {
			t.Fatalf("want 2 violations, got %+v", ve.Violations)
		}
		for i, id := range []string{"cis-example-1.1", "cis-example-1.2"} {
			v := ve.Violations[i]
			if v.File != "cis-other/two.yaml" || v.Path != fmt.Sprintf("/rules/%d/id", i) {
				t.Errorf("violation %d is located at %s %s, want the later file and the id of rule %d", i, v.File, v.Path, i)
			}
			for _, want := range []string{id, "cis-example/one.yaml", "cis-other/two.yaml"} {
				if !strings.Contains(v.Message, want) {
					t.Errorf("violation %d message %q does not name %q", i, v.Message, want)
				}
			}
			if !strings.Contains(err.Error(), id) {
				t.Errorf("error text does not mention %s: %v", id, err)
			}
		}
	})

	t.Run("same id twice in one file", func(t *testing.T) {
		fsys := fstest.MapFS{
			"cis-example/one.yaml": {Data: []byte(fileBody("1.0.0", ruleBody("cis-example-1.1", 1), ruleBody("cis-example-1.1", 2)))},
		}
		set, err := rule.LoadFS(fsys, "external")
		if err == nil || set != nil {
			t.Fatalf("want an error and no set, got set=%v err=%v", set, err)
		}
		var ve *rule.ViolationsError
		if !errors.As(err, &ve) || len(ve.Violations) != 1 || ve.Violations[0].Path != "/rules/1/id" {
			t.Fatalf("want one violation at /rules/1/id, got %v", err)
		}
		if !strings.Contains(ve.Violations[0].Message, "cis-example-1.1") || !strings.Contains(ve.Violations[0].Message, "cis-example/one.yaml") {
			t.Errorf("message must name the id and the file: %q", ve.Violations[0].Message)
		}
	})

	t.Run("distinct ids across files load", func(t *testing.T) {
		fsys := fstest.MapFS{
			"cis-example/one.yaml": {Data: []byte(fileBody("1.0.0", ruleBody("cis-example-1.1", 1)))},
			"cis-example/two.yaml": {Data: []byte(fileBody("1.0.0", ruleBody("cis-example-1.2", 1)))},
		}
		set, err := rule.LoadFS(fsys, "external")
		if err != nil || set == nil || len(set.Rules) != 2 {
			t.Fatalf("want two rules, got set=%v err=%v", set, err)
		}
	})
}

// brokenFS is a file system that cannot be read at all.
type brokenFS struct{}

func (brokenFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
}

func TestLoadFS_AnyViolationIsError(t *testing.T) {
	valid := mustRead(t, fixtureDir+"valid-minimal.yaml")
	badRef := mustRead(t, fixtureDir+"invalid-ref-float.yaml")
	dupKey := mustRead(t, fixtureDir+"invalid-duplicate-key.yaml")

	cases := []struct {
		name string
		fsys fstest.MapFS
		want []string // substrings of the error text
	}{
		{
			"schema violation next to a valid file",
			fstest.MapFS{"cis-example/ok.yaml": {Data: valid}, "cis-example/bad.yaml": {Data: badRef}},
			[]string{"cis-example/bad.yaml", "/rules/0/ref", "want string"},
		},
		{
			"yaml that cannot be parsed",
			fstest.MapFS{"cis-example/dup.yaml": {Data: dupKey}},
			[]string{"cis-example/dup.yaml", "unreadable yaml", "yaml-duplicate-key", "line 11"},
		},
		{
			"file over the size limit",
			fstest.MapFS{"cis-example/huge.yaml": {Data: bytes.Repeat([]byte("["), 2<<20)}},
			[]string{"cis-example/huge.yaml", "unreadable yaml", "yaml-too-large"},
		},
		{
			"empty file",
			fstest.MapFS{"cis-example/empty.yaml": {Data: nil}},
			[]string{"cis-example/empty.yaml", "got null, want object"},
		},
		{
			"allowlist.yaml below the root is a rule file",
			fstest.MapFS{"cis-example/ok.yaml": {Data: valid}, "cis-example/allowlist.yaml": {Data: []byte("gcloud: []\n")}},
			[]string{"cis-example/allowlist.yaml", "dsl_version"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			set, err := rule.LoadFS(c.fsys, "external")
			if err == nil || set != nil {
				t.Fatalf("want an error and no set, got set=%v err=%v", set, err)
			}
			var ve *rule.ViolationsError
			if !errors.As(err, &ve) || len(ve.Violations) == 0 {
				t.Fatalf("want *rule.ViolationsError with violations, got %T: %v", err, err)
			}
			for _, want := range c.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error text lacks %q:\n%v", want, err)
				}
			}
		})
	}

	t.Run("every file is checked and every violation is kept", func(t *testing.T) {
		fsys := fstest.MapFS{
			"cis-example/ok.yaml":  {Data: valid},
			"cis-example/ref.yaml": {Data: badRef},
			"cis-example/dup.yaml": {Data: dupKey},
		}
		files, vs, err := rule.LoadFiles(fsys)
		if err != nil {
			t.Fatalf("LoadFiles: %v", err)
		}
		// A file that cannot be parsed becomes a violation and the walk goes on; a file that
		// parses is returned even when it has violations, so that later checks can use it.
		var names []string
		for _, f := range files {
			names = append(names, f.Name)
		}
		if want := []string{"cis-example/ok.yaml", "cis-example/ref.yaml"}; !slices.Equal(names, want) {
			t.Errorf("files = %q, want %q", names, want)
		}
		if len(vs) != 2 {
			t.Fatalf("want 2 violations, got %+v", vs)
		}
		if vs[0].File != "cis-example/dup.yaml" || vs[0].Path != "" || !strings.HasPrefix(vs[0].Message, "unreadable yaml: yaml-duplicate-key: line 11:") {
			t.Errorf("unreadable file violation = %+v", vs[0])
		}
		if vs[1].File != "cis-example/ref.yaml" || vs[1].Path != "/rules/0/ref" {
			t.Errorf("schema violation = %+v", vs[1])
		}

		_, err = rule.LoadFS(fsys, "external")
		var ve *rule.ViolationsError
		if !errors.As(err, &ve) || len(ve.Violations) != 2 {
			t.Errorf("LoadFS must report both problems at once, got %v", err)
		}
	})

	t.Run("the message lists 20 violations and counts the rest", func(t *testing.T) {
		fsys := fstest.MapFS{}
		for i := range 25 {
			id := fmt.Sprintf("cis-example-6.%d", i+1)
			doc := strings.Replace(string(badRef), "cis-example-6.1", id, 1)
			fsys[fmt.Sprintf("bad/%02d.yaml", i)] = &fstest.MapFile{Data: []byte(doc)}
		}
		_, err := rule.LoadFS(fsys, "external")
		var ve *rule.ViolationsError
		if !errors.As(err, &ve) {
			t.Fatalf("want *rule.ViolationsError, got %T: %v", err, err)
		}
		if len(ve.Violations) != 25 {
			t.Errorf("the error must carry all 25 violations, got %d", len(ve.Violations))
		}
		msg := err.Error()
		if got := strings.Count(msg, "/rules/0/ref"); got != 20 {
			t.Errorf("message lists %d violations, want 20:\n%s", got, msg)
		}
		for _, want := range []string{"25 violations", "5 more omitted", "bad/00.yaml", "bad/19.yaml"} {
			if !strings.Contains(msg, want) {
				t.Errorf("message lacks %q:\n%s", want, msg)
			}
		}
		if strings.Contains(msg, "bad/20.yaml") {
			t.Errorf("message lists a violation beyond the first 20:\n%s", msg)
		}
	})

	t.Run("data files at the root are not rule files", func(t *testing.T) {
		// Neither would pass the rule schema, so loading them as rules would fail the load.
		fsys := fstest.MapFS{
			"cis-example/ok.yaml": {Data: valid},
			"allowlist.yaml":      {Data: []byte("gcloud: []\n")},
			"verification.yaml":   {Data: []byte("fixtures: []\n")},
			"notes.txt":           {Data: []byte("not yaml")},
			"cis-example/x.yml":   {Data: []byte("not: a rule file")},
		}
		set, err := rule.LoadFS(fsys, "external")
		if err != nil {
			t.Fatalf("LoadFS: %v", err)
		}
		if got := ruleIDs(set.Rules); !slices.Equal(got, []string{"cis-example-1.1", "cis-example-1.2"}) {
			t.Errorf("rules = %q", got)
		}
	})

	t.Run("a file system that cannot be read is an error, not a violation", func(t *testing.T) {
		set, err := rule.LoadFS(brokenFS{}, "external")
		var ve *rule.ViolationsError
		if err == nil || set != nil || errors.As(err, &ve) || !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("want the read error itself, got set=%v err=%v", set, err)
		}
		if _, _, err := rule.LoadFiles(brokenFS{}); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("LoadFiles: want the read error, got %v", err)
		}
	})
}

// sha256Hex returns "sha256:" followed by the hex digest of s, computed here and not by the
// package, so that the tests pin the hashing recipe instead of repeating it.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestLoadFS_HashIsOrderIndependent(t *testing.T) {
	body := func(id string) string { return ruleBody(id, 5) }

	// The same three rules spread over files in two ways, with different file names and
	// different rule orders inside the files.
	arrangeA := fstest.MapFS{
		"cis-example/a.yaml": {Data: []byte(fileBody("1.0.0", body("cis-example-1.2"), body("cis-example-1.10")))},
		"cis-example/b.yaml": {Data: []byte(fileBody("1.0.0", body("cis-example-1.1")))},
	}
	arrangeB := fstest.MapFS{
		"z/only.yaml": {Data: []byte(fileBody("1.0.0", body("cis-example-1.1"), body("cis-example-1.10"), body("cis-example-1.2")))},
	}
	setA, err := rule.LoadFS(arrangeA, "embedded")
	if err != nil {
		t.Fatalf("LoadFS A: %v", err)
	}
	setB, err := rule.LoadFS(arrangeB, "embedded")
	if err != nil {
		t.Fatalf("LoadFS B: %v", err)
	}

	if !hashFormat.MatchString(setA.Hash) {
		t.Errorf("Set.Hash = %q, want sha256:<64 lowercase hex>", setA.Hash)
	}
	if setA.Hash != setB.Hash {
		t.Errorf("the set hash depends on file layout or order: %s vs %s", setA.Hash, setB.Hash)
	}

	// Plain string order of the ids, so cis-example-1.10 comes before cis-example-1.2.
	wantOrder := []string{"cis-example-1.1", "cis-example-1.10", "cis-example-1.2"}
	for label, set := range map[string]*rule.Set{"A": setA, "B": setB} {
		if got := ruleIDs(set.Rules); !slices.Equal(got, wantOrder) {
			t.Errorf("set %s rules = %q, want %q", label, got, wantOrder)
		}
	}
	for i := range setA.Rules {
		if setA.Rules[i].Hash != setB.Rules[i].Hash {
			t.Errorf("rule %s hashes differently in the two layouts", setA.Rules[i].ID)
		}
	}

	// The set hash is the digest of the sorted "<id>\t<rule hash>\n" lines.
	var lines strings.Builder
	for _, r := range setA.Rules {
		lines.WriteString(r.ID + "\t" + r.Hash + "\n")
	}
	if want := sha256Hex(lines.String()); setA.Hash != want {
		t.Errorf("Set.Hash = %s, want %s", setA.Hash, want)
	}

	t.Run("a change to one rule changes the set hash", func(t *testing.T) {
		changed := fstest.MapFS{
			"z/only.yaml": {Data: []byte(fileBody("1.0.0", body("cis-example-1.1"), ruleBody("cis-example-1.10", 6), body("cis-example-1.2")))},
		}
		set, err := rule.LoadFS(changed, "embedded")
		if err != nil {
			t.Fatalf("LoadFS: %v", err)
		}
		if set.Hash == setA.Hash {
			t.Error("set hash did not change with the content of a rule")
		}
	})

	t.Run("source is passed through", func(t *testing.T) {
		if setA.Source != "embedded" {
			t.Errorf("Source = %q, want embedded", setA.Source)
		}
	})

	t.Run("files come back in plain path order", func(t *testing.T) {
		// A directory walk visits a/z.yaml before a.yaml; plain string order of the paths
		// puts a.yaml first because '.' sorts before '/'.
		fsys := fstest.MapFS{
			"b/x.yaml": {Data: []byte(fileBody("1.0.0", body("cis-example-3.1")))},
			"a/z.yaml": {Data: []byte(fileBody("1.0.0", body("cis-example-2.1")))},
			"a.yaml":   {Data: []byte(fileBody("1.0.0", body("cis-example-1.1")))},
		}
		files, vs, err := rule.LoadFiles(fsys)
		if err != nil || len(vs) != 0 {
			t.Fatalf("LoadFiles: violations=%+v err=%v", vs, err)
		}
		var names []string
		for _, f := range files {
			names = append(names, f.Name)
		}
		if want := []string{"a.yaml", "a/z.yaml", "b/x.yaml"}; !slices.Equal(names, want) {
			t.Errorf("files = %q, want %q", names, want)
		}
	})
}

func TestRuleHash_ChangesWhenParamChanges(t *testing.T) {
	const reformatted = `# The same rule as ruleBody("cis-example-1.1", 5): keys reordered, other quoting, flow style,
# a comment and a different indentation.
benchmark: {version: "1.0.0", id: cis-example}
rules:
- notes: Inline fixture for loader tests.
  remediation: "Reduce the number of items."
  check: {assert: "size(data.items) <= params.limit"}   # trailing comment
  params: {limit: 5}
  collect:
  - gcloud: 'compute instances list --project={{ .project }} --format=json'
    id: items
  scope: project
  severity: medium
  mode: deterministic
  cis_assessment: automated
  profile: L1
  title: "Ensure example resources are configured"
  ref: '1.1'
  id: cis-example-1.1
dsl_version: 1
`

	// hashOf parses a document that holds exactly one rule and returns that rule's hash.
	hashOf := func(t *testing.T, name, doc string) string {
		t.Helper()
		f, _ := mustParse(t, name, []byte(doc))
		if len(f.Rules) != 1 {
			t.Fatalf("want one rule, got %d", len(f.Rules))
		}
		if !hashFormat.MatchString(f.Rules[0].Hash) {
			t.Fatalf("hash %q is not sha256:<64 lowercase hex>", f.Rules[0].Hash)
		}
		return f.Rules[0].Hash
	}
	base := hashOf(t, "base.yaml", fileBody("1.0.0", ruleBody("cis-example-1.1", 5)))

	cases := []struct {
		name string
		hash string
		same bool
	}{
		{"param default changed", hashOf(t, "p.yaml", fileBody("1.0.0", ruleBody("cis-example-1.1", 6))), false},
		{"rule id changed", hashOf(t, "i.yaml", fileBody("1.0.0", ruleBody("cis-example-1.2", 5))), false},
		{"benchmark version changed", hashOf(t, "v.yaml", fileBody("2.0.0", ruleBody("cis-example-1.1", 5))), false},
		{
			"benchmark id changed",
			hashOf(t, "b.yaml", strings.Replace(fileBody("1.0.0", ruleBody("cis-example-1.1", 5)), "cis-example,", "cis-other,", 1)),
			false,
		},
		{"file name differs", hashOf(t, "some/other/place.yaml", fileBody("1.0.0", ruleBody("cis-example-1.1", 5))), true},
		{"key order, quoting, comments and layout differ", hashOf(t, "r.yaml", reformatted), true},
		{
			"benchmark title and section are not part of the hash",
			hashOf(t, "t.yaml", strings.Replace(fileBody("1.0.0", ruleBody("cis-example-1.1", 5)), "{id: cis-example,", "{section: \"9\", title: Other, id: cis-example,", 1)),
			true,
		},
		{
			"another rule in the file does not matter",
			func() string {
				f, _ := mustParse(t, "two.yaml", []byte(fileBody("1.0.0", ruleBody("cis-example-1.9", 1), ruleBody("cis-example-1.1", 5))))
				return f.Rules[1].Hash
			}(),
			true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.hash == base; got != c.same {
				t.Errorf("hash equal to base = %v, want %v (base %s, got %s)", got, c.same, base, c.hash)
			}
		})
	}

	// The recipe is the digest of the canonical JSON (sorted keys, no whitespace) of the
	// benchmark id and version plus the rule mapping. The expected value is computed here
	// from that JSON text and does not use the package.
	t.Run("recipe", func(t *testing.T) {
		const doc = "dsl_version: 1\nbenchmark: {id: b, version: \"1\"}\nrules:\n  - {id: x, params: {z: 1, a: [true, null, 1.5, \"<&>\"]}}\n"
		f, _ := mustParse(t, "recipe.yaml", []byte(doc))
		const canonical = `{"benchmark":{"id":"b","version":"1"},"rule":{"id":"x","params":{"a":[true,null,1.5,"<&>"],"z":1}}}`
		if got, want := f.Rules[0].Hash, sha256Hex(canonical); got != want {
			t.Errorf("hash = %s, want %s", got, want)
		}
	})
}

func TestLoadDir_SourceIsExternal(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "cis-example")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "valid.yaml"), mustRead(t, fixtureDir+"valid-minimal.yaml"), 0o600); err != nil {
		t.Fatal(err)
	}

	set, err := rule.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if set.Source != "external" {
		t.Errorf("Source = %q, want external", set.Source)
	}
	if !hashFormat.MatchString(set.Hash) {
		t.Errorf("Set.Hash = %q", set.Hash)
	}

	r, ok := set.Get("cis-example-1.2")
	if !ok || r == nil || r.ID != "cis-example-1.2" {
		t.Fatalf("Get(cis-example-1.2) = %v, %v", r, ok)
	}
	// SourceFile is relative to the loaded root and uses forward slashes.
	if r.SourceFile != "cis-example/valid.yaml" {
		t.Errorf("SourceFile = %q, want cis-example/valid.yaml", r.SourceFile)
	}
	if r.Benchmark.ID != "cis-example" || r.Benchmark.Version != "1.0.0" {
		t.Errorf("Benchmark = %+v", r.Benchmark)
	}
	if r, ok := set.Get("cis-example-9.9"); ok || r != nil {
		t.Errorf("Get of an unknown id = %v, %v; want nil, false", r, ok)
	}

	t.Run("missing directory is an error that says so", func(t *testing.T) {
		set, err := rule.LoadDir(filepath.Join(dir, "missing"))
		if set != nil || !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("want fs.ErrNotExist, got set=%v err=%v", set, err)
		}
	})
}

// The embedded corpus loads without error and yields a non-nil set. This
// pins that every known violation has been fixed and that LoadEmbedded can
// be used as the single source of rules.
func TestLoadEmbedded_CorpusLoads(t *testing.T) {
	set, err := rule.LoadEmbedded()
	if err != nil {
		t.Fatalf("want no error after the corpus revision, got err=%v", err)
	}
	if set == nil {
		t.Fatal("want a set after the corpus revision, got nil")
	}
}
