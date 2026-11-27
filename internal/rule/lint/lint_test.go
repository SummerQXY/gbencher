package lint_test

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/celenv"
	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/internal/rule/lint"
)

// fixtureRoot is the directory of the lint fixtures, relative to this package.
const fixtureRoot = "../../../testdata/lint/"

// maxMessageLen is a generous bound on the length of a finding message: a message may repeat a
// piece of the rule it is about, and that piece is cut well before this.
const maxMessageLen = 400

// parseFixtures parses each fixture with rule.ParseFile. The fixtures break the schema or the lint
// rules on purpose, so they are not loaded with rule.LoadFS or rule.LoadEmbedded, which reject them.
// A file that cannot be parsed at all fails the test.
func parseFixtures(t *testing.T, paths ...string) ([]*rule.File, []rule.Violation) {
	t.Helper()
	var (
		files      []*rule.File
		violations []rule.Violation
	)
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		name := filepath.ToSlash(strings.TrimPrefix(p, fixtureRoot))
		f, vs, err := rule.ParseFile(name, data)
		if err != nil || f == nil {
			t.Fatalf("ParseFile(%s): file=%v err=%v", name, f, err)
		}
		files = append(files, f)
		violations = append(violations, vs...)
	}
	return files, violations
}

// runFixture lints one fixture file with the allowlist that is built into the program, as the
// command line does, so that the clean fixture also shows the policy checks have no false positive.
// Only schema.yaml may violate the schema, so that a fixture cannot end up testing two things at
// once.
func runFixture(t *testing.T, path string) []lint.Finding {
	t.Helper()
	files, violations := parseFixtures(t, path)
	if len(violations) > 0 && filepath.Base(path) != "schema.yaml" {
		t.Fatalf("%s violates the schema and only schema.yaml may: %+v", path, violations)
	}
	return lint.Run(files, violations, policyOptions(t))
}

// lintRules lints rules held in one file that was never written to disk.
func lintRules(rules ...*rule.Rule) []lint.Finding {
	return lint.Run([]*rule.File{{Name: "inline.yaml", Rules: rules}}, nil, lint.Options{})
}

// summarize renders each finding as "<code> <where>", sorted, which is all most cases care about.
func summarize(fs []lint.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Code + " " + f.Where
	}
	slices.Sort(out)
	return out
}

// wantFindings fails the test unless fs holds exactly the findings in want, each written
// "<code> <where>". It also holds every message to the rules that apply to all of them: one
// line, and bounded.
func wantFindings(t *testing.T, fs []lint.Finding, want ...string) {
	t.Helper()
	slices.Sort(want)
	if got := summarize(fs); !slices.Equal(got, want) {
		t.Errorf("findings\n got  %q\n want %q\n%s", got, want, lint.FormatText(fs))
	}
	for _, f := range fs {
		if strings.ContainsAny(f.Where+f.Message, "\r\n") {
			t.Errorf("finding is not on one line: %+v", f)
		}
		if len(f.Message) > maxMessageLen {
			t.Errorf("message of %d bytes is not bounded: %q", len(f.Message), f.Message)
		}
	}
}

// baseRule returns a rule that lints clean. Each case changes one thing in a fresh copy.
func baseRule() *rule.Rule {
	return &rule.Rule{
		ID:    "cis-inline-1",
		Scope: "project",
		Collect: []rule.Step{
			{ID: "instances", Gcloud: "compute instances list --project={{ .project }} --format=json"},
			{ID: "disks", Gcloud: "compute disks list --project={{ .project }} --format=json"},
		},
		Resource: &rule.Resource{From: "data.instances", Kind: "compute.googleapis.com/Instance", Name: "r.name"},
		Params:   map[string]any{"limit": 3, "key": "instances", "names": []any{"a"}},
		Check: rule.Check{
			Assert:  "size(r.disks) <= params.limit",
			Message: "Instance {{ .r.name }} has more than {{ .params.limit }} disks",
		},
	}
}

// withAssert returns an edit that sets the assert expression.
func withAssert(expr string) func(*rule.Rule) {
	return func(r *rule.Rule) { r.Check.Assert = expr }
}

// withMessage returns an edit that sets the message template.
func withMessage(text string) func(*rule.Rule) {
	return func(r *rule.Rule) { r.Check.Message = text }
}

// asAggregate turns the rule into an aggregate rule: no resource block, so no r, and an assert
// and message that do not use it.
func asAggregate(r *rule.Rule) {
	r.Resource = nil
	r.Check.Assert = "size(data.disks) <= params.limit"
	r.Check.Message = "The project has too many disks"
}

// exprSite is a place a rule holds a CEL expression and a way to put one there.
type exprSite struct {
	where string
	set   func(r *rule.Rule, expr string)
}

// resourceRuleExprSites are the expression sites of baseRule.
var resourceRuleExprSites = []exprSite{
	{"collect.disks.foreach", func(r *rule.Rule, e string) { r.Collect[1].Foreach = e }},
	{"resource.from", func(r *rule.Rule, e string) { r.Resource.From = e }},
	{"resource.filter", func(r *rule.Rule, e string) { r.Resource.Filter = e }},
	{"resource.name", func(r *rule.Rule, e string) { r.Resource.Name = e }},
	{"resource.key", func(r *rule.Rule, e string) { r.Resource.Key = e }},
	{"check.assert", func(r *rule.Rule, e string) { r.Check.Assert = e }},
	{"check.review_when", func(r *rule.Rule, e string) { r.Check.ReviewWhen = e }},
	{"evidence[1]", func(r *rule.Rule, e string) { r.Evidence = []string{"params.limit", e} }},
}

// templateSite is a place a rule holds a template and a way to put one there.
type templateSite struct {
	where string
	set   func(r *rule.Rule, text string)
}

var templateSites = []templateSite{
	{"collect.disks.gcloud", func(r *rule.Rule, s string) { r.Collect[1].Gcloud = s }},
	{"collect.extra.kubectl", func(r *rule.Rule, s string) {
		r.Collect = append(r.Collect, rule.Step{ID: "extra", Kubectl: s})
	}},
	{"collect.extra.api.url", func(r *rule.Rule, s string) {
		r.Collect = append(r.Collect, rule.Step{ID: "extra", API: &rule.APIStep{Method: "GET", URL: s}})
	}},
	{"check.message", func(r *rule.Rule, s string) { r.Check.Message = s }},
	{"check.review_message", func(r *rule.Rule, s string) { r.Check.ReviewMessage = s }},
}

func TestRun_EachFixtureProducesExactlyItsCode(t *testing.T) {
	// Each fixture holds one rule, cis-lint-<code>-1. The table says where its single finding is
	// reported and, for the two codes whose messages point into the text, how the message starts.
	fixtures := []struct{ code, where, messagePrefix string }{
		{"cel-compile", "check.assert", "line 1, column "},
		{"data-ref-unknown", "check.assert", ""},
		{"data-ref-forward", "collect.keys.foreach", ""},
		{"params-ref-undefined", "check.assert", ""},
		{"ctx-ref-unknown", "check.assert", ""},
		{"template-parse", "check.message", "line 1: "},
		{"template-var-undeclared", "collect.instances.gcloud", ""},
		{"r-unavailable", "check.assert", ""},
		{"step-id-duplicate", "collect.instances", ""},
		{"schema", "/rules/0/ref", ""},
	}
	for _, fx := range fixtures {
		t.Run(fx.code, func(t *testing.T) {
			fs := runFixture(t, fixtureRoot+fx.code+".yaml")
			if len(fs) != 1 || fs[0].Code != fx.code {
				t.Fatalf("want exactly one %s finding, got %+v", fx.code, fs)
			}
			want := lint.Finding{File: fx.code + ".yaml", RuleID: "cis-lint-" + fx.code + "-1", Where: fx.where, Code: fx.code, Message: fs[0].Message}
			if fs[0] != want || fs[0].Message == "" {
				t.Errorf("got %+v, want %+v with a message", fs[0], want)
			}
			if !strings.HasPrefix(fs[0].Message, fx.messagePrefix) {
				t.Errorf("message %q does not start with %q", fs[0].Message, fx.messagePrefix)
			}
		})
	}

	t.Run("references by site", func(t *testing.T) {
		// A reference is found, and reported where it is, in every expression a rule can hold.
		for _, s := range resourceRuleExprSites {
			t.Run(s.where, func(t *testing.T) {
				r := baseRule()
				s.set(r, "data.nope == 1 && params.nope == 1 && ctx.nope == 1")
				wantFindings(t, lintRules(r),
					"data-ref-unknown "+s.where, "params-ref-undefined "+s.where, "ctx-ref-unknown "+s.where)
			})
		}
	})

	t.Run("r by site", func(t *testing.T) {
		// r is the resource under evaluation, so it exists everywhere except in the expressions that
		// produce the resources: foreach and resource.from.
		for _, s := range resourceRuleExprSites {
			t.Run(s.where, func(t *testing.T) {
				r := baseRule()
				s.set(r, `r.name == "x"`)
				var want []string
				if s.where == "collect.disks.foreach" || s.where == "resource.from" {
					want = []string{"r-unavailable " + s.where}
				}
				wantFindings(t, lintRules(r), want...)
			})
		}
		t.Run("aggregate rule", func(t *testing.T) {
			for _, s := range resourceRuleExprSites {
				if strings.HasPrefix(s.where, "resource.") {
					continue // an aggregate rule has no resource block
				}
				t.Run(s.where, func(t *testing.T) {
					r := baseRule()
					asAggregate(r)
					s.set(r, `r.name == "x"`)
					wantFindings(t, lintRules(r), "r-unavailable "+s.where)
				})
			}
		})
	})

	t.Run("r agrees with the CEL environment that has no r", func(t *testing.T) {
		// The lint finds a use of r in the syntax tree. The environment aggregate rules are
		// evaluated in has no r, so its type checker rejects an expression exactly when r is
		// used and not shadowed. The two must agree in every scoping case.
		noR, err := celenv.New(false)
		if err != nil {
			t.Fatal(err)
		}
		for _, expr := range []string{
			`r.name == "x"`,
			`has(r.x)`,
			`r.?x.orValue(1) > 0`,
			`size([r]) == 1`,
			`{"a": r}.size() == 1`,
			`.r.name == "x"`,
			`data.instances.exists(r, r.name == "x")`,
			`data.instances.exists(r, true) && r.ok`,
			`data.instances.exists(x, data.instances.exists(r, r.a) && r.b)`,
			`data.instances.exists(r, data.instances.all(x, r.name == x.name))`,
			`data.instances.filter(r, r.ok).map(r, r.name).size() > 0`,
			`data.instances.exists(r, .r.name == "x")`,
			`data.instances.exists(d, d.r == 1)`,
			`cel.bind(r, 1, r + 1) > 0`,
			`cel.bind(r, r, true)`,
			`cel.bind(x, 1, x + r) > 0`,
			`params.?limit.optMap(r, r + 1).hasValue()`,
			`params.?limit.optMap(x, x + 1).orValue(r) > 0`,
		} {
			t.Run(expr, func(t *testing.T) {
				_, iss := noR.Compile(expr)
				rejected := iss != nil && iss.Err() != nil

				r := baseRule()
				asAggregate(r)
				r.Check.Assert = expr
				var unavailable bool
				for _, f := range lintRules(r) {
					if f.Code == "cel-compile" {
						t.Fatalf("the expression must compile except for r: %+v", f)
					}
					unavailable = unavailable || f.Code == "r-unavailable"
				}
				if unavailable != rejected {
					t.Errorf("lint reports r-unavailable = %v, the environment without r rejects the expression = %v (%v)", unavailable, rejected, iss)
				}
			})
		}
	})

	cases := []struct {
		name string
		edit func(r *rule.Rule)
		want []string // "<code> <where>"
	}{
		// data.<id>
		{"known step", withAssert("size(data.instances) == 0 && size(data.disks) == 0"), nil},
		{"unknown step", withAssert("size(data.volumes) == 0"), []string{"data-ref-unknown check.assert"}},
		{"optional select", withAssert("data.?volumes.orValue([]) == []"), []string{"data-ref-unknown check.assert"}},
		{"index with a string literal", withAssert(`size(data["volumes"]) == 0`), []string{"data-ref-unknown check.assert"}},
		{"optional index", withAssert(`data[?"volumes"].hasValue()`), []string{"data-ref-unknown check.assert"}},
		{"presence test", withAssert("has(data.volumes)"), []string{"data-ref-unknown check.assert"}},
		{"absolute name", withAssert("size(.data.volumes) == 0"), []string{"data-ref-unknown check.assert"}},
		{"computed index is not a reference", withAssert("data[params.key] == 1"), nil},
		{"the same reference twice is one finding", withAssert("data.volumes == data.volumes"), []string{"data-ref-unknown check.assert"}},
		{"two references are two findings", withAssert("data.volumes == data.snapshots"),
			[]string{"data-ref-unknown check.assert", "data-ref-unknown check.assert"}},
		{"a field of r called data is not data", withAssert("r.data.volumes == 1 && r.params.nope == 1 && r.ctx.nope == 1"), nil},
		{"a field index of r is not data", withAssert(`r.labels["data"] == "nope"`), nil},

		// comprehension and bind variables shadow the names they are called
		{"iteration variable shadows data", withAssert("data.instances.exists(data, data.nope == 1)"), nil},
		{"shadowing ends with the macro", withAssert("data.instances.exists(data, true) && data.nope == 1"),
			[]string{"data-ref-unknown check.assert"}},
		{"the range of a macro is outside its scope", withAssert("data.nope.exists(data, data.x == 1)"),
			[]string{"data-ref-unknown check.assert"}},
		{"bind variable shadows data in its body", withAssert(`cel.bind(data, {"nope": 1}, data.nope == 1)`), nil},
		{"bind initializer is outside the scope", withAssert("cel.bind(data, data.nope, true)"),
			[]string{"data-ref-unknown check.assert"}},
		{"an absolute name is not shadowed", withAssert("data.instances.exists(data, .data.nope == 1)"),
			[]string{"data-ref-unknown check.assert"}},
		{"a nested macro keeps the outer shadow", withAssert("data.instances.exists(data, [1].all(x, data.nope == 1))"), nil},
		{"filter and map shadow too", withAssert("size(data.instances.filter(data, data.nope).map(params, params.nope)) == 0"), nil},
		{"optMap variable shadows params", withAssert("params.?limit.optMap(params, params.nope).hasValue()"), nil},

		// every kind of node a reference can hide in
		{"list element", withAssert("size([data.volumes]) == 1"), []string{"data-ref-unknown check.assert"}},
		{"optional list element", withAssert("size([?data.?volumes]) == 0"), []string{"data-ref-unknown check.assert"}},
		{"map value", withAssert(`{"k": data.volumes}.size() == 1`), []string{"data-ref-unknown check.assert"}},
		{"map key", withAssert("{data.volumes: 1}.size() == 1"), []string{"data-ref-unknown check.assert"}},
		{"optional map entry", withAssert(`{?"k": data.?volumes}.size() == 0`), []string{"data-ref-unknown check.assert"}},
		{"struct field", withAssert("google.protobuf.Value{string_value: data.volumes} != null"), []string{"data-ref-unknown check.assert"}},
		{"target of a member call", withAssert("params.missing.size() > 0"), []string{"params-ref-undefined check.assert"}},
		{"argument of a call", withAssert("size(data.volumes) > 0"), []string{"data-ref-unknown check.assert"}},
		{"branch of a conditional", withAssert("r.ok ? data.volumes : 1"), []string{"data-ref-unknown check.assert"}},
		{"step of a macro", withAssert("data.instances.exists(i, i.name == data.volumes)"), []string{"data-ref-unknown check.assert"}},

		// params.<name>
		{"known param", withAssert("size(r.disks) <= params.limit"), nil},
		{"unknown param", withAssert("size(r.disks) <= params.missing"), []string{"params-ref-undefined check.assert"}},
		{"unknown param, optional select", withAssert("params.?missing.orValue(1) > 0"), []string{"params-ref-undefined check.assert"}},
		{"unknown param, index", withAssert(`params["missing"] > 0`), []string{"params-ref-undefined check.assert"}},
		{"unknown param, presence test", withAssert("has(params.missing)"), []string{"params-ref-undefined check.assert"}},
		{"iteration variable shadows params", withAssert("data.instances.all(params, params.missing > 0)"), nil},
		{"rule without params", func(r *rule.Rule) { r.Params = nil },
			[]string{"params-ref-undefined check.assert", "params-ref-undefined check.message"}},

		// ctx.<name>
		{"every context field", withAssert(`ctx.account != "" && ctx.cluster == null && ctx.folder != "" && ctx.now > ctx.now && ` +
			`ctx.organization != "" && ctx.organization_domain != "" && ctx.project != "" && ctx.project_number != ""`), nil},
		{"unknown context field", withAssert(`ctx.region == "x"`), []string{"ctx-ref-unknown check.assert"}},
		{"unknown context field, optional select", withAssert(`ctx.?region.orValue("") == "x"`), []string{"ctx-ref-unknown check.assert"}},
		{"iteration variable shadows ctx", withAssert("data.instances.map(ctx, ctx.region).size() == 1"), nil},

		// steps and the order they run in
		{"foreach reads an earlier step", func(r *rule.Rule) { r.Collect[1].Foreach = "data.instances" }, nil},
		{"foreach reads a later step", func(r *rule.Rule) { r.Collect[0].Foreach = "data.disks" },
			[]string{"data-ref-forward collect.instances.foreach"}},
		{"foreach reads its own step", func(r *rule.Rule) { r.Collect[1].Foreach = "data.disks" },
			[]string{"data-ref-forward collect.disks.foreach"}},
		{"foreach reads a step that does not exist", func(r *rule.Rule) { r.Collect[1].Foreach = "data.volumes" },
			[]string{"data-ref-unknown collect.disks.foreach"}},
		{"later expressions see every step", func(r *rule.Rule) {
			r.Check.ReviewWhen = "size(data.disks) > 0"
			r.Evidence = []string{"data.disks", "data.instances"}
		}, nil},
		{"the first of two steps with one id is visible to a later foreach", func(r *rule.Rule) {
			r.Collect = []rule.Step{{ID: "a", Gcloud: "x"}, {ID: "b", Gcloud: "x", Foreach: "data.a"}, {ID: "a", Gcloud: "x"}}
			r.Resource.From = "data.b"
		}, []string{"step-id-duplicate collect.a"}},
		{"implicit cluster step in a cluster rule", func(r *rule.Rule) {
			r.Scope = "cluster"
			r.Collect[0].Foreach = "data.cluster.nodePools"
			r.Check.Assert = "data.cluster.name != ''"
		}, nil},
		{"data.cluster outside a cluster rule", withAssert("data.cluster.name != ''"), []string{"data-ref-unknown check.assert"}},

		// r
		{"r in an aggregate rule", func(r *rule.Rule) { asAggregate(r); r.Check.Assert = "r.ok" },
			[]string{"r-unavailable check.assert"}},
		{"r twice in one expression is one finding", func(r *rule.Rule) { asAggregate(r); r.Check.Assert = "r.a && r.b" },
			[]string{"r-unavailable check.assert"}},
		{"r in each expression of an aggregate rule", func(r *rule.Rule) {
			asAggregate(r)
			r.Check.Assert, r.Check.ReviewWhen, r.Evidence = "r.a", "r.b", []string{"r.c"}
		}, []string{"r-unavailable check.assert", "r-unavailable check.review_when", "r-unavailable evidence[0]"}},
		{"macro variable r in an aggregate rule", func(r *rule.Rule) {
			asAggregate(r)
			r.Check.Assert = "data.instances.exists(r, r.name == 'x')"
		}, nil},
		{"r after a macro in an aggregate rule", func(r *rule.Rule) {
			asAggregate(r)
			r.Check.Assert = "data.instances.exists(r, r.name == 'x') && r.ok"
		}, []string{"r-unavailable check.assert"}},
		{"bind variable r in an aggregate rule", func(r *rule.Rule) { asAggregate(r); r.Check.Assert = "cel.bind(r, 1, r + 1) > 0" }, nil},
		{"bind initializer r in an aggregate rule", func(r *rule.Rule) { asAggregate(r); r.Check.Assert = "cel.bind(r, r, true)" },
			[]string{"r-unavailable check.assert"}},

		// compilation
		{"syntax error", withAssert("size(r.disks) <="), []string{"cel-compile check.assert"}},
		{"type error", withAssert(`("a" + 1) == "b"`), []string{"cel-compile check.assert"}},
		{"unknown function", withAssert("nope(1)"), []string{"cel-compile check.assert"}},
		{"a custom function", withAssert(`portRangeContains("20-30", 22) && days(1) == duration("24h")`), nil},
		{"a compile error does not hide a bad reference", withAssert(`("a" + 1) == data.volumes`),
			[]string{"cel-compile check.assert", "data-ref-unknown check.assert"}},
		{"a blank expression is left to the schema", withAssert("  \n "), nil},
		{"a multi-line expression", withAssert("size(r.disks) <=\n  params.limit &&\n  nope(1)"),
			[]string{"cel-compile check.assert"}},
		{"a very long expression", withAssert("size(r.disks) <= " + strings.Repeat("params.limit + ", 5000) + "+"),
			[]string{"cel-compile check.assert"}},
		{"a very long name", withAssert("data." + strings.Repeat("x", 5000) + " == 1"), []string{"data-ref-unknown check.assert"}},
		{"nesting past the parser limit", withAssert(strings.Repeat("(", 5000) + "1" + strings.Repeat(")", 5000)),
			[]string{"cel-compile check.assert"}},

		// template variables
		{"step template without foreach has no item", func(r *rule.Rule) { r.Collect[0].Gcloud = "x {{ .item.name }}" },
			[]string{"template-var-undeclared collect.instances.gcloud"}},
		{"foreach variable defaults to item", func(r *rule.Rule) {
			r.Collect[1].Foreach = "data.instances"
			r.Collect[1].Gcloud = "x {{ .item.name }}"
		}, nil},
		{"foreach variable named by as", func(r *rule.Rule) {
			r.Collect[1].Foreach, r.Collect[1].As = "data.instances", "vm"
			r.Collect[1].Gcloud = "x {{ .vm.name }} {{ .item.name }}"
		}, []string{"template-var-undeclared collect.disks.gcloud"}},
		{"as without foreach declares nothing", func(r *rule.Rule) {
			r.Collect[1].As = "vm"
			r.Collect[1].Gcloud = "x {{ .vm.name }}"
		}, []string{"template-var-undeclared collect.disks.gcloud"}},
		{"every step variable", func(r *rule.Rule) {
			r.Collect[0].Gcloud = "x {{ .project }} {{ .project_number }} {{ .organization }} {{ .folder }} {{ .cluster.name }} {{ .params.limit }}"
			// A param that is written into a command has to be constrained.
			upper := 10.0
			r.ParamsConstraints = map[string]rule.ParamConstraint{"limit": {Maximum: &upper}}
		}, nil},
		{"r is not a step variable", func(r *rule.Rule) { r.Collect[0].Gcloud = "x {{ .r.name }}" },
			[]string{"template-var-undeclared collect.instances.gcloud"}},
		{"data is not a step variable", func(r *rule.Rule) { r.Collect[0].Gcloud = "x {{ .data.disks }}" },
			[]string{"template-var-undeclared collect.instances.gcloud"}},
		{"kubectl template", func(r *rule.Rule) {
			r.Collect = append(r.Collect, rule.Step{ID: "k", Kubectl: "get nodes {{ .nope }}"})
		}, []string{"template-var-undeclared collect.k.kubectl"}},
		{"api url template", func(r *rule.Rule) {
			r.Collect = append(r.Collect, rule.Step{ID: "a", API: &rule.APIStep{Method: "GET", URL: "https://x.example/{{ .nope }}"}})
		}, []string{"template-var-undeclared collect.a.api.url"}},
		{"a step with no id is located by position", func(r *rule.Rule) { r.Collect[1].ID, r.Collect[1].Gcloud = "", "x {{ .nope }}" },
			[]string{"template-var-undeclared collect[1].gcloud"}},
		{"every message variable", withMessage("{{ .r.name }} {{ .params.limit }} {{ .project }} {{ .project_number }} {{ .organization }} {{ .folder }} {{ .cluster }}"), nil},
		{"ctx is not a message variable", withMessage("{{ .ctx.project }}"), []string{"template-var-undeclared check.message"}},
		{"foreach variable is not a message variable", func(r *rule.Rule) {
			r.Collect[1].Foreach, r.Collect[1].As = "data.instances", "vm"
			r.Check.Message = "{{ .vm.name }}"
		}, []string{"template-var-undeclared check.message"}},
		{"review message", func(r *rule.Rule) { r.Check.ReviewMessage = "{{ .nope.x }}" },
			[]string{"template-var-undeclared check.review_message"}},
		{"one finding per name", withMessage("{{ .a }} {{ .a }} {{ .b }}"),
			[]string{"template-var-undeclared check.message", "template-var-undeclared check.message"}},
		{"r in the message of an aggregate rule", func(r *rule.Rule) { asAggregate(r); r.Check.Message = "{{ .r.name }} {{ .r.id }}" },
			[]string{"r-unavailable check.message"}},
		{"names in plain text are not variables", withMessage("see .nope, data.nope and {{ .project }}"), nil},
		{"dot on its own", withMessage("{{ . }}"), nil},

		// template params
		{"template reads a param", withMessage("{{ .params.limit }}"), nil},
		{"template reads all params", withMessage("{{ .params }}"), nil},
		{"template reads an unknown param", withMessage("{{ .params.missing }}"), []string{"params-ref-undefined check.message"}},
		{"step template reads an unknown param", func(r *rule.Rule) { r.Collect[0].Gcloud = "x {{ .params.missing }}" },
			[]string{"params-ref-undefined collect.instances.gcloud"}},
		{"template reads an unknown param through parentheses", withMessage("{{ (.params).missing }}"),
			[]string{"params-ref-undefined check.message"}},
		{"template reads an unknown param from the root", withMessage("{{ $.params.missing }}"),
			[]string{"params-ref-undefined check.message"}},
		{"template reads a nested field of a param", withMessage("{{ .params.names }} {{ .params.limit.x }}"), nil},

		// template control flow, functions and the dot
		{"if and else", withMessage("{{ if .params.limit }}a{{ else }}b{{ end }}"), nil},
		{"else if", withMessage("{{ if .params.limit }}a{{ else if .project }}b{{ else }}c{{ end }}"), nil},
		{"if on an unknown param", withMessage("{{ if .params.missing }}a{{ else }}b{{ end }}"),
			[]string{"params-ref-undefined check.message"}},
		{"if with a function", withMessage(`{{ if eq .r.name "default" }}a{{ end }}`), nil},
		{"functions and pipelines", withMessage(`{{ printf "%d" .params.limit }} {{ len .params.names | printf "%d" }} {{ index .params.names 0 }}`), nil},
		{"range body reads the element", withMessage("{{ range .params.names }}{{ .name }}{{ . }}{{ end }}"), nil},
		{"range pipeline is outside the loop", withMessage("{{ range .nope }}x{{ end }}"),
			[]string{"template-var-undeclared check.message"}},
		{"range else branch reads the root", withMessage("{{ range .params.names }}x{{ else }}{{ .nope }}{{ end }}"),
			[]string{"template-var-undeclared check.message"}},
		{"root variable inside a range", withMessage("{{ range .params.names }}{{ $.nope }}{{ end }}"),
			[]string{"template-var-undeclared check.message"}},
		{"with body reads the value", withMessage("{{ with .cluster }}{{ .name }}{{ end }}"), nil},
		{"with inside range stays relative", withMessage("{{ range .params.names }}{{ with .x }}{{ .y }}{{ end }}{{ end }}"), nil},
		{"local variable", withMessage("{{ $x := .params.limit }}{{ $x }} {{ $x.y }}"), nil},
		{"local variable initializer", withMessage("{{ $x := .nope }}{{ $x }}"), []string{"template-var-undeclared check.message"}},
		{"root variable", withMessage("{{ $.params.limit }} {{ $ }}"), nil},
		{"unknown root variable", withMessage("{{ $.nope }}"), []string{"template-var-undeclared check.message"}},
		{"if reads the root in the then branch", withMessage("{{ if .params.limit }}{{ .nope }}{{ end }}"),
			[]string{"template-var-undeclared check.message"}},
		{"if reads the root in the else branch", withMessage("{{ if .params.limit }}a{{ else }}{{ .nope }}{{ end }}"),
			[]string{"template-var-undeclared check.message"}},
		{"with else branch reads the root", withMessage("{{ with .params.names }}x{{ else }}{{ .nope }}{{ end }}"),
			[]string{"template-var-undeclared check.message"}},
		{"argument of a function", withMessage(`{{ printf "%d" .nope }}`), []string{"template-var-undeclared check.message"}},
		{"argument of a later command in a pipeline", withMessage(`{{ len .params.names | printf "%s" .nope }}`),
			[]string{"template-var-undeclared check.message"}},
		{"template call argument", withMessage(`{{ define "x" }}{{ .a }}{{ end }}{{ template "x" .nope }}`),
			[]string{"template-var-undeclared check.message"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := baseRule()
			c.edit(r)
			wantFindings(t, lintRules(r), c.want...)
		})
	}

	t.Run("a step id that is long is cut in the location", func(t *testing.T) {
		long := strings.Repeat("s", 5000)
		r := baseRule()
		r.Collect = append(r.Collect, rule.Step{ID: long, Gcloud: "x {{ .nope }}"})
		fs := lintRules(r)
		if len(fs) != 1 || len(fs[0].Where) > 200 {
			t.Errorf("want one finding with a bounded location, got %d findings: %+v", len(fs), fs)
		}
	})
}

func TestRun_CleanFixtureHasNoFindings(t *testing.T) {
	path := fixtureRoot + "clean-dir/clean.yaml"
	if fs := runFixture(t, path); len(fs) != 0 {
		t.Errorf("clean fixture has findings:\n%s", lint.FormatText(fs))
	}

	// The fixture has to keep the three shapes later checks and tests rely on.
	files, _ := parseFixtures(t, path)
	var foreachWithAttach, aggregate, cluster bool
	for _, r := range files[0].Rules {
		aggregate = aggregate || r.Resource == nil
		cluster = cluster || r.Scope == "cluster"
		for _, s := range r.Collect {
			foreachWithAttach = foreachWithAttach || (s.Foreach != "" && s.Attach != "")
		}
	}
	if !foreachWithAttach || !aggregate || !cluster {
		t.Errorf("clean fixture lost a shape: foreach with attach=%v, aggregate rule=%v, cluster rule=%v",
			foreachWithAttach, aggregate, cluster)
	}
}

func TestRun_RuleIDDuplicateAcrossFiles(t *testing.T) {
	const id = "cis-lint-rule-id-duplicate-1"
	files, vs := parseFixtures(t, fixtureRoot+"rule-id-duplicate/a.yaml", fixtureRoot+"rule-id-duplicate/b.yaml")
	if len(vs) != 0 {
		t.Fatalf("the duplicate fixtures are valid on their own, got %+v", vs)
	}

	// The pair is reported once, on the later file, whatever order Run is given the files in.
	for _, order := range [][]*rule.File{{files[0], files[1]}, {files[1], files[0]}} {
		fs := lint.Run(order, nil, lint.Options{})
		if len(fs) != 1 {
			t.Fatalf("want exactly one finding for the pair, got %+v", fs)
		}
		f := fs[0]
		if f.Code != "rule-id-duplicate" || f.File != "rule-id-duplicate/b.yaml" || f.RuleID != id || f.Where != "id" {
			t.Errorf("got %+v", f)
		}
		if !strings.Contains(f.Message, "rule-id-duplicate/a.yaml") || !strings.Contains(f.Message, "rule-id-duplicate/b.yaml") {
			t.Errorf("the message should name both files: %q", f.Message)
		}
	}

	named := func(name string, ids ...string) *rule.File {
		f := &rule.File{Name: name}
		for _, id := range ids {
			f.Rules = append(f.Rules, &rule.Rule{ID: id})
		}
		return f
	}
	cases := []struct {
		name  string
		files []*rule.File
		want  []string // "<file> <code>" of each finding
	}{
		{"three files", []*rule.File{named("a.yaml", "x"), named("b.yaml", "x"), named("c.yaml", "x")},
			[]string{"b.yaml rule-id-duplicate", "c.yaml rule-id-duplicate"}},
		{"one file twice", []*rule.File{named("a.yaml", "x", "y", "x")}, []string{"a.yaml rule-id-duplicate"}},
		{"distinct ids", []*rule.File{named("a.yaml", "x"), named("b.yaml", "y")}, nil},
		{"no id is not an id", []*rule.File{named("a.yaml", "", ""), named("b.yaml", "")}, nil},
		{"nil entries are skipped", []*rule.File{nil, named("a.yaml", "x"), {Name: "n.yaml", Rules: []*rule.Rule{nil}}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			for _, f := range lint.Run(c.files, nil, lint.Options{}) {
				got = append(got, f.File+" "+f.Code)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestRun_SchemaViolationsBecomeFindings(t *testing.T) {
	// A violation found by the real loader keeps its path and names the rule it is in.
	files, vs := parseFixtures(t, fixtureRoot+"schema.yaml")
	if len(vs) != 1 {
		t.Fatalf("schema.yaml must have exactly one violation, got %+v", vs)
	}
	got := lint.Run(files, vs, lint.Options{})
	want := lint.Finding{File: "schema.yaml", RuleID: "cis-lint-schema-1", Where: "/rules/0/ref", Code: "schema", Message: vs[0].Message}
	if len(got) != 1 || got[0] != want {
		t.Errorf("got %+v, want [%+v]", got, want)
	}

	// The rule id is a best effort: it is there only when the path points into a rule that was decoded.
	file := &rule.File{Name: "x.yaml", Rules: []*rule.Rule{{ID: "r-a"}, {ID: "r-b"}}}
	paths := []struct{ file, path, wantRuleID string }{
		{"x.yaml", "/rules/0/ref", "r-a"},
		{"x.yaml", "/rules/1/check/assert", "r-b"},
		{"x.yaml", "/rules/1", "r-b"},
		{"x.yaml", "/rules/2/ref", ""},
		{"x.yaml", "/rules/x/ref", ""},
		{"x.yaml", "/rules/-1/ref", ""},
		{"x.yaml", "/benchmark/id", ""},
		{"x.yaml", "", ""},
		{"gone.yaml", "/rules/0/ref", ""},
	}
	var violations []rule.Violation
	for _, p := range paths {
		violations = append(violations, rule.Violation{File: p.file, Path: p.path, Message: "bad value\nsecond line"})
	}
	byKey := map[string]lint.Finding{}
	for _, f := range lint.Run([]*rule.File{file}, violations, lint.Options{}) {
		if f.Code != "schema" {
			t.Errorf("unexpected finding %+v", f)
		}
		byKey[f.File+" "+f.Where] = f
	}
	for _, p := range paths {
		f, ok := byKey[p.file+" "+p.path]
		if !ok {
			t.Errorf("no finding for %s %q", p.file, p.path)
			continue
		}
		if f.RuleID != p.wantRuleID || f.Message != "bad value second line" {
			t.Errorf("%s %q: got rule id %q and message %q, want %q and a single-line message", p.file, p.path, f.RuleID, f.Message, p.wantRuleID)
		}
	}
}

func TestRun_NoFilesIsAFinding(t *testing.T) {
	opts := lint.Options{}
	for name, fs := range map[string][]lint.Finding{
		"nil":   lint.Run(nil, nil, opts),
		"empty": lint.Run([]*rule.File{}, nil, opts),
		"nils":  lint.Run([]*rule.File{nil}, []rule.Violation{}, opts),
	} {
		if len(fs) != 1 || fs[0].Code != "no-rule-files" || fs[0].File != "" || fs[0].RuleID != "" || fs[0].Message == "" {
			t.Errorf("%s: want exactly one no-rule-files finding without a file or rule, got %+v", name, fs)
		}
	}

	// With a file or a violation there is something to report on, and no such finding.
	withFile := lint.Run([]*rule.File{{Name: "a.yaml"}}, nil, opts)
	if len(withFile) != 0 {
		t.Errorf("a file with nothing wrong: want no findings, got %+v", withFile)
	}
	withViolation := lint.Run(nil, []rule.Violation{{File: "a.yaml", Message: "unreadable yaml: yaml-syntax: x"}}, opts)
	if len(withViolation) != 1 || withViolation[0].Code != "schema" {
		t.Errorf("a violation without files: want exactly one schema finding, got %+v", withViolation)
	}
	for _, f := range append(withFile, withViolation...) {
		if f.Code == "no-rule-files" {
			t.Errorf("unexpected %+v", f)
		}
	}
}

func TestRun_StringLiteralMentioningDataIsNotAReference(t *testing.T) {
	for _, expr := range []string{
		`r.name == "data.nope"`,
		`r.name == 'params.nope' || r.name == "ctx.nope"`,
		`r.name == r"data.nope"`,
		`r.name == """data.nope"""`,
		`r.name.contains("data.nope") && "x" in ["params.nope", "ctx.nope"]`,
		`r.name.matches("^data\\.nope$")`,
		`{"data.nope": 1}["data.nope"] == 1`,
		`size(b"data.nope") > 0`,
	} {
		t.Run(expr, func(t *testing.T) {
			r := baseRule()
			r.Check.Assert = expr
			wantFindings(t, lintRules(r))
		})
	}

	// Text and strings in a template are not references either; only the fields read by an action are.
	for _, text := range []string{
		"see data.nope and params.nope",
		`{{ "data.nope" }} {{ "{{ .nope }}" }}`,
		`{{ printf "%s" "ctx.nope" }}`,
		"{{ `.nope` }}",
	} {
		t.Run(text, func(t *testing.T) {
			r := baseRule()
			r.Check.Message = text
			wantFindings(t, lintRules(r))
		})
	}

	// The same text outside a string is a reference.
	r := baseRule()
	r.Check.Assert = `r.name == data.nope`
	wantFindings(t, lintRules(r), "data-ref-unknown check.assert")
}

func TestRun_MalformedTemplateReportsParseNotPanic(t *testing.T) {
	texts := []string{
		"{{ .project",
		"{{ range }}",
		"{{ end }}",
		"{{ if .params.limit }}x",
		"{{ nosuchfunction .project }}",
		`{{ "unterminated }}`,
		"{{ | .a }}",
		"{{ template }}",
		"{{ $x }}",
		"{{" + strings.Repeat("(", 100000) + ".a" + strings.Repeat(")", 100000) + "}}",
		strings.Repeat("{{ if .params.limit }}", 20000),
	}
	for _, s := range templateSites {
		for _, text := range texts {
			t.Run(fmt.Sprintf("%s/%.20s", s.where, text), func(t *testing.T) {
				r := baseRule()
				s.set(r, text)
				wantFindings(t, lintRules(r), "template-parse "+s.where)
			})
		}
	}
}

func TestFormatText_IsSortedAndStable(t *testing.T) {
	fs := []lint.Finding{
		{File: "b.yaml", RuleID: "r-1", Where: "check.assert", Code: "cel-compile", Message: "m1"},
		{File: "a.yaml", RuleID: "r-2", Where: "check.assert", Code: "cel-compile", Message: "m2"},
		{File: "a.yaml", RuleID: "r-1", Where: "evidence[0]", Code: "data-ref-unknown", Message: "m3"},
		{File: "a.yaml", RuleID: "r-1", Where: "check.assert", Code: "data-ref-unknown", Message: "m4"},
		{File: "a.yaml", RuleID: "r-1", Where: "check.assert", Code: "cel-compile", Message: "line one\nline two\r\n"},
		{File: "a.yaml", RuleID: "r-1", Where: "check.assert", Code: "data-ref-unknown", Message: "m0"},
	}
	want := strings.Join([]string{
		"a.yaml: r-1: check.assert: cel-compile: line one line two",
		"a.yaml: r-1: check.assert: data-ref-unknown: m0",
		"a.yaml: r-1: check.assert: data-ref-unknown: m4",
		"a.yaml: r-1: evidence[0]: data-ref-unknown: m3",
		"a.yaml: r-2: check.assert: cel-compile: m2",
		"b.yaml: r-1: check.assert: cel-compile: m1",
	}, "\n") + "\n"

	before := slices.Clone(fs)
	if got := lint.FormatText(fs); got != want {
		t.Errorf("FormatText:\n got\n%s want\n%s", got, want)
	}
	if !slices.Equal(fs, before) {
		t.Errorf("FormatText reordered its argument: %+v", fs)
	}
	reversed := slices.Clone(fs)
	slices.Reverse(reversed)
	if got := lint.FormatText(reversed); got != want {
		t.Errorf("the order of the input changed the output:\n%s", got)
	}

	if got := lint.FormatText(nil); got != "" {
		t.Errorf("FormatText(nil) = %q, want nothing", got)
	}
	if got := lint.FormatText([]lint.Finding{}); got != "" {
		t.Errorf("FormatText of an empty list = %q, want nothing", got)
	}
	// A finding without a file or a rule keeps its columns, so that every line has the same shape.
	if got, want := lint.FormatText([]lint.Finding{{Code: "no-rule-files", Message: "m"}}), ": : : no-rule-files: m\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	// What Run returns is already in that order and does not change between calls.
	r := baseRule()
	r.Check.Assert = "data.zzz == data.aaa && params.nope == ctx.nope"
	r.Check.Message = "{{ .zzz }} {{ .aaa }}"
	r.Evidence = []string{"data.mmm", "data.bbb"}
	r.Collect = append(r.Collect, rule.Step{ID: "disks", Gcloud: "x"})
	first := lintRules(r)
	if len(first) < 8 {
		t.Fatalf("want a rule with many findings, got %+v", first)
	}
	compare := func(a, b lint.Finding) int {
		return cmp.Or(cmp.Compare(a.File, b.File), cmp.Compare(a.RuleID, b.RuleID), cmp.Compare(a.Code, b.Code),
			cmp.Compare(a.Where, b.Where), cmp.Compare(a.Message, b.Message))
	}
	if !slices.IsSortedFunc(first, compare) {
		t.Errorf("Run did not sort by file, rule, code, where and message:\n%s", lint.FormatText(first))
	}
	if second := lintRules(r); !slices.Equal(first, second) {
		t.Errorf("Run is not stable:\n%s\n%s", lint.FormatText(first), lint.FormatText(second))
	}
	if got := lint.FormatText(first); strings.Count(got, "\n") != len(first) {
		t.Errorf("want one line per finding, got %d findings in:\n%s", len(first), got)
	}
}
