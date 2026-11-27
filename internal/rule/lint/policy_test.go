package lint_test

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/internal/rule/lint"
)

// Where the findings about the steps that policyCase edits are reported.
const (
	gcloudWhere  = "collect.instances.gcloud"
	kubectlWhere = "collect.extra.kubectl"
	apiWhere     = "collect.extra.api.url"
)

// ptr returns a pointer to v, for the optional fields of a constraint.
func ptr[T any](v T) *T { return &v }

// policyOptions returns the options the command line passes: the allowlist that is built into the
// program. A rule that lints clean with them has no policy violation.
func policyOptions(t *testing.T) lint.Options {
	t.Helper()
	allow, err := rule.LoadAllowlist()
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	return lint.Options{Allow: allow}
}

// lintPolicy lints rules held in one file that was never written to disk, with the allowlist.
func lintPolicy(t *testing.T, rules ...*rule.Rule) []lint.Finding {
	t.Helper()
	return lint.Run([]*rule.File{{Name: "inline.yaml", Rules: rules}}, nil, policyOptions(t))
}

// lintWithAllowlist lints rules with an allowlist that is written out in the document, for the
// cases that need an entry the real allowlist does not have.
func lintWithAllowlist(t *testing.T, doc string, rules ...*rule.Rule) []lint.Finding {
	t.Helper()
	allow, err := rule.ParseAllowlist([]byte(doc))
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	return lint.Run([]*rule.File{{Name: "inline.yaml", Rules: rules}}, nil, lint.Options{Allow: allow})
}

// policyCase changes a fresh baseRule and says which findings the allowlist run reports for it,
// each written "<code> <where>".
type policyCase struct {
	name string
	edit func(r *rule.Rule)
	want []string
}

func runPolicyCases(t *testing.T, cases []policyCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := baseRule()
			c.edit(r)
			wantFindings(t, lintPolicy(t, r), c.want...)
		})
	}
}

// withGcloud sets the command of the first step.
func withGcloud(cmd string) func(*rule.Rule) {
	return func(r *rule.Rule) { r.Collect[0].Gcloud = cmd }
}

// withKubectlStep adds a kubectl step.
func withKubectlStep(cmd string) func(*rule.Rule) {
	return func(r *rule.Rule) { r.Collect = append(r.Collect, rule.Step{ID: "extra", Kubectl: cmd}) }
}

// withAPIStep adds a REST step.
func withAPIStep(method, url string) func(*rule.Rule) {
	return func(r *rule.Rule) {
		r.Collect = append(r.Collect, rule.Step{ID: "extra", API: &rule.APIStep{Method: method, URL: url}})
	}
}

// withParam defines a param and, when c is not nil, its constraint.
func withParam(name string, def any, c *rule.ParamConstraint) func(*rule.Rule) {
	return func(r *rule.Rule) {
		r.Params[name] = def
		if c != nil {
			if r.ParamsConstraints == nil {
				r.ParamsConstraints = map[string]rule.ParamConstraint{}
			}
			r.ParamsConstraints[name] = *c
		}
	}
}

// together applies several edits in order.
func together(edits ...func(*rule.Rule)) func(*rule.Rule) {
	return func(r *rule.Rule) {
		for _, e := range edits {
			e(r)
		}
	}
}

func TestRun_PolicyFixtures(t *testing.T) {
	// Each fixture holds one rule, cis-lint-<code>-1, and produces exactly one finding of its code
	// when it is linted with the allowlist. The table says where, and a word the message has.
	fixtures := []struct{ code, where, messageHas string }{
		{"command-not-allowed", gcloudWhere, "compute instances delete list"},
		{"flag-forbidden", gcloudWhere, "--impersonate-service-account"},
		{"evaluate-per-mismatch", "check.assert", "ctx.project"},
		{"attach-without-foreach", "collect.service_accounts.attach", "accounts"},
		{"attach-source", "collect.user_keys.foreach", "user_keys"},
		{"params-template-unconstrained", gcloudWhere, "params.status"},
		{"params-default-violates-constraint", "params_constraints.max_disks", "maximum"},
		{"params-constraint-unknown", "params_constraints.wanted_status", "wanted_status"},
	}
	for _, fx := range fixtures {
		t.Run(fx.code, func(t *testing.T) {
			fs := runFixture(t, fixtureRoot+fx.code+".yaml")
			if len(fs) != 1 || fs[0].Code != fx.code {
				t.Fatalf("%s: want exactly one finding of that code, got %+v", fx.code, fs)
			}
			want := lint.Finding{File: fx.code + ".yaml", RuleID: "cis-lint-" + fx.code + "-1", Where: fx.where, Code: fx.code, Message: fs[0].Message}
			if fs[0] != want || fs[0].Message == "" {
				t.Errorf("got %+v, want %+v with a message", fs[0], want)
			}
			if !strings.Contains(fs[0].Message, fx.messageHas) {
				t.Errorf("message %q does not mention %q", fs[0].Message, fx.messageHas)
			}
		})
	}

	t.Run("a flag is named in the message and its value is not", func(t *testing.T) {
		fs := runFixture(t, fixtureRoot+"flag-forbidden.yaml")
		if len(fs) == 1 && strings.Contains(fs[0].Message, "example-sec") {
			t.Errorf("the message repeats the value of the flag: %q", fs[0].Message)
		}
	})
}

// orgRule returns an organization rule that lints clean for either evaluate_per value.
func orgRule(evaluatePer string) *rule.Rule {
	return &rule.Rule{
		ID:          "cis-inline-org-1",
		Scope:       "organization",
		EvaluatePer: evaluatePer,
		Collect: []rule.Step{
			{ID: "policies", Gcloud: "access-context-manager policies list --organization={{ .organization }} --format=json"},
		},
		Resource: &rule.Resource{From: "data.policies", Kind: "accesscontextmanager.googleapis.com/AccessPolicy", Name: "r.name"},
		Params:   map[string]any{"project": "p", "names": []any{"a"}},
		Check: rule.Check{
			Assert:  `r.name != ""`,
			Message: "Access policy {{ .r.name }} of organization {{ .organization }} is not usable",
		},
	}
}

func TestRun_EvaluatePerPresence(t *testing.T) {
	// The fixture breaks the schema as well, which is how a rule that went through the loader
	// shows this defect twice: once from the schema and once, with the rule id, from the lint.
	files, violations := parseFixtures(t, fixtureRoot+"evaluate-per.yaml")
	if len(violations) != 1 {
		t.Fatalf("evaluate-per.yaml must have exactly one schema violation, got %+v", violations)
	}
	fs := lint.Run(files, violations, policyOptions(t))
	var codes []string
	for _, f := range fs {
		codes = append(codes, f.Code)
	}
	slices.Sort(codes)
	if !slices.Equal(codes, []string{"evaluate-per", "schema"}) {
		t.Fatalf("want one schema and one evaluate-per finding, got:\n%s", lint.FormatText(fs))
	}
	for _, f := range fs {
		if f.Code == "evaluate-per" {
			want := lint.Finding{File: "evaluate-per.yaml", RuleID: "cis-lint-evaluate-per-1", Where: "evaluate_per", Code: "evaluate-per", Message: f.Message}
			if f != want || f.Message == "" {
				t.Errorf("got %+v, want %+v with a message", f, want)
			}
		}
	}

	// Rules built in memory never went through the schema, and the lint finds the defect alone.
	const bad = "evaluate-per evaluate_per"
	cases := []struct {
		name string
		rule *rule.Rule
		want []string
	}{
		{"organization rule without evaluate_per", orgRule(""), []string{bad}},
		{"organization rule with an unknown value", orgRule("region"), []string{bad}},
		{"organization rule with a value in the wrong case", orgRule("Project"), []string{bad}},
		{"organization rule evaluated per project", orgRule("project"), nil},
		{"organization rule evaluated per organization", orgRule("organization"), nil},
		{"project rule with evaluate_per project", func() *rule.Rule {
			r := baseRule()
			r.EvaluatePer = "project"
			return r
		}(), []string{bad}},
		{"project rule with evaluate_per organization", func() *rule.Rule {
			r := baseRule()
			r.EvaluatePer = "organization"
			return r
		}(), []string{bad}},
		{"cluster rule with evaluate_per", func() *rule.Rule {
			r := baseRule()
			r.Scope, r.EvaluatePer = "cluster", "project"
			return r
		}(), []string{bad}},
		{"project rule without evaluate_per", baseRule(), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantFindings(t, lintPolicy(t, c.rule), c.want...)
		})
	}
}

// mismatchSite is a place an organization rule can hold a reference to the project or the folder
// and a way to put one there. field is project, project_number or folder.
type mismatchSite struct {
	where string
	set   func(r *rule.Rule, field string)
}

var mismatchSites = []mismatchSite{
	// CEL expressions
	{"collect.scoped.foreach", func(r *rule.Rule, f string) {
		r.Collect = append(r.Collect, rule.Step{ID: "scoped", Foreach: "data.policies.filter(p, p.name != ctx." + f + ")", As: "p",
			Gcloud: "access-context-manager perimeters list --policy={{ .p.name }} --format=json"})
	}},
	{"resource.from", func(r *rule.Rule, f string) { r.Resource.From = `data.policies.filter(p, ctx.` + f + ` != "")` }},
	{"resource.filter", func(r *rule.Rule, f string) { r.Resource.Filter = `ctx.` + f + ` != ""` }},
	{"resource.name", func(r *rule.Rule, f string) { r.Resource.Name = `r.name + string(ctx.` + f + `)` }},
	{"resource.key", func(r *rule.Rule, f string) { r.Resource.Key = `r.name + string(ctx.` + f + `)` }},
	{"check.assert", func(r *rule.Rule, f string) { r.Check.Assert = `ctx.` + f + ` != ""` }},
	{"check.review_when", func(r *rule.Rule, f string) { r.Check.ReviewWhen = `ctx.` + f + ` == ""` }},
	{"evidence[0]", func(r *rule.Rule, f string) { r.Evidence = []string{"ctx." + f} }},

	// templates
	{"collect.policies.gcloud", func(r *rule.Rule, f string) { r.Collect[0].Gcloud += " --filter=name:{{ ." + f + " }}" }},
	{"collect.rest.api.url", func(r *rule.Rule, f string) {
		r.Collect = append(r.Collect, rule.Step{ID: "rest", API: &rule.APIStep{Method: "GET",
			URL: "https://bigquery.googleapis.com/bigquery/v2/projects/{{ ." + f + " }}/datasets"}})
	}},
	{"collect.kube.kubectl", func(r *rule.Rule, f string) {
		r.Collect = append(r.Collect, rule.Step{ID: "kube", Kubectl: "get pods --namespace={{ ." + f + " }}"})
	}},
	{"check.message", func(r *rule.Rule, f string) { r.Check.Message = "Value {{ ." + f + " }}" }},
	{"check.review_message", func(r *rule.Rule, f string) { r.Check.ReviewMessage = "Value {{ ." + f + " }}" }},
}

// withEveryMismatch puts a reference to field in every site.
func withEveryMismatch(field string) func(*rule.Rule) {
	return func(r *rule.Rule) {
		for _, s := range mismatchSites {
			s.set(r, field)
		}
	}
}

func TestRun_EvaluatePerMismatch(t *testing.T) {
	var everywhere []string
	for _, s := range mismatchSites {
		everywhere = append(everywhere, "evaluate-per-mismatch "+s.where)
	}

	t.Run("each field in each site", func(t *testing.T) {
		for _, field := range []string{"project", "project_number", "folder"} {
			for _, s := range mismatchSites {
				t.Run(field+"/"+s.where, func(t *testing.T) {
					r := orgRule("organization")
					s.set(r, field)
					wantFindings(t, lintPolicy(t, r), "evaluate-per-mismatch "+s.where)
				})
			}
		}
	})

	t.Run("the message names the value and the reason", func(t *testing.T) {
		r := orgRule("organization")
		mismatchSites[5].set(r, "project") // check.assert
		fs := lintPolicy(t, r)
		if len(fs) != 1 || !strings.Contains(fs[0].Message, "ctx.project") || !strings.Contains(fs[0].Message, "evaluate_per") {
			t.Errorf("want a message with the reference and evaluate_per, got %+v", fs)
		}
		r = orgRule("organization")
		mismatchSites[len(mismatchSites)-2].set(r, "folder") // check.message
		fs = lintPolicy(t, r)
		if len(fs) != 1 || !strings.Contains(fs[0].Message, ".folder") {
			t.Errorf("want a message with the template field, got %+v", fs)
		}
	})

	cases := []struct {
		name string
		rule func() *rule.Rule
		want []string
	}{
		{"every site at once is one finding for each", func() *rule.Rule {
			r := orgRule("organization")
			withEveryMismatch("project")(r)
			return r
		}, everywhere},
		{"the same references are fine when evaluated per project", func() *rule.Rule {
			r := orgRule("project")
			withEveryMismatch("project")(r)
			return r
		}, nil},
		{"the folder is fine when evaluated per project", func() *rule.Rule {
			r := orgRule("project")
			withEveryMismatch("folder")(r)
			return r
		}, nil},
		{"the same references are fine in a project rule", func() *rule.Rule {
			r := orgRule("organization")
			withEveryMismatch("project")(r)
			r.Scope, r.EvaluatePer = "project", ""
			return r
		}, nil},
		{"the same references are fine in a cluster rule", func() *rule.Rule {
			r := orgRule("organization")
			withEveryMismatch("project_number")(r)
			r.Scope, r.EvaluatePer = "cluster", ""
			return r
		}, nil},
		{"the organization is there", func() *rule.Rule {
			r := orgRule("organization")
			withEveryMismatch("organization")(r)
			return r
		}, nil},
		{"two values in one site are one finding", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Assert = `ctx.project != "" && ctx.folder != "" && ctx.project_number != ""`
			return r
		}, []string{"evaluate-per-mismatch check.assert"}},
		{"two values in one template are one finding", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Message = "{{ .project }} {{ .folder }} {{ .project }}"
			return r
		}, []string{"evaluate-per-mismatch check.message"}},
		{"a macro variable called ctx is not the context", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Assert = "data.policies.exists(ctx, ctx.project == 1)"
			return r
		}, nil},
		{"the context outside the macro still counts", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Assert = "data.policies.exists(ctx, ctx.project == 1) && ctx.project != ''"
			return r
		}, []string{"evaluate-per-mismatch check.assert"}},
		{"a string that says ctx.project is not a reference", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Assert = `r.name == "ctx.project" && "ctx.folder" in [r.name]`
			return r
		}, nil},
		{"an index with a string literal is a reference", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Assert = `ctx["project"] != ""`
			return r
		}, []string{"evaluate-per-mismatch check.assert"}},
		{"a presence test is a reference", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Assert = `has(ctx.folder)`
			return r
		}, []string{"evaluate-per-mismatch check.assert"}},
		{"an optional select is a reference", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Assert = `ctx.?project.orValue("") != ""`
			return r
		}, []string{"evaluate-per-mismatch check.assert"}},
		{"a condition in a template is a reference", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Message = "{{ if .project }}in a project{{ else }}in the organization{{ end }}"
			return r
		}, []string{"evaluate-per-mismatch check.message"}},
		{"a field of the element is not a variable of the template", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Message = "{{ range .params.names }}{{ .project }}{{ end }}"
			return r
		}, nil},
		{"the root variable inside a range is the variable of the template", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Message = "{{ range .params.names }}{{ $.project }}{{ end }}"
			return r
		}, []string{"evaluate-per-mismatch check.message"}},
		{"a param called project is not the project", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Message = "{{ .params.project }}"
			return r
		}, nil},
		{"text that says .project is not a reference", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Message = `see .project and {{ "{{ .folder }}" }}`
			return r
		}, nil},
		{"an expression that does not compile is left to cel-compile", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Assert = "ctx.project =="
			return r
		}, []string{"cel-compile check.assert"}},
		{"a template that does not parse is left to template-parse", func() *rule.Rule {
			r := orgRule("organization")
			r.Check.Message = "{{ .project"
			return r
		}, []string{"template-parse check.message"}},
		{"nothing is checked when evaluate_per is missing", func() *rule.Rule {
			r := orgRule("")
			r.Check.Assert = `ctx.project != ""`
			return r
		}, []string{"evaluate-per evaluate_per"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantFindings(t, lintPolicy(t, c.rule()), c.want...)
		})
	}
}

func TestRun_DeleteVerbCommandIsNotAllowed(t *testing.T) {
	bad := []string{"command-not-allowed " + gcloudWhere}
	runPolicyCases(t, []policyCase{
		{"the allowed command", withGcloud("compute instances list --project={{ .project }} --format=json"), nil},
		{"a read verb used as a resource name", withGcloud("compute instances delete list --project={{ .project }}"), bad},
		{"a name that only starts like an allowed one", withGcloud("compute instances list-xyz"), bad},
		{"a command that is a prefix of an allowed one", withGcloud("compute instances"), bad},
		{"a command the engine runs but rules may not", withGcloud("projects describe example-prod"), bad},
		{"the version command of the engine", withGcloud("--version"), bad},
		{"a write command", withGcloud("compute instances stop example --project={{ .project }}"), bad},
		{"flags in front of the path", withGcloud("--project={{ .project }} compute instances list"), bad},
		{"an action in the path", withGcloud("compute {{ .project }} list"), bad},
		{"an empty command", withGcloud("   "), bad},
		{"quotes do not change the words", withGcloud(`'compute' "instances" list --project={{ .project }}`), nil},
		{"a quote that is not closed", withGcloud("compute instances list --filter='x"), bad},
		{"an action that is not closed", withGcloud("compute instances list --project={{ .project"),
			[]string{"command-not-allowed " + gcloudWhere, "template-parse " + gcloudWhere}},
		{"a step without an id is located by its position", func(r *rule.Rule) {
			r.Collect[1].ID, r.Collect[1].Gcloud = "", "compute disks delete list"
		}, []string{"command-not-allowed collect[1].gcloud"}},
	})

	t.Run("the message quotes the first four words and no more", func(t *testing.T) {
		r := baseRule()
		withGcloud("compute instances delete list --project=quoted-later --format=json")(r)
		fs := lintPolicy(t, r)
		if len(fs) != 1 || !strings.Contains(fs[0].Message, `"compute instances delete list"`) || strings.Contains(fs[0].Message, "quoted-later") {
			t.Errorf("want a message with the first four words only, got %+v", fs)
		}
	})

	t.Run("the path of a command is not read as flags", func(t *testing.T) {
		// An entry that is a whole command line starting with a dash, as the engine's version
		// command is: its words are the path, and the flags are what comes after it.
		r := baseRule()
		r.Collect = []rule.Step{{ID: "instances", Gcloud: "--version"}}
		wantFindings(t, lintWithAllowlist(t, "gcloud:\n  - {path: \"--version\", bind: [none]}\n", r))
	})

	t.Run("a command that cannot be split says so", func(t *testing.T) {
		r := baseRule()
		withGcloud("compute instances list --filter='x")(r)
		if fs := lintPolicy(t, r); len(fs) != 1 || !strings.Contains(fs[0].Message, "quote") {
			t.Errorf("want a message about the quote that is not closed, got %+v", fs)
		}
	})
}

func TestRun_ForbiddenFlagBothForms(t *testing.T) {
	gcloud := func(flags string) func(*rule.Rule) { return withGcloud("compute instances list " + flags) }
	kubectl := func(flags string) func(*rule.Rule) { return withKubectlStep("get pods " + flags) }
	badGcloud := []string{"flag-forbidden " + gcloudWhere}
	badKubectl := []string{"flag-forbidden " + kubectlWhere}
	namespace := together(
		withParam("namespace", "kube-system", &rule.ParamConstraint{Pattern: "[a-z0-9-]+"}),
		kubectl("--namespace={{ .params.namespace }}"))

	runPolicyCases(t, []policyCase{
		// gcloud: a flag on the forbidden list, one that is on no list, and each way of writing them
		{"account with a value attached", gcloud("--account=x"), badGcloud},
		{"impersonation with a separate value", gcloud("--impersonate-service-account x"), badGcloud},
		{"a debug flag", gcloud("--log-http"), badGcloud},
		{"a hidden global flag", gcloud("--credential-file-override=f"), badGcloud},
		{"the short flag of quiet", gcloud("-q"), badGcloud},
		{"a flag nobody has listed", gcloud("--some-future-flag=1"), badGcloud},
		{"a flag in quotes", gcloud("'--account=x'"), badGcloud},
		{"a flag split by quotes", gcloud(`--acc"ount"=x`), badGcloud},
		{"a flag whose name is an action", gcloud("--{{ .project }}=x"), badGcloud},
		{"a value that starts with a dash is a flag too", gcloud("--filter -x"), badGcloud},
		{"the end of options marker", gcloud("--"), badGcloud},
		{"two flags are two findings", gcloud("--account=x --log-http"), append(badGcloud, badGcloud...)},
		{"one flag twice is one finding", gcloud("--account=x --account=y"), badGcloud},
		{"a value is not looked at", gcloud("--filter=--account"), nil},
		{"flags the positive list has", gcloud("--format=json --format json --project={{ .project }} --filter=name:x --limit 5"), nil},
		{"a positional that is an action", gcloud("{{ .project }}"), nil},
		{"a positional that starts like a flag after an action", gcloud("{{ .project }}-x"), nil},

		// kubectl
		{"server with a separate value", kubectl("-s http://x"), badKubectl},
		{"combined short flags", kubectl("-As"), badKubectl},
		{"server with a value attached", kubectl("--server=http://x"), badKubectl},
		{"the short flag of namespace", kubectl("-n x"), badKubectl},
		{"the short flag of output with the value attached", kubectl("-ojson"), badKubectl},
		{"a flag nobody has listed", kubectl("--some-future-flag"), badKubectl},
		{"two flags", kubectl("-s x --token=y"), append(badKubectl, badKubectl...)},
		{"output", kubectl("-o json"), nil},
		{"all namespaces", kubectl("--all-namespaces"), nil},
		{"a namespace from a param with a constraint", namespace, nil},
	})
}

func TestRun_KubectlStepVerbAndResource(t *testing.T) {
	bad := []string{"command-not-allowed " + kubectlWhere}
	runPolicyCases(t, []policyCase{
		{"get pods", withKubectlStep("get pods -o json"), nil},
		{"get a resource with a dot in its name", withKubectlStep("get managedcertificates.networking.gke.io -o json"), nil},
		{"the api resources", withKubectlStep("api-resources"), nil},
		{"the api resources as names", withKubectlStep("api-resources -o name"), nil},
		{"version", withKubectlStep("version"), nil},
		{"a resource in quotes", withKubectlStep(`get "po"ds -o json`), nil},
		{"new lines between the words", withKubectlStep("get\n  nodes\n  -o json"), nil},

		{"secrets are not readable", withKubectlStep("get secrets"), bad},
		{"delete", withKubectlStep("delete pods"), bad},
		{"exec", withKubectlStep("exec pods"), bad},
		{"a verb of a command that is not in the list", withKubectlStep("auth can-i get pods"), bad},
		{"a resource that is an action", withKubectlStep("get {{ .project }}"), bad},
		{"a resource that is an unknown variable", withKubectlStep("get {{ .x }}"),
			append(bad, "template-var-undeclared "+kubectlWhere)},
		{"a verb that is an action", withKubectlStep("{{ .project }} pods"), bad},
		{"a resource that holds an action", withKubectlStep("get pod{{ .project }}"), bad},
		{"no resource", withKubectlStep("get"), bad},
		{"no resource before the flags", withKubectlStep("get -o json"), bad},
		{"several resources in one word", withKubectlStep("get pods,secrets"), bad},
		{"a resource with a name", withKubectlStep("get pods/web"), bad},
		{"the verb in capitals", withKubectlStep("GET pods"), bad},
		{"nothing", withKubectlStep("  "), bad},
		{"a quote that is not closed", withKubectlStep("get 'pods"), bad},
		{"a forbidden flag does not hide the verb", withKubectlStep("delete pods --server=x"),
			[]string{"command-not-allowed " + kubectlWhere, "flag-forbidden " + kubectlWhere}},
	})

	t.Run("the message says why", func(t *testing.T) {
		for _, c := range []struct{ command, has string }{
			{"get {{ .project }}", "template action"},
			{"{{ .project }} pods", "template action"},
			{"delete pods", `"delete pods"`},
			{"get", `"get"`},
		} {
			r := baseRule()
			withKubectlStep(c.command)(r)
			if fs := lintPolicy(t, r); len(fs) != 1 || !strings.Contains(fs[0].Message, c.has) {
				t.Errorf("%q: want one message that has %s, got %+v", c.command, c.has, fs)
			}
		}
	})
}

func TestRun_APIStepHostAndMethod(t *testing.T) {
	bad := []string{"command-not-allowed " + apiWhere}
	runPolicyCases(t, []policyCase{
		{"GET on a listed host", withAPIStep("GET", "https://bigquery.googleapis.com/bigquery/v2/projects/{{ .project }}/datasets"), nil},
		{"GET with a query", withAPIStep("GET", "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer"), nil},
		{"POST with a method that only reads", withAPIStep("POST", "https://bigquery.googleapis.com/bigquery/v2/projects/{{ .project }}/datasets/d/tables/t:getIamPolicy"), nil},
		{"an action after the host", withAPIStep("GET", "https://dlp.googleapis.com/v2/projects/{{ .project }}/infoTypes?filter={{ .project }}"), nil},
		{"an action in the query right after the host", withAPIStep("GET", "https://dlp.googleapis.com?x={{ .project }}"), nil},

		{"http", withAPIStep("GET", "http://bigquery.googleapis.com/x"), bad},
		{"a scheme in capitals", withAPIStep("GET", "HTTPS://bigquery.googleapis.com/x"), bad},
		{"white space before the scheme", withAPIStep("GET", " https://bigquery.googleapis.com/x"), bad},
		{"no scheme", withAPIStep("GET", "bigquery.googleapis.com/x"), bad},
		{"an empty URL", withAPIStep("GET", ""), bad},
		{"a host that is not listed", withAPIStep("GET", "https://example.com/x"), bad},
		{"a host that only starts like a listed one", withAPIStep("GET", "https://bigquery.googleapis.com.example.com/x"), bad},
		{"an action as the host", withAPIStep("GET", "https://{{ .project }}/x"), bad},
		{"an action in the host", withAPIStep("GET", "https://bigquery.googleapis.com{{ .project }}/x"), bad},
		{"an action in the user info", withAPIStep("GET", "https://{{ .project }}@bigquery.googleapis.com/x"), bad},
		{"an action that holds a slash in the host", withAPIStep("GET", `https://bigquery.googleapis.com{{ "/" }}x`), bad},
		{"user info", withAPIStep("GET", "https://user@bigquery.googleapis.com/x"), bad},
		{"a port", withAPIStep("GET", "https://bigquery.googleapis.com:443/x"), bad},
		{"POST without a suffix", withAPIStep("POST", "https://bigquery.googleapis.com/bigquery/v2/projects/p/queries"), bad},
		{"a method that is not listed", withAPIStep("DELETE", "https://bigquery.googleapis.com/x"), bad},
		{"a method in lower case", withAPIStep("get", "https://bigquery.googleapis.com/x"), bad},
		{"an action that is not closed", withAPIStep("GET", "https://bigquery.googleapis.com/x/{{ .project"),
			append(bad, "template-parse "+apiWhere)},
	})

	t.Run("the message says what is wrong with the URL", func(t *testing.T) {
		for _, c := range []struct{ url, has string }{
			{"http://bigquery.googleapis.com/x", "https://"},
			{"https://{{ .project }}/x", "host"},
			{"https://example.com/x", "not in the allowlist"},
			{"https://bigquery.googleapis.com/x/{{ .project", "not closed"},
		} {
			r := baseRule()
			withAPIStep("GET", c.url)(r)
			fs := lintPolicy(t, r)
			if len(fs) == 0 || !strings.Contains(fs[0].Message, c.has) {
				t.Errorf("%q: want a message that has %q, got %+v", c.url, c.has, fs)
			}
		}
	})

	t.Run("a host that an action would complete is not allowed", func(t *testing.T) {
		// An action is replaced by the letter x to look up the method, so the host below, which
		// the letter completes, is listed on purpose: the host has to be text all the same.
		const doc = "rest:\n  - {host: x.example.com, methods: [GET]}\n"
		for url, want := range map[string][]string{
			"https://{{ .project }}.example.com/v1": {"command-not-allowed collect.instances.api.url"},
			"https://x.example.com/v1":              nil,
		} {
			r := baseRule()
			r.Collect = []rule.Step{{ID: "instances", API: &rule.APIStep{Method: "GET", URL: url}}}
			wantFindings(t, lintWithAllowlist(t, doc, r), want...)
		}
	})
}

func TestRun_NilAllowlistSkipsCommandChecksOnly(t *testing.T) {
	build := func() *rule.Rule {
		r := baseRule()
		r.Collect[0].Gcloud = "compute instances delete list --account=x"
		r.Collect[1].Gcloud = "compute disks list -q"
		withKubectlStep("delete pods -s x")(r)
		r.Collect = append(r.Collect,
			rule.Step{ID: "api", API: &rule.APIStep{Method: "GET", URL: "http://example.com/x"}},
			rule.Step{ID: "att", Attach: "att", Gcloud: "compute networks list --project={{ .project }} --format=json"})
		return r
	}

	wantFindings(t, lintRules(build()), "attach-without-foreach collect.att.attach")

	// With the allowlist the same rule has the command findings as well, so the run above is
	// the nil allowlist at work and not a rule that happens to be clean.
	wantFindings(t, lintPolicy(t, build()),
		"attach-without-foreach collect.att.attach",
		"command-not-allowed "+gcloudWhere,
		"flag-forbidden collect.disks.gcloud",
		"command-not-allowed "+kubectlWhere,
		"flag-forbidden "+kubectlWhere,
		"command-not-allowed collect.api.api.url")

	// The checks that do not read the allowlist are not skipped either.
	r := build()
	r.Params["p"] = []any{"a"}
	r.Collect[0].Gcloud = "compute instances list --filter={{ .params.p }}"
	wantFindings(t, lintRules(r), "attach-without-foreach collect.att.attach", "params-template-unconstrained "+gcloudWhere)
}

// attachRule returns a rule whose last step attaches its result to the elements foreach yields.
// The earlier steps are a and b.
func attachRule(foreach string) *rule.Rule {
	r := baseRule()
	r.Collect = []rule.Step{
		{ID: "a", Gcloud: "compute instances list --project={{ .project }} --format=json"},
		{ID: "b", Gcloud: "compute disks list --project={{ .project }} --format=json"},
		{ID: "c", Foreach: foreach, Attach: "c", Gcloud: "compute networks subnets describe {{ .item.name }} --project={{ .project }} --format=json"},
	}
	r.Resource.From = "data.a"
	return r
}

func TestRun_AttachSourceAllowsFilterFlattenAndConcat(t *testing.T) {
	for _, expr := range []string{
		"data.a.filter(i, i.ok)",
		"data.a.flatten()",
		"data.a + data.b",
		"[data.a[0]] + data.b",
		"data.a.filter(i, i.n in [1, 2])",
		"data.a",
		"data.a.filter(i, i.ok).filter(j, j.n > 1)",
		"data.a.filter(i, i.x.exists(j, j == 1))",
		"data.a.flatten().filter(i, has(i.n))",
		`data.a.filter(i, i.s == "x.map(y)")`,
	} {
		t.Run(expr, func(t *testing.T) {
			wantFindings(t, lintPolicy(t, attachRule(expr)))
		})
	}
}

func TestRun_AttachSourceRejectsConstruction(t *testing.T) {
	const bad = "attach-source collect.c.foreach"
	for _, c := range []struct{ name, expr string }{
		{"map with a map literal", `data.a.map(i, {"n": i.n})`},
		{"spaces around the dot and the paren", `data.a. map (i, {"n": i.n})`},
		{"a new line before map", "data.a\n  .map(i, {\"n\": i.n})"},
		{"map that returns the element", `data.a.map(i, i)`},
		{"map with a filter argument", `data.a.map(i, i.ok, i)`},
		{"a map literal at the top", `{"k": data.a}["k"]`},
		{"a map in the condition of a filter", `data.a.filter(i, i.k.map(j, j) != [])`},
		{"a map literal in the condition of a filter", `data.a.filter(i, i.n in {"a": 1})`},
		{"a map literal inside a bind", `cel.bind(x, {"k": data.a}, x.k)`},
		{"a map after a flatten", `data.a.flatten().map(i, i)`},
		{"an optional map entry", `{?"k": data.a.?x}.k`},
	} {
		t.Run(c.name, func(t *testing.T) {
			wantFindings(t, lintPolicy(t, attachRule(c.expr)), bad)
		})
	}

	t.Run("a macro and a literal in one expression are one finding", func(t *testing.T) {
		wantFindings(t, lintPolicy(t, attachRule(`data.a.map(i, {"n": i.n})`)), bad)
	})

	t.Run("the message names the attach field", func(t *testing.T) {
		fs := lintPolicy(t, attachRule(`data.a.map(i, i)`))
		if len(fs) != 1 || !strings.Contains(fs[0].Message, `"c"`) {
			t.Errorf("want a message that names the attach field, got %+v", fs)
		}
	})

	t.Run("a step that does not attach may build objects", func(t *testing.T) {
		r := attachRule(`data.a.map(i, {"n": i.n})`)
		r.Collect[2].Attach = ""
		wantFindings(t, lintPolicy(t, r))
	})

	t.Run("an attach without foreach has no source to check", func(t *testing.T) {
		r := attachRule("data.a")
		r.Collect[2].Foreach = ""
		r.Collect[2].Gcloud = "compute networks list --project={{ .project }} --format=json"
		wantFindings(t, lintPolicy(t, r), "attach-without-foreach collect.c.attach")
	})

	t.Run("a source that does not compile is left to cel-compile", func(t *testing.T) {
		wantFindings(t, lintPolicy(t, attachRule(`data.a.map(i, {"n": `)), "cel-compile collect.c.foreach")
	})
}

func TestRun_TemplateParamScalarWithConstraintIsClean(t *testing.T) {
	const uses = "compute instances list --project={{ .project }} --filter=name={{ .params.p }} --format=json"
	for _, c := range []struct {
		name string
		def  any
		c    rule.ParamConstraint
	}{
		{"an integer with both bounds", 3, rule.ParamConstraint{Minimum: ptr(0.0), Maximum: ptr(10.0)}},
		{"a string with a pattern", "abc", rule.ParamConstraint{Pattern: "[a-z]+"}},
		{"a minimum alone", 5, rule.ParamConstraint{Minimum: ptr(1.0)}},
		{"a maximum alone", 5, rule.ParamConstraint{Maximum: ptr(9.0)}},
		{"an enum alone", "b", rule.ParamConstraint{Enum: []any{"a", "b"}}},
		{"a max_length alone", "abc", rule.ParamConstraint{MaxLength: ptr(8)}},
		{"a float", 2.5, rule.ParamConstraint{Minimum: ptr(1.0), Maximum: ptr(3.0)}},
		{"a boolean", true, rule.ParamConstraint{Enum: []any{true}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := baseRule()
			together(withParam("p", c.def, &c.c), withGcloud(uses))(r)
			wantFindings(t, lintPolicy(t, r))
		})
	}

	t.Run("in a kubectl command and in a URL", func(t *testing.T) {
		r := baseRule()
		together(
			withParam("p", "kube-system", &rule.ParamConstraint{Pattern: "[a-z0-9-]+"}),
			withKubectlStep("get pods --namespace={{ .params.p }}"),
			withAPIStep("GET", "https://bigquery.googleapis.com/bigquery/v2/projects/{{ .project }}/datasets?filter={{ .params.p }}"),
		)(r)
		r.Collect[3].ID = "extra_url"
		wantFindings(t, lintPolicy(t, r))
	})
}

func TestRun_TemplateParamNeedsConstraint(t *testing.T) {
	const uses = "compute instances list --project={{ .project }} --filter=name={{ .params.p }} --format=json"
	bad := []string{"params-template-unconstrained " + gcloudWhere}
	str := func(s string) *rule.ParamConstraint { return &rule.ParamConstraint{Pattern: s} }

	runPolicyCases(t, []policyCase{
		{"no constraint entry", together(withParam("p", "x", nil), withGcloud(uses)), bad},
		{"an empty entry", together(withParam("p", "x", &rule.ParamConstraint{}), withGcloud(uses)), bad},
		{"an empty enum is no constraint", together(withParam("p", "x", &rule.ParamConstraint{Enum: []any{}}), withGcloud(uses)), bad},
		{"an empty pattern is no constraint", together(withParam("p", "x", str("")), withGcloud(uses)), bad},
		{"a list default", together(withParam("p", []any{"a"}, nil), withGcloud(uses)), bad},
		{"a list default with a constraint is also a violation of it",
			together(withParam("p", []any{"a"}, &rule.ParamConstraint{MaxLength: ptr(5)}), withGcloud(uses)),
			append(bad, "params-default-violates-constraint params_constraints.p")},
		{"a map default", together(withParam("p", map[string]any{"k": "v"}, nil), withGcloud(uses)), bad},
		{"a null default", together(withParam("p", nil, nil), withGcloud(uses)), bad},
		{"the whole of params", withGcloud("compute instances list --filter={{ .params }}"), bad},
		{"the whole of params through index", withGcloud(`compute instances list --filter={{ index .params "limit" }}`), bad},
		{"a param without a constraint among others", together(withParam("p", "x", str("x")), withGcloud(
			"compute instances list --filter={{ .params.p }} --limit={{ .params.limit }}")), bad},
		{"a field of a param", together(withParam("p", map[string]any{"k": "v"}, nil), withGcloud(
			"compute instances list --filter={{ .params.p.k }}")), bad},
		{"through parentheses", together(withParam("p", "x", nil), withGcloud("compute instances list --filter={{ (.params).p }}")), bad},
		{"from the root variable", together(withParam("p", "x", nil), withGcloud("compute instances list --filter={{ $.params.p }}")), bad},
		{"in a URL", together(withParam("p", "x", nil),
			withAPIStep("GET", "https://bigquery.googleapis.com/bigquery/v2/projects/{{ .project }}/datasets?filter={{ .params.p }}")),
			[]string{"params-template-unconstrained " + apiWhere}},
		{"in a kubectl command", together(withParam("p", "x", nil), withKubectlStep("get pods --namespace={{ .params.p }}")),
			[]string{"params-template-unconstrained " + kubectlWhere}},
		{"in two commands", together(withParam("p", "x", nil), withGcloud(uses), withKubectlStep("get pods --namespace={{ .params.p }}")),
			append(bad, "params-template-unconstrained "+kubectlWhere)},
		{"twice in one command is one finding", together(withParam("p", "x", nil), withGcloud(
			"compute instances list --filter={{ .params.p }} --limit={{ .params.p }}")), bad},
		{"two params in one command are two findings", together(withParam("p", "x", nil), withParam("q", "y", nil), withGcloud(
			"compute instances list --filter={{ .params.p }} --limit={{ .params.q }}")), append(bad, bad...)},

		{"only in the message", together(withParam("p", "x", nil), withMessage("{{ .params.p }}")), nil},
		{"only in the review message", together(withParam("p", "x", nil), func(r *rule.Rule) { r.Check.ReviewMessage = "{{ .params.p }}" }), nil},
		{"only in an expression", together(withParam("p", "x", nil), withAssert(`r.name == params.p`)), nil},
		{"a param that is not defined is left to params-ref-undefined", withGcloud(uses),
			[]string{"params-ref-undefined " + gcloudWhere}},
		{"a template that does not parse is left to template-parse", together(withParam("p", "x", nil), withGcloud(
			"compute instances list --filter={{ .params.p")),
			[]string{"template-parse " + gcloudWhere, "command-not-allowed " + gcloudWhere}},
	})

	t.Run("the message says what is missing", func(t *testing.T) {
		r := baseRule()
		together(withParam("p", []any{"a"}, nil), withGcloud(uses))(r)
		fs := lintPolicy(t, r)
		if len(fs) != 1 || !strings.Contains(fs[0].Message, "scalar") || !strings.Contains(fs[0].Message, "params_constraints") ||
			!strings.Contains(fs[0].Message, "params.p") {
			t.Errorf("want one message about the param, the scalar and params_constraints, got %+v", fs)
		}
		r = baseRule()
		withGcloud("compute instances list --filter={{ .params }}")(r)
		if fs := lintPolicy(t, r); len(fs) != 1 || !strings.Contains(fs[0].Message, "whole") {
			t.Errorf("want one message about the whole of params, got %+v", fs)
		}
	})
}

func TestRun_ParamsConstraintSemantics(t *testing.T) {
	const violated = "params-default-violates-constraint params_constraints.p"
	cases := []struct {
		name string
		def  any
		c    rule.ParamConstraint
		want []string
		msg  string // a text the message of the single finding has
	}{
		// pattern: the whole value must match
		{"pattern matches the whole value", "a", rule.ParamConstraint{Pattern: "a"}, nil, ""},
		{"pattern must match all of the value", "ab", rule.ParamConstraint{Pattern: "a"}, []string{violated}, "pattern"},
		{"pattern with a wildcard", "ab", rule.ParamConstraint{Pattern: "a.*"}, nil, ""},
		{"pattern must match from the start", "xab", rule.ParamConstraint{Pattern: "ab"}, []string{violated}, "pattern"},
		{"an alternation is one group", "b", rule.ParamConstraint{Pattern: "a|b"}, nil, ""},
		{"an alternation does not match a longer value", "ab", rule.ParamConstraint{Pattern: "a|b"}, []string{violated}, "pattern"},
		{"a trailing new line is not matched by the end", "a\n", rule.ParamConstraint{Pattern: "a"}, []string{violated}, "pattern"},
		{"a pattern with a character class", "kube-system", rule.ParamConstraint{Pattern: "[a-z0-9-]+"}, nil, ""},
		{"a pattern that does not compile", "a", rule.ParamConstraint{Pattern: "("}, []string{violated}, "not a valid"},
		{"a pattern that only compiles inside the wrapper", "b", rule.ParamConstraint{Pattern: "a)|(b"}, []string{violated}, "not a valid"},
		{"a pattern RE2 does not have", "a", rule.ParamConstraint{Pattern: `(?=a)a`}, []string{violated}, "not a valid"},
		{"a pattern and a default that is a number", 5, rule.ParamConstraint{Pattern: "[0-9]+"}, []string{violated}, "string"},
		{"a pattern and a default that is a boolean", true, rule.ParamConstraint{Pattern: "true"}, []string{violated}, "string"},

		// minimum and maximum: a closed range of numbers
		{"the minimum itself", 1, rule.ParamConstraint{Minimum: ptr(1.0)}, nil, ""},
		{"the maximum itself", 10, rule.ParamConstraint{Maximum: ptr(10.0)}, nil, ""},
		{"below the minimum", 0, rule.ParamConstraint{Minimum: ptr(1.0)}, []string{violated}, "minimum"},
		{"above the maximum", 11, rule.ParamConstraint{Maximum: ptr(10.0)}, []string{violated}, "maximum"},
		{"inside a range", 5, rule.ParamConstraint{Minimum: ptr(1.0), Maximum: ptr(10.0)}, nil, ""},
		{"a float inside a range", 2.5, rule.ParamConstraint{Minimum: ptr(1.0), Maximum: ptr(3.0)}, nil, ""},
		{"a float above a range", 3.5, rule.ParamConstraint{Minimum: ptr(1.0), Maximum: ptr(3.0)}, []string{violated}, "maximum"},
		{"a negative range", -5, rule.ParamConstraint{Minimum: ptr(-10.0), Maximum: ptr(-1.0)}, nil, ""},
		{"another integer type", int64(5), rule.ParamConstraint{Minimum: ptr(1.0)}, nil, ""},
		{"an unsigned integer", uint64(5), rule.ParamConstraint{Maximum: ptr(4.0)}, []string{violated}, "maximum"},
		{"a value that is not a number", math.NaN(), rule.ParamConstraint{Minimum: ptr(0.0), Maximum: ptr(10.0)}, []string{violated}, "minimum"},
		{"a string under a minimum", "5", rule.ParamConstraint{Minimum: ptr(1.0)}, []string{violated}, "number"},
		{"a boolean under a maximum", true, rule.ParamConstraint{Maximum: ptr(10.0)}, []string{violated}, "number"},

		// enum: equality, where 1 and 1.0 are the same number
		{"a value in the enum", "b", rule.ParamConstraint{Enum: []any{"a", "b"}}, nil, ""},
		{"a value that is not in the enum", "c", rule.ParamConstraint{Enum: []any{"a", "b"}}, []string{violated}, "enum"},
		{"an integer in an enum of floats", 1, rule.ParamConstraint{Enum: []any{1.0, 2.0}}, nil, ""},
		{"a float in an enum of integers", 1.0, rule.ParamConstraint{Enum: []any{1, 2}}, nil, ""},
		{"a number that is not in the enum", 3, rule.ParamConstraint{Enum: []any{1, 2}}, []string{violated}, "enum"},
		{"a string is not a number", "1", rule.ParamConstraint{Enum: []any{1}}, []string{violated}, "enum"},
		{"a number is not a string", 1, rule.ParamConstraint{Enum: []any{"1"}}, []string{violated}, "enum"},
		{"a boolean in the enum", true, rule.ParamConstraint{Enum: []any{true}}, nil, ""},
		{"a boolean that is not in the enum", false, rule.ParamConstraint{Enum: []any{true}}, []string{violated}, "enum"},
		{"an enum of lists holds no scalar", "a", rule.ParamConstraint{Enum: []any{[]any{"a"}}}, []string{violated}, "enum"},

		// max_length: characters, not bytes
		{"as long as the limit in characters", "\u00e9\u00e9\u00e9", rule.ParamConstraint{MaxLength: ptr(3)}, nil, ""},
		{"longer than the limit in characters", "\u00e9\u00e9\u00e9", rule.ParamConstraint{MaxLength: ptr(2)}, []string{violated}, "max_length"},
		{"an empty string", "", rule.ParamConstraint{MaxLength: ptr(1)}, nil, ""},
		{"a limit on a number", 12, rule.ParamConstraint{MaxLength: ptr(5)}, []string{violated}, "string"},

		// a constraint on something that is not a scalar
		{"a list under a constraint", []any{"a"}, rule.ParamConstraint{MaxLength: ptr(5)}, []string{violated}, "scalar"},
		{"a map under a constraint", map[string]any{"k": "v"}, rule.ParamConstraint{Pattern: ".*"}, []string{violated}, "scalar"},
		{"null under a constraint", nil, rule.ParamConstraint{Enum: []any{"a"}}, []string{violated}, "scalar"},
		{"an empty entry constrains nothing", []any{"a"}, rule.ParamConstraint{}, nil, ""},

		// several limits
		{"every limit kept", "ab", rule.ParamConstraint{Pattern: "a.*", MaxLength: ptr(3), Enum: []any{"ab", "ac"}}, nil, ""},
		{"two limits broken are one finding", "abc", rule.ParamConstraint{Pattern: "a", MaxLength: ptr(2)}, []string{violated}, "max_length"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := baseRule()
			withParam("p", c.def, &c.c)(r)
			fs := lintPolicy(t, r)
			wantFindings(t, fs, c.want...)
			if c.msg != "" && len(fs) == 1 && !strings.Contains(fs[0].Message, c.msg) {
				t.Errorf("message %q does not mention %q", fs[0].Message, c.msg)
			}
		})
	}

	t.Run("two limits broken say both", func(t *testing.T) {
		r := baseRule()
		withParam("p", "abc", &rule.ParamConstraint{Pattern: "a", MaxLength: ptr(2)})(r)
		if fs := lintPolicy(t, r); len(fs) != 1 || !strings.Contains(fs[0].Message, "pattern") || !strings.Contains(fs[0].Message, "max_length") {
			t.Errorf("want one message about both limits, got %+v", fs)
		}
	})

	t.Run("a constraint for a param the rule does not have", func(t *testing.T) {
		r := baseRule()
		r.ParamsConstraints = map[string]rule.ParamConstraint{"nope": {MaxLength: ptr(3)}}
		wantFindings(t, lintPolicy(t, r), "params-constraint-unknown params_constraints.nope")
	})

	t.Run("an unknown constraint and a broken default are two findings", func(t *testing.T) {
		r := baseRule()
		r.ParamsConstraints = map[string]rule.ParamConstraint{"nope": {MaxLength: ptr(3)}, "limit": {Maximum: ptr(2.0)}}
		wantFindings(t, lintPolicy(t, r),
			"params-constraint-unknown params_constraints.nope", "params-default-violates-constraint params_constraints.limit")
	})

	t.Run("a rule without params has no param for a constraint", func(t *testing.T) {
		r := baseRule()
		r.Params = nil
		r.Check.Assert, r.Check.Message = "true", "x"
		r.ParamsConstraints = map[string]rule.ParamConstraint{"p": {MaxLength: ptr(3)}}
		wantFindings(t, lintPolicy(t, r), "params-constraint-unknown params_constraints.p")
	})
}

func TestRun_PolicyMessagesAreOneLineAndClipped(t *testing.T) {
	long := strings.Repeat("\u00e9", 200)
	fromBase := func(edit func(*rule.Rule)) func() *rule.Rule {
		return func() *rule.Rule {
			r := baseRule()
			edit(r)
			return r
		}
	}
	cases := []struct {
		name  string
		build func() *rule.Rule
		code  string
	}{
		{"a long flag name", fromBase(withGcloud("compute instances list --" + long + "=1")), "flag-forbidden"},
		{"an escape character in a flag name", fromBase(withGcloud("compute instances list --a\x1b[31mb")), "flag-forbidden"},
		{"a flag name with a new line in quotes", fromBase(withGcloud("compute instances list '--a\nb'")), "flag-forbidden"},
		{"a long word of the path", fromBase(withGcloud("compute " + long + " list")), "command-not-allowed"},
		{"a new line inside quotes in the path", fromBase(withGcloud("compute 'inst\nances' list")), "command-not-allowed"},
		{"an escape character in the path", fromBase(withGcloud("compute inst\x1bances list")), "command-not-allowed"},
		{"a long command of many words", fromBase(withGcloud(strings.Repeat(long+" ", 10))), "command-not-allowed"},
		{"a long kubectl verb", fromBase(withKubectlStep(long + " pods")), "command-not-allowed"},
		{"a long kubectl resource", fromBase(withKubectlStep("get " + long)), "command-not-allowed"},
		{"a long kubectl flag", fromBase(withKubectlStep("get pods --" + long)), "flag-forbidden"},
		{"a long REST host", fromBase(withAPIStep("GET", "https://"+long+".example/x")), "command-not-allowed"},
		{"a long REST scheme", fromBase(withAPIStep("GET", long+"://x")), "command-not-allowed"},
		{"a long REST method", fromBase(withAPIStep(long, "https://bigquery.googleapis.com/x")), "command-not-allowed"},
		{"a long evaluate_per", fromBase(func(r *rule.Rule) { r.Scope, r.EvaluatePer = "organization", long }), "evaluate-per"},
		{"a long scope with evaluate_per", fromBase(func(r *rule.Rule) { r.Scope, r.EvaluatePer = long, "project" }), "evaluate-per"},
		{"a long param name in a command", fromBase(together(withParam(long, "x", nil),
			withGcloud("compute instances list --filter={{ .params."+long+" }}"))), "params-template-unconstrained"},
		{"a long name of a constraint", fromBase(func(r *rule.Rule) {
			r.ParamsConstraints = map[string]rule.ParamConstraint{long: {MaxLength: ptr(3)}}
		}), "params-constraint-unknown"},
		{"a pattern that does not compile", fromBase(withParam("p", "x", &rule.ParamConstraint{Pattern: "(" + long})),
			"params-default-violates-constraint"},
		{"a long attach field that builds objects", func() *rule.Rule {
			r := attachRule("data.a.map(i, i)")
			r.Collect[2].Attach = long
			return r
		}, "attach-source"},
		{"a long attach field without foreach", func() *rule.Rule {
			r := attachRule("")
			r.Collect[2].Attach, r.Collect[2].Gcloud = long, "compute networks list --project={{ .project }} --format=json"
			return r
		}, "attach-without-foreach"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var found bool
			for _, f := range lintPolicy(t, c.build()) {
				found = found || f.Code == c.code
				wantCleanText(t, f)
			}
			if !found {
				t.Errorf("want a %s finding", c.code)
			}
		})
	}

	// Text that is not a template, at every place a template can be, goes through all of the
	// checks: none may panic, and what they say about it is clean as well.
	malformed := []string{
		"{{ .project", "{{ range }}", "{{ end }}", "{{ if .params.limit }}x", "{{ nosuchfunction .project }}", `{{ "unterminated }}`,
		"{{ | .a }}", "{{ template }}", "{{ $x }}", "{{", "}}", "'", `"`, "\x00", "\xff\xfe", "{{/* c */}}", "{{ define \"x\" }}{{ end }}",
		"{{" + strings.Repeat("(", 10000) + ".a" + strings.Repeat(")", 10000) + "}}",
		strings.Repeat("{{ if .params.limit }}", 2000),
	}
	for _, site := range templateSites {
		for _, text := range malformed {
			t.Run(fmt.Sprintf("%s/%.20q", site.where, text), func(t *testing.T) {
				for _, per := range []string{"", "organization"} {
					r := baseRule()
					site.set(r, text)
					if per != "" {
						r.Scope, r.EvaluatePer = "organization", per
					}
					for _, f := range lintPolicy(t, r) {
						wantCleanText(t, f)
					}
				}
			})
		}
	}
}

// wantCleanText fails the test unless the message and the location of f are made of clean text:
// valid UTF-8 without U+FFFD or control characters, at most 120 quoted characters (the tests here
// quote only the letter e with an acute accent), and of a bounded length.
func wantCleanText(t *testing.T, f lint.Finding) {
	t.Helper()
	for name, text := range map[string]string{"message": f.Message, "location": f.Where} {
		switch {
		case !utf8.ValidString(text):
			t.Errorf("%s of %s is not UTF-8: %q", name, f.Code, text)
		case strings.ContainsRune(text, utf8.RuneError):
			t.Errorf("%s of %s has U+FFFD: %q", name, f.Code, text)
		case strings.IndexFunc(text, unicode.IsControl) >= 0:
			t.Errorf("%s of %s has a control character: %q", name, f.Code, text)
		case strings.Count(text, "\u00e9") > 120:
			t.Errorf("%s of %s quotes %d characters, at most 120 are allowed", name, f.Code, strings.Count(text, "\u00e9"))
		case utf8.RuneCountInString(text) > 400:
			t.Errorf("%s of %s is %d characters long", name, f.Code, utf8.RuneCountInString(text))
		}
	}
}
