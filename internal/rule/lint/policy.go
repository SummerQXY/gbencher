package lint

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"text/template"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"

	"github.com/SummerQXY/gbencher/internal/cmdline"
	"github.com/SummerQXY/gbencher/internal/rule"
)

// The checks in this file are about what a rule is allowed to do. The ones that read the
// allowlist (gcloud, kubectl and REST steps) run only when Options.Allow is set.
//
// A message repeats rule text only through quote and clip, which cut it to maxQuoted characters
// and leave no control character, because commands, names and patterns come from the rule file.

// gcloudSummaryWords is how many words of a command a message quotes.
const gcloudSummaryWords = 4

// checkGcloudSteps checks every gcloud step against the allowlist: the command must be on it, and
// the flags the rule writes must be on the positive list of flags.
func checkGcloudSteps(allow *rule.Allowlist) ruleCheck {
	return func(f *rule.File, r *rule.Rule) []Finding {
		var out []Finding
		for i, s := range r.Collect {
			if s.Gcloud != "" {
				out = append(out, lintGcloud(allow, f, r, stepWhere(i, s)+".gcloud", s.Gcloud)...)
			}
		}
		return out
	}
}

func lintGcloud(allow *rule.Allowlist, f *rule.File, r *rule.Rule, where, command string) []Finding {
	words, err := cmdline.Split(command)
	if err != nil {
		return []Finding{newFinding(f, r, where, codeCommandNotAllowed, "the command cannot be split into words: "+err.Error())}
	}
	argv := make([]string, len(words))
	for i, w := range words {
		argv[i] = w.String()
	}

	entry, _, ok := allow.MatchGcloud(argv, false)
	if !ok {
		message := "the gcloud command is empty"
		if len(argv) > 0 {
			message = fmt.Sprintf("gcloud command %s is not on the allowlist", quote(strings.Join(argv[:min(len(argv), gcloudSummaryWords)], " ")))
		}
		return []Finding{newFinding(f, r, where, codeCommandNotAllowed, message)}
	}
	return flagFindings(allow, "gcloud", f, r, where, words[len(entry.Path):])
}

// checkKubectlSteps checks every kubectl step against the allowlist: the verb and the resource
// must be on it, and the flags the rule writes must be on the positive list of flags.
func checkKubectlSteps(allow *rule.Allowlist) ruleCheck {
	return func(f *rule.File, r *rule.Rule) []Finding {
		var out []Finding
		for i, s := range r.Collect {
			if s.Kubectl != "" {
				out = append(out, lintKubectl(allow, f, r, stepWhere(i, s)+".kubectl", s.Kubectl)...)
			}
		}
		return out
	}
}

// lintKubectl reads a kubectl command as a verb, then a resource unless the next word is a flag,
// then flags. The verb and the resource are looked up by their text, so neither can be an action:
// what an action turns into is not known until the command is rendered.
func lintKubectl(allow *rule.Allowlist, f *rule.File, r *rule.Rule, where, command string) []Finding {
	words, err := cmdline.Split(command)
	if err != nil {
		return []Finding{newFinding(f, r, where, codeCommandNotAllowed, "the command cannot be split into words: "+err.Error())}
	}
	if len(words) == 0 {
		return []Finding{newFinding(f, r, where, codeCommandNotAllowed, "the kubectl command is empty")}
	}

	verb, resource := words[0], cmdline.Word{}
	if len(words) > 1 && !startsWithDash(words[1]) {
		resource = words[1]
	}
	said := quote(strings.TrimSpace(verb.String() + " " + resource.String()))

	var out []Finding
	switch {
	case hasAction(verb) || hasAction(resource):
		out = append(out, newFinding(f, r, where, codeCommandNotAllowed,
			"the verb and the resource of a kubectl command must be text, not template actions: "+said))
	case !allow.KubectlAllowed(verb.String(), resource.String()):
		out = append(out, newFinding(f, r, where, codeCommandNotAllowed, "kubectl "+said+" is not on the allowlist"))
	}
	return append(out, flagFindings(allow, "kubectl", f, r, where, words[1:])...)
}

// flagFindings reports each word of words that starts with a dash and that the flag policy of
// tool refuses, once for each flag name. The policy is a positive list: a word that starts with a
// dash is refused unless its name is on the list.
//
// A word that starts with an action is a positional argument, not a flag; what it renders to is
// checked when the command is rendered. A word that is a value is looked at too when it starts
// with a dash, as in --filter -x.
func flagFindings(allow *rule.Allowlist, tool string, f *rule.File, r *rule.Rule, where string, words []cmdline.Word) []Finding {
	var out []Finding
	seen := make(map[string]bool)
	for _, w := range words {
		text := w.String()
		if !strings.HasPrefix(text, "-") || !allow.ForbiddenFlag(tool, text) {
			continue
		}
		name, _, _ := strings.Cut(text, "=") // the value is left out of the message
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, newFinding(f, r, where, codeFlagForbidden, flagMessage(allow, tool, name)))
	}
	return out
}

func flagMessage(allow *rule.Allowlist, tool, name string) string {
	forbidden := allow.ForbiddenGcloudFlags
	if tool == "kubectl" {
		forbidden = allow.ForbiddenKubectlFlags
	}
	if slices.Contains(forbidden, name) {
		return fmt.Sprintf("flag %s is forbidden in a %s step: the engine sets the identity, the endpoint and the logging of a command", quote(name), tool)
	}
	return fmt.Sprintf("flag %s is not on the list of flags a %s step may use", quote(name), tool)
}

// startsWithDash reports whether w begins with a literal dash. An action never does: its text
// begins with "{{".
func startsWithDash(w cmdline.Word) bool { return strings.HasPrefix(w.String(), "-") }

func hasAction(w cmdline.Word) bool {
	return slices.ContainsFunc(w.Parts, func(p cmdline.Part) bool { return p.Action })
}

// checkAPISteps checks every REST step against the allowlist. The URL has to start with the text
// https:// and the host has to be text, because the token goes to whatever host the rendered URL
// names. The rest of the URL may hold actions; they are replaced by a letter, which is enough to
// find out whether the method is allowed on the host.
func checkAPISteps(allow *rule.Allowlist) ruleCheck {
	return func(f *rule.File, r *rule.Rule) []Finding {
		var out []Finding
		for i, s := range r.Collect {
			if s.API == nil {
				continue
			}
			where := stepWhere(i, s) + ".api.url"
			if problem := apiProblem(allow, s.API); problem != "" {
				out = append(out, newFinding(f, r, where, codeCommandNotAllowed, problem))
			}
		}
		return out
	}
}

// apiProblem returns what is wrong with a REST step, or an empty string.
func apiProblem(allow *rule.Allowlist, api *rule.APIStep) string {
	const scheme = "https://"
	rest, ok := strings.CutPrefix(api.URL, scheme)
	if !ok {
		return "the URL must start with the text " + scheme
	}
	host := rest
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		host = rest[:end]
	}
	if strings.Contains(host, "{{") {
		return "the host of the URL must be text, not a template action"
	}
	plain, closed := replaceActions(api.URL)
	if !closed {
		return "the URL has an action that is not closed"
	}
	if err := allow.RESTAllowed(api.Method, plain); err != nil {
		return "the REST step is not allowed: " + clip(strings.TrimPrefix(err.Error(), "rest: "))
	}
	return ""
}

// replaceActions replaces every action of a template, from "{{" to the next "}}", with the letter
// x. These are the same delimiters cmdline.Split uses. It reports false when an action is not
// closed.
func replaceActions(s string) (string, bool) {
	var b strings.Builder
	for {
		start := strings.Index(s, "{{")
		if start < 0 {
			b.WriteString(s)
			return b.String(), true
		}
		length := strings.Index(s[start+2:], "}}")
		if length < 0 {
			return "", false
		}
		b.WriteString(s[:start])
		b.WriteByte('x')
		s = s[start+2+length+2:]
	}
}

// checkEvaluatePer checks that evaluate_per is there exactly when it is needed: an organization
// rule has it, with a value that means something, and no other rule does. A rule that went
// through the schema is reported by the schema as well; this check also catches a rule that was
// built in memory, and names the rule.
func checkEvaluatePer(f *rule.File, r *rule.Rule) []Finding {
	const where = "evaluate_per"
	switch {
	case r.Scope == "organization" && r.EvaluatePer == "":
		return []Finding{newFinding(f, r, where, codeEvaluatePer, `an organization rule must set evaluate_per to "organization" or "project"`)}
	case r.Scope == "organization" && r.EvaluatePer != "organization" && r.EvaluatePer != "project":
		return []Finding{newFinding(f, r, where, codeEvaluatePer,
			fmt.Sprintf(`evaluate_per is %s, it must be "organization" or "project"`, quote(r.EvaluatePer)))}
	case r.Scope != "organization" && r.EvaluatePer != "":
		return []Finding{newFinding(f, r, where, codeEvaluatePer,
			fmt.Sprintf("evaluate_per is only for organization rules, and the scope of this rule is %s", quote(r.Scope)))}
	}
	return nil
}

// projectValues are the values that belong to one project: the fields of ctx and the variables of
// a template. A rule that is evaluated once per organization has no current project, so they are
// empty there.
var projectValues = []string{"project", "project_number", "folder"}

// checkEvaluatePerMismatch reports every place of a rule that is evaluated once per organization
// and that reads the project, the project number or the folder, with one finding for each place.
// The references are found the way the other checks find them, so a macro variable called ctx and
// a string that says ctx.project are not references.
func checkEvaluatePerMismatch(env *cel.Env) ruleCheck {
	return func(f *rule.File, r *rule.Rule) []Finding {
		if r.Scope != "organization" || r.EvaluatePer != "organization" {
			return nil
		}
		var out []Finding
		report := func(where string, names []string) {
			if len(names) > 0 {
				out = append(out, newFinding(f, r, where, codeEvaluatePerMismatch,
					strings.Join(names, ", ")+": the rule is evaluated once per organization (evaluate_per: organization), so there is no current project or folder and the value is empty"))
			}
		}

		for _, s := range exprSites(r) {
			parsed, iss := env.Parse(s.text)
			if iss != nil && iss.Err() != nil {
				continue // reported as cel-compile
			}
			var names []string
			for _, ref := range references(parsed.NativeRep().Expr()) {
				if ref.root == "ctx" && slices.Contains(projectValues, ref.field) {
					names = appendMissing(names, "ctx."+ref.field)
				}
			}
			report(s.where, names)
		}

		for _, s := range templateSites(r) {
			paths, ok := templatePaths(s.text)
			if !ok {
				continue // blank, or reported as template-parse
			}
			var names []string
			for _, path := range paths {
				if slices.Contains(projectValues, path[0]) {
					names = appendMissing(names, "."+path[0])
				}
			}
			report(s.where, names)
		}
		return out
	}
}

func appendMissing(names []string, name string) []string {
	if slices.Contains(names, name) {
		return names
	}
	return append(names, name)
}

// templatePaths returns the fields a template reads, see templateRefs. ok is false when the
// template is blank or does not parse; a template that does not parse is reported by
// checkTemplates, and there is nothing to read in a blank one.
func templatePaths(text string) (paths [][]string, ok bool) {
	if strings.TrimSpace(text) == "" {
		return nil, false
	}
	tmpl, err := template.New(templateName).Parse(text)
	if err != nil {
		return nil, false
	}
	return templateRefs(tmpl.Tree.Root), true
}

// checkAttachWithoutForeach reports each step that attaches its result and has no foreach: there
// are no elements to attach it to.
func checkAttachWithoutForeach(f *rule.File, r *rule.Rule) []Finding {
	var out []Finding
	for i, s := range r.Collect {
		if s.Attach != "" && s.Foreach == "" {
			out = append(out, newFinding(f, r, stepWhere(i, s)+".attach", codeAttachWithoutForeach,
				fmt.Sprintf("the step attaches its result as %s but has no foreach to say which elements it belongs to", quote(s.Attach))))
		}
	}
	return out
}

// checkAttachSource reports each step that attaches its result to elements that its foreach
// builds. The result is attached to the original objects of the data, so the source must not
// make new ones: a map literal and the map macro do, and filter, flatten, adding lists, indexing
// and list literals do not. The check is on purpose rougher than it could be: a map literal
// anywhere in the source counts, even in a condition where it builds nothing that is returned.
//
// env has to keep macro calls: a macro is replaced by what it expands to while the expression is
// parsed, and the call that was written is only recorded when that is on. The syntax tree makes
// the check independent of white space, new lines and strings that happen to say .map(.
func checkAttachSource(env *cel.Env) ruleCheck {
	return func(f *rule.File, r *rule.Rule) []Finding {
		var out []Finding
		for i, s := range r.Collect {
			if s.Attach == "" || strings.TrimSpace(s.Foreach) == "" {
				continue
			}
			parsed, iss := env.Parse(s.Foreach)
			if iss != nil && iss.Err() != nil {
				continue // reported as cel-compile
			}
			if buildsObjects(parsed) {
				out = append(out, newFinding(f, r, stepWhere(i, s)+".foreach", codeAttachSource,
					fmt.Sprintf("the foreach builds new objects (a map literal or the map macro), but attach %s needs the original elements: use filter, flatten, list addition or indexing instead", quote(s.Attach))))
			}
		}
		return out
	}
}

// buildsObjects reports whether the expression has a map literal or calls the map macro.
func buildsObjects(parsed *cel.Ast) bool {
	native := parsed.NativeRep()
	var literal bool
	ast.PreOrderVisit(native.Expr(), ast.NewExprVisitor(func(e ast.Expr) {
		literal = literal || e.Kind() == ast.MapKind
	}))
	if literal {
		return true
	}
	for _, call := range native.SourceInfo().MacroCalls() {
		if call.Kind() == ast.CallKind && call.AsCall().FunctionName() == "map" {
			return true
		}
	}
	return false
}

// checkTemplateParams reports each param that a command or a URL writes in and that is not limited
// enough for that: its default has to be a scalar, and params_constraints has to constrain it.
// Overrides are checked against the same constraint when a scan starts. A param the rule does not
// define is left to params-ref-undefined.
func checkTemplateParams(f *rule.File, r *rule.Rule) []Finding {
	var out []Finding
	for _, s := range templateSites(r) {
		if !s.command {
			continue
		}
		paths, ok := templatePaths(s.text)
		if !ok {
			continue
		}
		var wholeParams bool
		var named []string
		for _, path := range paths {
			switch {
			case path[0] != "params":
			case len(path) == 1:
				wholeParams = true
			default:
				named = appendMissing(named, path[1])
			}
		}

		if wholeParams {
			out = append(out, newFinding(f, r, s.where, codeParamsTemplateUnconstrained,
				"the whole of params is used in a command: use single params that are scalars with a constraint instead"))
		}
		for _, name := range named {
			if problems := paramProblems(r, name); len(problems) > 0 {
				out = append(out, newFinding(f, r, s.where, codeParamsTemplateUnconstrained,
					fmt.Sprintf("params.%s is written into a command, but %s", clip(name), strings.Join(problems, " and "))))
			}
		}
	}
	return out
}

// paramProblems says why a param cannot go into a command, one text for each reason. It is empty
// for a param that is not defined.
func paramProblems(r *rule.Rule, name string) []string {
	def, defined := r.Params[name]
	if !defined {
		return nil
	}
	var problems []string
	if !isScalar(def) {
		problems = append(problems, "its default value is not a scalar (a string, a number or a boolean)")
	}
	constraint, ok := r.ParamsConstraints[name]
	switch {
	case !ok:
		problems = append(problems, "params_constraints has no entry for it")
	case constraint.Pattern == "" && constraint.Minimum == nil && constraint.Maximum == nil && len(constraint.Enum) == 0 && constraint.MaxLength == nil:
		problems = append(problems, "its params_constraints entry sets none of pattern, minimum, maximum, enum and max_length")
	}
	return problems
}

func isScalar(v any) bool {
	if v == nil {
		return false
	}
	switch reflect.TypeOf(v).Kind() {
	case reflect.String, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	default:
		return false
	}
}

// checkParamsConstraints checks every entry of params_constraints: the param has to exist, and
// its default value has to meet the constraint, since a default that breaks it would fail every
// scan that does not override the param.
func checkParamsConstraints(f *rule.File, r *rule.Rule) []Finding {
	var out []Finding
	for _, name := range slices.Sorted(maps.Keys(r.ParamsConstraints)) {
		where := "params_constraints." + clip(name)
		def, defined := r.Params[name]
		if !defined {
			out = append(out, newFinding(f, r, where, codeParamsConstraintUnknown,
				fmt.Sprintf("params_constraints has an entry for %s, which the rule does not define as a param", quote(name))))
			continue
		}
		if err := r.ParamsConstraints[name].Check(def); err != nil {
			out = append(out, newFinding(f, r, where, codeParamsDefaultViolatesConstraint,
				"the default value breaks the constraint: "+err.Error()))
		}
	}
	return out
}
