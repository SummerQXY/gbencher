// Package lint reads rule files without running them and reports what is wrong with them:
// schema violations, rule and step ids that are used twice, expressions that do not compile,
// references to steps, params and context fields that do not exist, templates that do not parse
// or that use variables that are not there, and what a rule may not do: run a command that is not
// on the allowlist, set a flag the engine controls, read a value that has none in the way the rule
// is evaluated, or build the objects of a step that attaches its result.
//
// Every finding has a code:
//
//	schema                              the file or a rule breaks the rule schema (reported by the loader)
//	rule-id-duplicate                   a rule id is used more than once, in one file or across files
//	step-id-duplicate                   a step id is used more than once in a rule
//	cel-compile                         an expression does not parse or does not type-check
//	data-ref-unknown                    data.<id> names no step of the rule
//	data-ref-forward                    data.<id> names a step that does not run before the expression
//	params-ref-undefined                params.<name> names a param the rule does not define
//	ctx-ref-unknown                     ctx.<name> names a field ctx does not have
//	template-parse                      a template does not parse
//	template-var-undeclared             a template uses a variable that is not available to it
//	r-unavailable                       r is used where the rule has no resource to evaluate
//	command-not-allowed                 a gcloud, kubectl or REST step is not on the allowlist
//	flag-forbidden                      a gcloud or kubectl step has a flag a rule may not set
//	evaluate-per                        evaluate_per is missing, has no valid value, or is set on a rule that is not an organization rule
//	evaluate-per-mismatch               a rule evaluated once per organization reads the project or the folder
//	attach-without-foreach              a step attaches its result and has no foreach
//	attach-source                       the foreach of a step that attaches builds new objects
//	params-template-unconstrained       a param written into a command is not a scalar or has no constraint
//	params-default-violates-constraint  the default of a param breaks its constraint
//	params-constraint-unknown           params_constraints names a param the rule does not define
//	no-rule-files                       there was nothing to check
//	verification-stale                  the stored verification map differs from computed levels
//
// References are found in the syntax tree of an expression or template, never by matching text,
// so a string that happens to contain data.x is not a reference to data.
package lint

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"cel.dev/cel-go/cel"

	"github.com/SummerQXY/gbencher/internal/celenv"
	"github.com/SummerQXY/gbencher/internal/rule"
)

const (
	codeSchema                = "schema"
	codeRuleIDDuplicate       = "rule-id-duplicate"
	codeStepIDDuplicate       = "step-id-duplicate"
	codeCELCompile            = "cel-compile"
	codeDataRefUnknown        = "data-ref-unknown"
	codeDataRefForward        = "data-ref-forward"
	codeParamsRefUndefined    = "params-ref-undefined"
	codeCtxRefUnknown         = "ctx-ref-unknown"
	codeTemplateParse         = "template-parse"
	codeTemplateVarUndeclared = "template-var-undeclared"
	codeRUnavailable          = "r-unavailable"
	codeNoRuleFiles           = "no-rule-files"

	codeCommandNotAllowed               = "command-not-allowed"
	codeFlagForbidden                   = "flag-forbidden"
	codeEvaluatePer                     = "evaluate-per"
	codeEvaluatePerMismatch             = "evaluate-per-mismatch"
	codeAttachWithoutForeach            = "attach-without-foreach"
	codeAttachSource                    = "attach-source"
	codeParamsTemplateUnconstrained     = "params-template-unconstrained"
	codeParamsDefaultViolatesConstraint = "params-default-violates-constraint"
	codeParamsConstraintUnknown         = "params-constraint-unknown"
)

// maxQuoted is the most characters of a name, expression or template that a message repeats.
const maxQuoted = 120

// Finding is one problem found in a rule file.
type Finding struct {
	// File is the rule file, as the loader names it. It is empty for no-rule-files.
	File string
	// RuleID is empty when the problem is about the file as a whole.
	RuleID string
	// Where says where in the rule or file the problem is: collect.<step>.gcloud, check.assert,
	// evidence[2], resource.from, or the JSON Pointer of a schema violation.
	Where string
	// Code is one of the codes listed in the package comment.
	Code string
	// Message is a single line of text for a person.
	Message string
}

// Options configures Run.
type Options struct {
	// Allow is the allowlist the checks of gcloud, kubectl and REST steps read. When it is nil
	// those checks are skipped and every other check still runs; the command line always passes
	// the allowlist that is built into the program.
	Allow *rule.Allowlist
}

// ruleCheck inspects one rule of a file and reports what is wrong with it.
type ruleCheck func(f *rule.File, r *rule.Rule) []Finding

// ruleChecks returns the checks Run applies to every rule. A new check is registered by
// appending it to the list. When the CEL environment cannot be built, the list holds only the
// checks that do not need it and the error says why the others are missing.
func ruleChecks(opts Options) ([]ruleCheck, error) {
	checks := []ruleCheck{
		checkStepIDs,
		checkTemplates,
		checkEvaluatePer,
		checkAttachWithoutForeach,
		checkParamsConstraints,
		checkTemplateParams,
	}
	if allow := opts.Allow; allow != nil {
		checks = append(checks, checkGcloudSteps(allow), checkKubectlSteps(allow), checkAPISteps(allow))
	}

	env, err := celenv.New(true)
	if err != nil {
		return checks, err
	}
	checks = append(checks, checkExpressions(env), checkEvaluatePerMismatch(env))

	// Only this check needs the parser to keep the macro calls it expands, so the extra option
	// stays out of the environment the other checks use.
	tracking, err := env.Extend(cel.EnableMacroCallTracking())
	if err != nil {
		return checks, err
	}
	return append(checks, checkAttachSource(tracking)), nil
}

// Run lints rule files and returns what it found, sorted by file, rule id, code, location and
// message. files and violations are what rule.LoadFiles or rule.ParseFile return; each
// violation becomes a schema finding.
//
// A scan with nothing to check must not look like a scan that passed, so when there are no
// files and no violations the only finding is no-rule-files.
func Run(files []*rule.File, violations []rule.Violation, opts Options) []Finding {
	files = slices.DeleteFunc(slices.Clone(files), func(f *rule.File) bool { return f == nil })
	if len(files) == 0 && len(violations) == 0 {
		return []Finding{{Code: codeNoRuleFiles, Message: "no rule files were found"}}
	}

	out := schemaFindings(files, violations)
	out = append(out, ruleIDFindings(files)...)

	checks, err := ruleChecks(opts)
	if err != nil {
		// The environment is fixed, so this is a defect of the program and not of any rule.
		// Say so instead of leaving the expressions unchecked without a word.
		out = append(out, Finding{Code: codeCELCompile, Message: "cannot create the CEL environment: " + oneLine(err.Error())})
	}
	for _, f := range files {
		for _, r := range f.Rules {
			if r == nil {
				continue
			}
			for _, check := range checks {
				out = append(out, check(f, r)...)
			}
		}
	}

	slices.SortStableFunc(out, compareFindings)
	return out
}

// FormatText renders findings one per line as "<file>: <rule-id>: <where>: <code>: <message>",
// sorted the way Run sorts them, each line ending in a newline. It is empty for no findings. A
// field that is empty stays empty, so every line has the same five columns.
func FormatText(fs []Finding) string {
	sorted := slices.Clone(fs)
	slices.SortStableFunc(sorted, compareFindings)

	var b strings.Builder
	for _, f := range sorted {
		fmt.Fprintf(&b, "%s: %s: %s: %s: %s\n", oneLine(f.File), oneLine(f.RuleID), oneLine(f.Where), oneLine(f.Code), oneLine(f.Message))
	}
	return b.String()
}

func compareFindings(a, b Finding) int {
	return cmp.Or(
		cmp.Compare(a.File, b.File),
		cmp.Compare(a.RuleID, b.RuleID),
		cmp.Compare(a.Code, b.Code),
		cmp.Compare(a.Where, b.Where),
		cmp.Compare(a.Message, b.Message),
	)
}

// newFinding makes a finding about rule r of file f. Where and message are made single-line;
// callers cut the pieces of rule text they put in the message with clip or quote.
func newFinding(f *rule.File, r *rule.Rule, where, code, message string) Finding {
	return Finding{File: f.Name, RuleID: r.ID, Where: oneLine(where), Code: code, Message: oneLine(message)}
}

// oneLine turns s into a single line: every run of white space and control characters becomes
// one space. Error text from the CEL parser and the template parser spans several lines, and
// some of it quotes the expression.
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// clip cuts s to maxQuoted characters, marking the cut.
func clip(s string) string {
	n := 0
	for i := range s {
		if n == maxQuoted {
			return s[:i] + "..."
		}
		n++
	}
	return s
}

// quote returns s clipped and in double quotes, with anything unprintable escaped.
func quote(s string) string { return strconv.Quote(clip(s)) }

// stepWhere names the collect step at index i by its id, or by its position when it has none.
func stepWhere(i int, s rule.Step) string {
	if s.ID == "" {
		return fmt.Sprintf("collect[%d]", i)
	}
	return "collect." + clip(s.ID)
}

// schemaFindings turns the violations the loader found into findings. The rule id is a best
// effort: a path of the form /rules/<i>/... names the rule the loader decoded at index i. A
// rules entry that is not a mapping is not decoded, so after one the ids can be a neighbour's;
// the file already has a violation for such an entry.
func schemaFindings(files []*rule.File, violations []rule.Violation) []Finding {
	byName := make(map[string]*rule.File, len(files))
	for _, f := range files {
		byName[f.Name] = f
	}
	out := make([]Finding, 0, len(violations))
	for _, v := range violations {
		out = append(out, Finding{
			File:    v.File,
			RuleID:  ruleIDAt(byName[v.File], v.Path),
			Where:   oneLine(v.Path),
			Code:    codeSchema,
			Message: oneLine(v.Message),
		})
	}
	return out
}

// ruleIDAt returns the id of the rule a JSON Pointer into file f points into, or "" when it
// points elsewhere or the rule was not decoded.
func ruleIDAt(f *rule.File, path string) string {
	rest, ok := strings.CutPrefix(path, "/rules/")
	if !ok || f == nil {
		return ""
	}
	index, _, _ := strings.Cut(rest, "/")
	i, err := strconv.Atoi(index)
	if err != nil || i < 0 || i >= len(f.Rules) || f.Rules[i] == nil {
		return ""
	}
	return f.Rules[i].ID
}

// ruleIDFindings reports every rule id that was already defined: in another file or earlier in
// the same one. The definition that comes first, in file name order and then in rule order, is
// the one the others repeat, so a pair is reported once, on the later file, and the result does
// not depend on the order of files.
func ruleIDFindings(files []*rule.File) []Finding {
	ordered := slices.Clone(files)
	slices.SortStableFunc(ordered, func(a, b *rule.File) int { return strings.Compare(a.Name, b.Name) })

	firstFile := make(map[string]string)
	var out []Finding
	for _, f := range ordered {
		for _, r := range f.Rules {
			if r == nil || r.ID == "" {
				continue // a missing id is a schema violation
			}
			first, seen := firstFile[r.ID]
			if !seen {
				firstFile[r.ID] = f.Name
				continue
			}
			out = append(out, newFinding(f, r, "id", codeRuleIDDuplicate, duplicateIDMessage(r.ID, first, f.Name)))
		}
	}
	return out
}

func duplicateIDMessage(id, firstFile, file string) string {
	if firstFile == file {
		return fmt.Sprintf("rule id %s is defined more than once in %s", quote(id), clip(file))
	}
	return fmt.Sprintf("rule id %s is defined in both %s and %s", quote(id), clip(firstFile), clip(file))
}

// checkStepIDs reports each step whose id an earlier step of the rule already has.
func checkStepIDs(f *rule.File, r *rule.Rule) []Finding {
	seen := make(map[string]bool, len(r.Collect))
	var out []Finding
	for i, s := range r.Collect {
		if s.ID == "" {
			continue // a missing id is a schema violation
		}
		if seen[s.ID] {
			out = append(out, newFinding(f, r, stepWhere(i, s), codeStepIDDuplicate,
				fmt.Sprintf("step id %s is defined more than once in the rule", quote(s.ID))))
		}
		seen[s.ID] = true
	}
	return out
}
