package lint

import (
	"fmt"
	"slices"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"

	"github.com/SummerQXY/gbencher/internal/rule"
)

// noResource says why r does not exist in an aggregate rule, a rule without a resource block.
const noResource = "an aggregate rule (a rule without a resource block)"

// ctxFields returns the fields of ctx that rule expressions can read.
func ctxFields() []string {
	return []string{"account", "cluster", "folder", "now", "organization", "organization_domain", "project", "project_number"}
}

// exprSite is one CEL expression of a rule and what it can see.
type exprSite struct {
	where string // see Finding.Where
	text  string
	// steps is how many collect steps have run when the expression is evaluated: the steps
	// before its own for a foreach expression, all of them for every other one, which run after
	// the collection is complete.
	steps int
	// noR says why r is not available; it is empty when it is.
	noR string
}

// exprSites lists the expressions of r. A blank expression is left out: the schema already
// reports a field that is present and empty.
func exprSites(r *rule.Rule) []exprSite {
	var sites []exprSite
	add := func(where, text string, steps int, noR string) {
		if strings.TrimSpace(text) != "" {
			sites = append(sites, exprSite{where: where, text: text, steps: steps, noR: noR})
		}
	}

	for i, s := range r.Collect {
		add(stepWhere(i, s)+".foreach", s.Foreach, i, "foreach expressions")
	}

	all := len(r.Collect)
	noR := ""
	if r.Resource == nil {
		noR = noResource
	} else {
		res := r.Resource
		add("resource.from", res.From, all, "resource.from")
		add("resource.filter", res.Filter, all, "")
		add("resource.name", res.Name, all, "")
		add("resource.key", res.Key, all, "")
	}
	add("check.assert", r.Check.Assert, all, noR)
	add("check.review_when", r.Check.ReviewWhen, all, noR)
	for i, e := range r.Evidence {
		add(fmt.Sprintf("evidence[%d]", i), e, all, noR)
	}
	return sites
}

// checkExpressions parses and type-checks every CEL expression of a rule in env, and checks the
// data, params, ctx and r it reads.
//
// env declares r everywhere. Where r does not exist the check finds it in the syntax tree and
// reports r-unavailable once, instead of letting the type checker reject it as an undeclared
// name and the finding come out as cel-compile.
func checkExpressions(env *cel.Env) ruleCheck {
	return func(f *rule.File, r *rule.Rule) []Finding {
		steps := firstStepIndex(r)
		var out []Finding
		for _, s := range exprSites(r) {
			out = append(out, lintExpression(env, f, r, steps, s)...)
		}
		return out
	}
}

// firstStepIndex maps each step id of r to the index of the first step that has it.
func firstStepIndex(r *rule.Rule) map[string]int {
	first := make(map[string]int, len(r.Collect))
	for i, s := range r.Collect {
		if _, ok := first[s.ID]; !ok {
			first[s.ID] = i
		}
	}
	return first
}

// lintExpression checks one expression. steps maps step ids to their index in the rule.
func lintExpression(env *cel.Env, f *rule.File, r *rule.Rule, steps map[string]int, s exprSite) []Finding {
	parsed, iss := env.Parse(s.text)
	if iss != nil && iss.Err() != nil {
		return []Finding{newFinding(f, r, s.where, codeCELCompile, issueText(iss))}
	}

	var out []Finding
	// The references come from the parsed tree, before the type checker has had a look at it.
	seen := make(map[reference]bool)
	for _, ref := range references(parsed.NativeRep().Expr()) {
		if ref.root == "r" {
			ref.field = "" // which field of r is read does not matter
		}
		if seen[ref] {
			continue
		}
		seen[ref] = true
		if code, message := checkReference(r, steps, s, ref); code != "" {
			out = append(out, newFinding(f, r, s.where, code, message))
		}
	}

	if _, iss := env.Check(parsed); iss != nil && iss.Err() != nil {
		out = append(out, newFinding(f, r, s.where, codeCELCompile, issueText(iss)))
	}
	return out
}

// checkReference returns the code and message of what is wrong with a use of ref in the
// expression s, or an empty code when nothing is.
func checkReference(r *rule.Rule, steps map[string]int, s exprSite, ref reference) (code, message string) {
	switch {
	case ref.root == "r" && s.noR != "":
		return codeRUnavailable, "r is not available in " + s.noR
	case ref.field == "":
		// There is no name to check: the variable is used as a whole, or indexed by something
		// that is not a string literal.
	case ref.root == "data":
		if r.Scope == "cluster" && ref.field == "cluster" {
			return "", "" // the engine adds the cluster as a step of its own
		}
		index, ok := steps[ref.field]
		switch {
		case !ok:
			return codeDataRefUnknown, fmt.Sprintf("data.%s: no collect step has this id", clip(ref.field))
		case index >= s.steps:
			return codeDataRefForward, fmt.Sprintf("data.%s: the step does not run before this expression, so it has no result yet", clip(ref.field))
		}
	case ref.root == "params":
		if _, ok := r.Params[ref.field]; !ok {
			return codeParamsRefUndefined, fmt.Sprintf("params.%s: the rule does not define this param", clip(ref.field))
		}
	case ref.root == "ctx":
		if !slices.Contains(ctxFields(), ref.field) {
			return codeCtxRefUnknown, fmt.Sprintf("ctx.%s: not a context field (known: %s)", clip(ref.field), strings.Join(ctxFields(), ", "))
		}
	}
	return "", ""
}

// issueText returns the first error of iss as one clipped line, with its position in the
// expression. The error text of the parser and the checker quotes the expression, which is why
// it is clipped.
func issueText(iss *cel.Issues) string {
	errs := iss.Errors()
	if len(errs) == 0 {
		return clip(oneLine(iss.Err().Error()))
	}
	first := errs[0]
	msg := clip(oneLine(first.Message))
	if loc := first.Location; loc != nil && loc.Line() > 0 {
		return fmt.Sprintf("line %d, column %d: %s", loc.Line(), loc.Column()+1, msg) // columns count from 0
	}
	return msg
}

// reference is a use of data, params, ctx or r in an expression.
type reference struct {
	root string // data, params, ctx or r
	// field is the name selected from root: x in data.x, data.?x and data["x"]. It is empty when
	// root is used on its own or is indexed by something that is not a string literal.
	field string
}

// references returns every use of data, params, ctx and r in e, in the order they appear.
//
// A macro variable can have the same name as one of them, as in data.items.exists(data, ...) or
// cel.bind(r, ...). Inside the macro that name is the macro's variable and not a use of the
// rule's. A variable is in scope in the loop of a comprehension and in what the macro returns,
// but not in the expression it iterates over or in the initial value of its accumulator.
func references(e ast.Expr) []reference {
	var w refWalker
	w.walk(e, nil)
	return w.refs
}

type refWalker struct{ refs []reference }

// walk visits e. shadowed holds the names of the macro variables in scope.
func (w *refWalker) walk(e ast.Expr, shadowed []string) {
	if operand, field, ok := selection(e); ok {
		if root, isRoot := rootName(operand, shadowed); isRoot {
			w.refs = append(w.refs, reference{root: root, field: field})
			return
		}
	}

	switch e.Kind() {
	case ast.IdentKind:
		if root, ok := rootName(e, shadowed); ok {
			w.refs = append(w.refs, reference{root: root})
		}
	case ast.SelectKind:
		w.walk(e.AsSelect().Operand(), shadowed)
	case ast.CallKind:
		call := e.AsCall()
		if call.IsMemberFunction() {
			w.walk(call.Target(), shadowed)
		}
		for _, arg := range call.Args() {
			w.walk(arg, shadowed)
		}
	case ast.ListKind:
		for _, el := range e.AsList().Elements() {
			w.walk(el, shadowed)
		}
	case ast.MapKind:
		for _, entry := range e.AsMap().Entries() {
			if entry.Kind() == ast.MapEntryKind {
				w.walk(entry.AsMapEntry().Key(), shadowed)
				w.walk(entry.AsMapEntry().Value(), shadowed)
			}
		}
	case ast.StructKind:
		for _, entry := range e.AsStruct().Fields() {
			if entry.Kind() == ast.StructFieldKind {
				w.walk(entry.AsStructField().Value(), shadowed)
			}
		}
	case ast.ComprehensionKind:
		c := e.AsComprehension()
		w.walk(c.IterRange(), shadowed)
		w.walk(c.AccuInit(), shadowed)

		loop := append(slices.Clone(shadowed), c.IterVar(), c.AccuVar())
		if c.HasIterVar2() {
			loop = append(loop, c.IterVar2())
		}
		w.walk(c.LoopCondition(), loop)
		w.walk(c.LoopStep(), loop)
		w.walk(c.Result(), append(slices.Clone(shadowed), c.AccuVar()))
	}
}

// selection recognizes the expressions that read one named field of an operand: x.name,
// x.?name, x["name"], x[?"name"], and the presence test has(x.name), which the parser turns
// into a select too.
func selection(e ast.Expr) (operand ast.Expr, field string, ok bool) {
	switch e.Kind() {
	case ast.SelectKind:
		sel := e.AsSelect()
		return sel.Operand(), sel.FieldName(), true
	case ast.CallKind:
		call := e.AsCall()
		switch call.FunctionName() {
		case operators.OptSelect, operators.Index, operators.OptIndex:
			args := call.Args()
			if call.IsMemberFunction() || len(args) != 2 {
				return nil, "", false
			}
			if name, isString := stringLiteral(args[1]); isString {
				return args[0], name, true
			}
		}
	}
	return nil, "", false
}

func stringLiteral(e ast.Expr) (string, bool) {
	if e.Kind() != ast.LiteralKind {
		return "", false
	}
	s, ok := e.AsLiteral().Value().(string)
	return s, ok
}

// rootName returns the name when e is the identifier data, params, ctx or r and it stands for
// the variable of the rule, not for a macro variable of the same name.
func rootName(e ast.Expr, shadowed []string) (string, bool) {
	if e.Kind() != ast.IdentKind {
		return "", false
	}
	name := e.AsIdent()
	if absolute, ok := strings.CutPrefix(name, "."); ok {
		// A leading dot names the variable of the environment even where a macro variable has
		// the same name.
		name = absolute
	} else if slices.Contains(shadowed, name) {
		return "", false
	}
	switch name {
	case "data", "params", "ctx", "r":
		return name, true
	}
	return "", false
}
