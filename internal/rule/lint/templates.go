package lint

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"text/template/parse"

	"github.com/SummerQXY/gbencher/internal/rule"
)

// templateName is the name a template is parsed under. It appears in the parse errors.
const templateName = "t"

// defaultLoopVar is the name of the element of a foreach step in its templates when the step
// does not set as.
const defaultLoopVar = "item"

// tmplSite is one template of a rule and the variables it can use.
type tmplSite struct {
	where string // see Finding.Where
	text  string
	vars  []string // the variables the template can read, such as project
	// noR says why r is not available; it is empty when it is.
	noR string
	// command is true for the templates that become a command line or a URL, and false for the
	// messages that people read.
	command bool
}

// templateSites lists the templates of r: the step templates, which are rendered while the data
// is being collected, and the message templates, which are rendered once there is a result.
// The two see different variables.
func templateSites(r *rule.Rule) []tmplSite {
	var sites []tmplSite

	for i, s := range r.Collect {
		vars := []string{"project", "project_number", "organization", "folder", "cluster", "params"}
		if s.Foreach != "" {
			vars = append(vars, cmp.Or(s.As, defaultLoopVar))
		}
		where := stepWhere(i, s)
		sites = append(sites,
			tmplSite{where: where + ".gcloud", text: s.Gcloud, vars: vars, command: true},
			tmplSite{where: where + ".kubectl", text: s.Kubectl, vars: vars, command: true})
		if s.API != nil {
			sites = append(sites, tmplSite{where: where + ".api.url", text: s.API.URL, vars: vars, command: true})
		}
	}

	vars := []string{"params", "project", "project_number", "organization", "folder", "cluster"}
	noR := ""
	if r.Resource == nil {
		noR = noResource
	} else {
		vars = append(vars, "r")
	}
	return append(sites,
		tmplSite{where: "check.message", text: r.Check.Message, vars: vars, noR: noR},
		tmplSite{where: "check.review_message", text: r.Check.ReviewMessage, vars: vars, noR: noR})
}

// checkTemplates parses every template of a rule and checks the variables it reads. Templates
// are only parsed, never executed.
func checkTemplates(f *rule.File, r *rule.Rule) []Finding {
	var out []Finding
	for _, s := range templateSites(r) {
		if strings.TrimSpace(s.text) != "" {
			out = append(out, lintTemplate(f, r, s)...)
		}
	}
	return out
}

func lintTemplate(f *rule.File, r *rule.Rule, s tmplSite) []Finding {
	tmpl, err := template.New(templateName).Parse(s.text)
	if err != nil {
		return []Finding{newFinding(f, r, s.where, codeTemplateParse, templateParseText(err))}
	}

	var out []Finding
	reported := make(map[string]bool)
	report := func(code, message string) {
		if !reported[code+" "+message] {
			reported[code+" "+message] = true
			out = append(out, newFinding(f, r, s.where, code, message))
		}
	}
	for _, path := range templateRefs(tmpl.Tree.Root) {
		name := path[0]
		switch {
		case name == "r" && s.noR != "":
			report(codeRUnavailable, "r is not available in "+s.noR)
		case !slices.Contains(s.vars, name):
			report(codeTemplateVarUndeclared, fmt.Sprintf(".%s is not a variable here (available: %s)", clip(name), dotted(s.vars)))
		case name == "params" && len(path) > 1:
			if _, ok := r.Params[path[1]]; !ok {
				report(codeParamsRefUndefined, fmt.Sprintf("params.%s: the rule does not define this param", clip(path[1])))
			}
		}
	}
	return out
}

// dotted renders variable names as they are written in a template, sorted.
func dotted(vars []string) string {
	names := slices.Clone(vars)
	slices.Sort(names)
	for i, n := range names {
		names[i] = "." + n
	}
	return strings.Join(names, ", ")
}

// templateParseText returns the parse error as one clipped line: "line 1: unclosed action".
func templateParseText(err error) string {
	msg := strings.TrimPrefix(err.Error(), "template: "+templateName+":")
	if line, rest, ok := strings.Cut(msg, ": "); ok {
		if n, convErr := strconv.Atoi(line); convErr == nil {
			msg = fmt.Sprintf("line %d: %s", n, rest)
		}
	}
	return clip(oneLine(msg))
}

// templateRefs returns the fields a template reads from its data, each as the path of names
// from the data: [params limit] for .params.limit. They are in the order they appear.
//
// Fields are looked up in the dot, and range and with give the dot another value inside their
// body: there .name is a field of the element, not a variable of the template, and is not
// returned. A path that starts at $, the data the template was executed with, is a variable
// wherever it is. Variables the template declares itself ($x), function names and the strings
// and numbers of an action are not fields.
func templateRefs(root *parse.ListNode) [][]string {
	var w tmplWalker
	w.walk(root, true)
	return w.paths
}

type tmplWalker struct{ paths [][]string }

// walk visits n. dotIsData says whether the dot is still the data the template was executed with.
func (w *tmplWalker) walk(n parse.Node, dotIsData bool) {
	switch n := n.(type) {
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, child := range n.Nodes {
			w.walk(child, dotIsData)
		}
	case *parse.ActionNode:
		w.walk(n.Pipe, dotIsData)
	case *parse.PipeNode:
		if n == nil {
			return
		}
		for _, cmd := range n.Cmds {
			w.walk(cmd, dotIsData)
		}
	case *parse.CommandNode:
		for _, arg := range n.Args {
			w.walk(arg, dotIsData)
		}
	case *parse.FieldNode:
		if dotIsData {
			w.paths = append(w.paths, n.Ident)
		}
	case *parse.VariableNode:
		if len(n.Ident) > 1 && n.Ident[0] == "$" {
			w.paths = append(w.paths, n.Ident[1:])
		}
	case *parse.ChainNode:
		// (.params).name: the field is read from the result of the parenthesized pipeline.
		if base, ok := singleField(n.Node); ok && dotIsData {
			w.paths = append(w.paths, slices.Concat(base, n.Field))
			return
		}
		w.walk(n.Node, dotIsData)
	case *parse.IfNode:
		w.walk(n.Pipe, dotIsData)
		w.walk(n.List, dotIsData)
		w.walk(n.ElseList, dotIsData)
	case *parse.RangeNode:
		w.walk(n.Pipe, dotIsData)
		w.walk(n.List, false)
		w.walk(n.ElseList, dotIsData)
	case *parse.WithNode:
		w.walk(n.Pipe, dotIsData)
		w.walk(n.List, false)
		w.walk(n.ElseList, dotIsData)
	case *parse.TemplateNode:
		w.walk(n.Pipe, dotIsData)
	}
}

// singleField returns the names of the field when n is a parenthesized pipeline that is just
// that field, as in (.params).
func singleField(n parse.Node) ([]string, bool) {
	pipe, ok := n.(*parse.PipeNode)
	if !ok || pipe == nil || len(pipe.Cmds) != 1 || len(pipe.Cmds[0].Args) != 1 {
		return nil, false
	}
	field, ok := pipe.Cmds[0].Args[0].(*parse.FieldNode)
	if !ok {
		return nil, false
	}
	return field.Ident, true
}
