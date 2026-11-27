package eval

import (
	"slices"
	"sort"

	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
)

// DataDependencies describes the step fields referenced by a CEL expression. Dynamic
// indexing or use of the data root without a static field is reported as unknown.
type DataDependencies struct {
	Fields  []string
	Unknown bool
}

// DataDependencies parses an expression and returns its references to the data root.
func (e *Env) DataDependencies(expression string) (DataDependencies, error) {
	parsed, err := e.compile(e.withoutResource, expression)
	if err != nil {
		return DataDependencies{Unknown: true}, err
	}
	walker := dataReferenceWalker{fields: make(map[string]bool)}
	walker.walk(parsed.NativeRep().Expr(), nil)
	fields := make([]string, 0, len(walker.fields))
	for field := range walker.fields {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return DataDependencies{Fields: fields, Unknown: walker.unknown}, nil
}

type dataReferenceWalker struct {
	fields  map[string]bool
	unknown bool
}

func (w *dataReferenceWalker) walk(expr ast.Expr, shadowed []string) {
	if operand, field, ok := dataSelection(expr); ok {
		if isDataRoot(operand, shadowed) {
			if field == "" {
				w.unknown = true
			} else {
				w.fields[field] = true
			}
			return
		}
	}

	switch expr.Kind() {
	case ast.IdentKind:
		if isDataRoot(expr, shadowed) {
			w.unknown = true
		}
	case ast.SelectKind:
		w.walk(expr.AsSelect().Operand(), shadowed)
	case ast.CallKind:
		call := expr.AsCall()
		if call.IsMemberFunction() {
			w.walk(call.Target(), shadowed)
		}
		for _, arg := range call.Args() {
			w.walk(arg, shadowed)
		}
	case ast.ListKind:
		for _, element := range expr.AsList().Elements() {
			w.walk(element, shadowed)
		}
	case ast.MapKind:
		for _, entry := range expr.AsMap().Entries() {
			if entry.Kind() == ast.MapEntryKind {
				w.walk(entry.AsMapEntry().Key(), shadowed)
				w.walk(entry.AsMapEntry().Value(), shadowed)
			}
		}
	case ast.StructKind:
		for _, entry := range expr.AsStruct().Fields() {
			if entry.Kind() == ast.StructFieldKind {
				w.walk(entry.AsStructField().Value(), shadowed)
			}
		}
	case ast.ComprehensionKind:
		comprehension := expr.AsComprehension()
		w.walk(comprehension.IterRange(), shadowed)
		w.walk(comprehension.AccuInit(), shadowed)
		loopScope := append(slices.Clone(shadowed), comprehension.IterVar(), comprehension.AccuVar())
		if comprehension.HasIterVar2() {
			loopScope = append(loopScope, comprehension.IterVar2())
		}
		w.walk(comprehension.LoopCondition(), loopScope)
		w.walk(comprehension.LoopStep(), loopScope)
		w.walk(comprehension.Result(), append(slices.Clone(shadowed), comprehension.AccuVar()))
	}
}

func dataSelection(expr ast.Expr) (operand ast.Expr, field string, ok bool) {
	switch expr.Kind() {
	case ast.SelectKind:
		selection := expr.AsSelect()
		return selection.Operand(), selection.FieldName(), true
	case ast.CallKind:
		call := expr.AsCall()
		switch call.FunctionName() {
		case operators.OptSelect, operators.Index, operators.OptIndex:
			args := call.Args()
			if call.IsMemberFunction() || len(args) != 2 {
				return nil, "", false
			}
			if args[1].Kind() == ast.LiteralKind {
				if field, ok := args[1].AsLiteral().Value().(string); ok {
					return args[0], field, true
				}
			}
			return args[0], "", true
		}
	}
	return nil, "", false
}

func isDataRoot(expr ast.Expr, shadowed []string) bool {
	if expr.Kind() != ast.IdentKind {
		return false
	}
	name := expr.AsIdent()
	if name != ".data" && slices.Contains(shadowed, name) {
		return false
	}
	return name == "data" || name == ".data"
}
