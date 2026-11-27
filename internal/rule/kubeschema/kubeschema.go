package kubeschema

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	celast "cel.dev/cel-go/common/ast"
	"github.com/SummerQXY/gbencher/internal/celenv"
	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/testdata/schemas"
)

// Result contains Kubernetes resource errors, unresolved-path warnings and rules whose paths
// were completely validated against pinned offline schemas.
type Result struct {
	Errors   []string
	Warnings []string
	StaticOK map[string]bool
}

type openAPIDocument struct {
	Source      string                     `json:"source"`
	Version     string                     `json:"version"`
	Retrieval   string                     `json:"retrieval"`
	Resources   map[string]string          `json:"resources"`
	Definitions map[string]json.RawMessage `json:"definitions"`
}

type crdDocument struct {
	Source    string                 `json:"source"`
	Version   string                 `json:"version"`
	Retrieval string                 `json:"retrieval"`
	Resource  map[string]crdResource `json:"resource"`
}

type crdResource struct {
	Kind   string          `json:"kind"`
	Scope  string          `json:"scope"`
	Schema json.RawMessage `json:"schema"`
}

type discoveryDocument struct {
	Source    string                     `json:"source"`
	Version   string                     `json:"version"`
	Revision  string                     `json:"revision"`
	Retrieval string                     `json:"retrieval"`
	Schemas   map[string]discoverySchema `json:"schemas"`
}

type discoverySchema struct {
	Properties map[string]json.RawMessage `json:"properties"`
}

type discoveryField struct {
	Ref  string `json:"$ref"`
	Type string `json:"type"`
}

type schemaSet struct {
	openAPI openAPIDocument
	crd     crdDocument
}

type valueType struct {
	name         string
	elem         *valueType
	additional   *valueType
	inline       map[string]json.RawMessage
	alternatives []valueType
	tracked      bool
	kubectl      bool
}

type evaluator struct {
	rule     *rule.Rule
	schemas  schemaSet
	steps    map[string]valueType
	vars     map[string]valueType
	errors   map[string]bool
	warnings map[string]bool
}

var dataRefPattern = regexp.MustCompile(`\bdata\.([A-Za-z_][A-Za-z0-9_]*)`)

// Check validates resource names and every statically recoverable Kubernetes CEL field path.
func Check(set *rule.Set) Result {
	out := Result{StaticOK: map[string]bool{}}
	if set == nil {
		out.Errors = append(out.Errors, "rule set is required")
		return out
	}
	schema, err := loadSchemas()
	if err != nil {
		out.Errors = append(out.Errors, err.Error())
		return out
	}
	env, err := celenv.New(true)
	if err != nil {
		out.Errors = append(out.Errors, "create CEL parser: "+err.Error())
		return out
	}
	if err := CheckKubeconfigFields(); err != nil {
		out.Errors = append(out.Errors, err.Error())
		return out
	}
	for _, current := range set.Rules {
		if current == nil {
			continue
		}
		steps, hasKubectl, ruleErrors := resourceTypes(current, schema)
		if !hasKubectl {
			continue
		}
		state := &evaluator{rule: current, schemas: schema, steps: steps, vars: make(map[string]valueType), errors: map[string]bool{}, warnings: map[string]bool{}}
		for _, message := range ruleErrors {
			state.errors[message] = true
		}
		if current.Resource != nil {
			state.vars["r"] = resourceType(current, steps)
		}
		for _, expression := range ruleExpressions(current) {
			if strings.TrimSpace(expression) == "" {
				continue
			}
			parsed, issues := env.Parse(expression)
			if issues != nil && issues.Err() != nil {
				state.warnings[fmt.Sprintf("%s CEL expression could not be parsed for Kubernetes schema paths", current.ID)] = true
				continue
			}
			state.inspect(parsed.NativeRep().Expr(), cloneTypes(state.vars))
		}
		for message := range state.errors {
			out.Errors = append(out.Errors, message)
		}
		for message := range state.warnings {
			out.Warnings = append(out.Warnings, message)
		}
		if len(state.errors) == 0 && len(state.warnings) == 0 {
			out.StaticOK[current.ID] = true
		}
	}
	sort.Strings(out.Errors)
	sort.Strings(out.Warnings)
	return out
}

// CheckKubeconfigFields ensures the generated kubeconfig inputs remain present in the pinned
// Container API Discovery schema.
func CheckKubeconfigFields() error {
	data, err := fs.ReadFile(schemas.FS, "container-v1-kubeconfig.json")
	if err != nil {
		return fmt.Errorf("read pinned Container API Discovery schema: %w", err)
	}
	var document discoveryDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("parse pinned Container API Discovery schema: %w", err)
	}
	if document.Source == "" || document.Version == "" || document.Revision == "" || document.Retrieval == "" {
		return fmt.Errorf("pinned Container API Discovery schema is missing source metadata")
	}
	cluster := document.Schemas["Cluster"].Properties
	master := document.Schemas["MasterAuth"].Properties
	for name, field := range map[string]json.RawMessage{
		"Cluster.endpoint":                cluster["endpoint"],
		"Cluster.masterAuth":              cluster["masterAuth"],
		"MasterAuth.clusterCaCertificate": master["clusterCaCertificate"],
	} {
		if len(field) == 0 || string(field) == "null" {
			return fmt.Errorf("pinned Container API Discovery schema lacks %s", name)
		}
	}
	var endpoint, masterAuth, ca discoveryField
	_ = json.Unmarshal(cluster["endpoint"], &endpoint)
	_ = json.Unmarshal(cluster["masterAuth"], &masterAuth)
	_ = json.Unmarshal(master["clusterCaCertificate"], &ca)
	if endpoint.Type != "string" || masterAuth.Ref != "MasterAuth" || ca.Type != "string" {
		return fmt.Errorf("pinned Container API Discovery schema has incompatible kubeconfig field declarations")
	}
	return nil
}

func loadSchemas() (schemaSet, error) {
	var out schemaSet
	data, err := fs.ReadFile(schemas.FS, "kubernetes-v1.32.0.json")
	if err != nil {
		return out, fmt.Errorf("read pinned Kubernetes OpenAPI schema: %w", err)
	}
	if err := json.Unmarshal(data, &out.openAPI); err != nil {
		return out, fmt.Errorf("parse pinned Kubernetes OpenAPI schema: %w", err)
	}
	if out.openAPI.Source == "" || out.openAPI.Version == "" || out.openAPI.Retrieval == "" || len(out.openAPI.Resources) == 0 || len(out.openAPI.Definitions) == 0 {
		return out, fmt.Errorf("pinned Kubernetes OpenAPI schema is missing source metadata or definitions")
	}
	data, err = fs.ReadFile(schemas.FS, "gke-managedcertificate-v1.json")
	if err != nil {
		return out, fmt.Errorf("read pinned GKE CRD schema: %w", err)
	}
	if err := json.Unmarshal(data, &out.crd); err != nil {
		return out, fmt.Errorf("parse pinned GKE CRD schema: %w", err)
	}
	if out.crd.Source == "" || out.crd.Version == "" || out.crd.Retrieval == "" || len(out.crd.Resource) == 0 {
		return out, fmt.Errorf("pinned GKE CRD schema is missing source metadata or definitions")
	}
	return out, nil
}

func resourceTypes(current *rule.Rule, schemas schemaSet) (map[string]valueType, bool, []string) {
	out := make(map[string]valueType)
	var errors []string
	hasKubectl := false
	for _, step := range current.Collect {
		if step.Kubectl == "" {
			continue
		}
		hasKubectl = true
		parts := strings.Fields(step.Kubectl)
		resource := ""
		for i := 0; i+1 < len(parts); i++ {
			if parts[i] == "get" {
				resource = strings.Trim(parts[i+1], ",")
				break
			}
		}
		if resource == "" {
			errors = append(errors, fmt.Sprintf("%s kubectl.%s: resource name could not be determined", current.ID, step.ID))
			continue
		}
		if _, ok := schemas.crd.Resource[resource]; ok {
			out[step.ID] = valueType{name: "list-crd:" + resource, tracked: true, kubectl: true}
			continue
		}
		definition, ok := schemas.openAPI.Resources[resource]
		if !ok {
			errors = append(errors, fmt.Sprintf("%s kubectl.%s: resource %q is not in the pinned Kubernetes OpenAPI or GKE CRD schemas", current.ID, step.ID, resource))
			continue
		}
		if _, ok := schemas.openAPI.Definitions[definition]; !ok {
			errors = append(errors, fmt.Sprintf("%s kubectl.%s: schema definition %q is missing", current.ID, step.ID, definition))
			continue
		}
		out[step.ID] = valueType{name: "list:" + definition, tracked: true, kubectl: true}
	}
	return out, hasKubectl, errors
}

func resourceType(current *rule.Rule, steps map[string]valueType) valueType {
	if current.Resource.Kind != "" {
		name := strings.TrimPrefix(current.Resource.Kind, "k8s.io/")
		for _, definition := range steps {
			if definition.name == "list:"+name {
				return valueType{name: name, tracked: true, kubectl: true}
			}
		}
	}
	var names []string
	for _, match := range dataRefPattern.FindAllStringSubmatch(current.Resource.From, -1) {
		if source, ok := steps[match[1]]; ok {
			if strings.HasPrefix(source.name, "list:") {
				names = append(names, strings.TrimPrefix(source.name, "list:"))
			} else if strings.HasPrefix(source.name, "list-crd:") {
				names = append(names, strings.TrimPrefix(source.name, "list-crd:"))
			} else {
				names = append(names, source.name)
			}
		}
	}
	names = uniqueStrings(names)
	if len(names) == 1 {
		return valueType{name: names[0], tracked: true, kubectl: true}
	}
	if len(names) > 1 {
		alternatives := make([]valueType, 0, len(names))
		for _, name := range names {
			alternatives = append(alternatives, valueType{name: name, tracked: true, kubectl: true})
		}
		return valueType{alternatives: alternatives, tracked: true, kubectl: true}
	}
	return valueType{}
}

func (e *evaluator) inspect(expr celast.Expr, vars map[string]valueType) valueType {
	if expr == nil {
		return valueType{}
	}
	switch expr.Kind() {
	case celast.IdentKind:
		name := expr.AsIdent()
		if value, ok := vars[name]; ok {
			return value
		}
		if value, ok := e.steps[name]; ok {
			return value
		}
		return valueType{}
	case celast.SelectKind:
		selection := expr.AsSelect()
		if selection.Operand().Kind() == celast.IdentKind && selection.Operand().AsIdent() == "data" {
			if step, ok := e.steps[selection.FieldName()]; ok {
				return step
			}
			if selection.FieldName() == "cluster" {
				e.warnings[fmt.Sprintf("%s CEL path %s could not be statically resolved against the Kubernetes schema", e.rule.ID, renderPath(expr))] = true
			}
			return valueType{}
		}
		base := e.inspect(selection.Operand(), vars)
		if !base.tracked {
			if isClusterContext(expr) || e.isKubeUnknownRoot(selection.Operand(), vars) {
				e.warnings[fmt.Sprintf("%s CEL path %s could not be statically resolved against the Kubernetes schema", e.rule.ID, renderPath(expr))] = true
			}
			return valueType{}
		}
		field, ok := e.resolveField(base, selection.FieldName())
		if !ok {
			e.errors[fmt.Sprintf("%s CEL path %s does not exist in the pinned Kubernetes schema", e.rule.ID, renderPath(expr))] = true
			return valueType{tracked: true, kubectl: true}
		}
		return field
	case celast.CallKind:
		call := expr.AsCall()
		name := call.FunctionName()
		var target valueType
		if call.IsMemberFunction() {
			target = e.inspect(call.Target(), vars)
		} else if call.Target() != nil {
			target = e.inspect(call.Target(), vars)
		}
		args := call.Args()
		argTypes := make([]valueType, len(args))
		for i, arg := range args {
			argTypes[i] = e.inspect(arg, vars)
		}
		if name == "flatten" || strings.HasSuffix(name, "_flatten") {
			return flattenType(target)
		}
		if name == "_+_" || name == "add" {
			if target.tracked && len(argTypes) > 0 {
				return combineTypes(target, argTypes[0])
			}
			if len(argTypes) > 1 {
				return combineTypes(argTypes[0], argTypes[1])
			}
		}
		if (name == "_?_:_" || name == "conditional") && len(argTypes) == 3 {
			return combineTypes(argTypes[1], argTypes[2])
		}
		if name == "_[_]" || name == "index" {
			indexed := target
			if !indexed.tracked && len(argTypes) == 2 {
				indexed = argTypes[0]
			}
			if indexed.tracked {
				if indexed.elem != nil {
					return elementType(indexed)
				}
				if indexed.additional != nil {
					return *indexed.additional
				}
				e.warnings[fmt.Sprintf("%s CEL path %s could not be statically resolved against the Kubernetes schema", e.rule.ID, renderExpression(expr))] = true
			}
			return valueType{}
		}
		return valueType{}
	case celast.ComprehensionKind:
		comprehension := expr.AsComprehension()
		rangeType := e.inspect(comprehension.IterRange(), vars)
		nested := cloneTypes(vars)
		if rangeType.tracked {
			nested[comprehension.IterVar()] = elementType(rangeType)
		} else {
			nested[comprehension.IterVar()] = valueType{}
		}
		if comprehension.IterVar2() != "" {
			nested[comprehension.IterVar2()] = valueType{}
		}
		nested[comprehension.AccuVar()] = valueType{}
		e.inspect(comprehension.LoopCondition(), nested)
		stepType := e.inspect(comprehension.LoopStep(), nested)
		resultType := e.inspect(comprehension.Result(), nested)
		if comprehension.Result().Kind() == celast.IdentKind && comprehension.Result().AsIdent() == comprehension.AccuVar() && stepType.tracked && stepType.elem != nil {
			return stepType
		}
		return resultType
	case celast.ListKind:
		var elem valueType
		for _, item := range expr.AsList().Elements() {
			itemType := e.inspect(item, vars)
			if !elem.tracked {
				elem = itemType
			} else {
				elem = combineTypes(elem, itemType)
			}
		}
		if elem.tracked {
			return valueType{elem: &elem, tracked: true, kubectl: elem.kubectl}
		}
	}
	return valueType{}
}

func (e *evaluator) isKubeUnknownRoot(expr celast.Expr, vars map[string]valueType) bool {
	if isClusterContext(expr) {
		return true
	}
	for expr != nil && expr.Kind() == celast.SelectKind {
		expr = expr.AsSelect().Operand()
	}
	if expr == nil || expr.Kind() != celast.IdentKind {
		return false
	}
	name := expr.AsIdent()
	if value, ok := vars[name]; ok {
		return value.kubectl
	}
	return name == "r" || name == "external"
}

func isClusterContext(expr celast.Expr) bool {
	if expr == nil || expr.Kind() != celast.SelectKind {
		return false
	}
	selection := expr.AsSelect()
	if selection.FieldName() != "cluster" || selection.Operand().Kind() != celast.IdentKind {
		return false
	}
	root := selection.Operand().AsIdent()
	return root == "ctx" || root == "data"
}

func (e *evaluator) resolveField(value valueType, field string) (valueType, bool) {
	if value.elem != nil {
		return valueType{}, false
	}
	alternatives := value.alternatives
	if len(alternatives) == 0 {
		alternatives = []valueType{value}
	}
	var result valueType
	for i, alternative := range alternatives {
		var resolved valueType
		var ok bool
		if alternative.elem != nil {
			return valueType{}, false
		}
		if alternative.inline != nil {
			if raw, found := alternative.inline[field]; found {
				resolved, ok = typeFromSchema(raw), true
			}
		} else {
			resolved, ok = e.fieldByName(alternative.name, field)
		}
		if !ok {
			return valueType{}, false
		}
		if i == 0 {
			result = resolved
		} else {
			result = combineTypes(result, resolved)
		}
	}
	return result, len(alternatives) > 0
}

func (e *evaluator) fieldByName(name, field string) (valueType, bool) {
	if strings.HasPrefix(name, "list:") || strings.HasPrefix(name, "list-crd:") {
		if field == "items" {
			itemName := strings.TrimPrefix(name, "list:")
			if strings.HasPrefix(name, "list-crd:") {
				itemName = "crd:" + strings.TrimPrefix(name, "list-crd:")
			}
			item := valueType{name: itemName, tracked: true, kubectl: true}
			return valueType{elem: &item, tracked: true, kubectl: true}, true
		}
		if field == "apiVersion" || field == "kind" {
			return valueType{name: "primitive:string", tracked: true, kubectl: true}, true
		}
		return valueType{}, false
	}
	var schema json.RawMessage
	if strings.HasPrefix(name, "crd:") {
		resource, ok := e.schemas.crd.Resource[strings.TrimPrefix(name, "crd:")]
		if !ok {
			return valueType{}, false
		}
		schema = resource.Schema
	} else {
		schema = e.schemas.openAPI.Definitions[name]
		if len(schema) == 0 {
			return valueType{}, false
		}
	}
	var object struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(schema, &object) != nil {
		return valueType{}, false
	}
	property, ok := object.Properties[field]
	if !ok {
		return valueType{}, false
	}
	return typeFromSchema(property), true
}

func typeFromSchema(data json.RawMessage) valueType {
	var schema struct {
		Ref        string                     `json:"$ref"`
		Type       string                     `json:"type"`
		Items      json.RawMessage            `json:"items"`
		Additional json.RawMessage            `json:"additionalProperties"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(data, &schema) != nil {
		return valueType{}
	}
	if schema.Ref != "" {
		name := strings.TrimPrefix(schema.Ref, "#/definitions/")
		name = strings.TrimPrefix(name, "definitions/")
		return valueType{name: name, tracked: true, kubectl: true}
	}
	if schema.Type == "array" {
		elem := typeFromSchema(schema.Items)
		return valueType{elem: &elem, tracked: elem.tracked, kubectl: elem.kubectl}
	}
	if schema.Type == "object" {
		value := valueType{name: "inline", inline: schema.Properties, tracked: true, kubectl: true}
		if len(schema.Additional) != 0 {
			additional := typeFromSchema(schema.Additional)
			if additional.tracked {
				value.additional = &additional
			}
		}
		return value
	}
	if schema.Type != "" {
		return valueType{name: "primitive:" + schema.Type, tracked: true, kubectl: true}
	}
	return valueType{}
}

func elementType(value valueType) valueType {
	if value.elem != nil {
		return *value.elem
	}
	return valueType{}
}

func flattenType(value valueType) valueType {
	if value.elem != nil && value.elem.elem != nil {
		return *value.elem
	}
	return value
}

func combineTypes(left, right valueType) valueType {
	if !left.tracked {
		return right
	}
	if !right.tracked {
		return left
	}
	if left.elem != nil && right.elem != nil {
		element := combineTypes(*left.elem, *right.elem)
		return valueType{elem: &element, tracked: true, kubectl: left.kubectl || right.kubectl}
	}
	if typeSignature(left) == typeSignature(right) {
		left.tracked = true
		left.kubectl = left.kubectl || right.kubectl
		return left
	}
	bySignature := make(map[string]valueType)
	for _, value := range append(typeAlternatives(left), typeAlternatives(right)...) {
		bySignature[typeSignature(value)] = value
	}
	signatures := make([]string, 0, len(bySignature))
	for signature := range bySignature {
		signatures = append(signatures, signature)
	}
	sort.Strings(signatures)
	if len(signatures) == 1 {
		value := bySignature[signatures[0]]
		value.tracked = true
		value.kubectl = left.kubectl || right.kubectl
		return value
	}
	alternatives := make([]valueType, 0, len(signatures))
	for _, signature := range signatures {
		alternatives = append(alternatives, bySignature[signature])
	}
	return valueType{alternatives: alternatives, tracked: true, kubectl: left.kubectl || right.kubectl}
}

func typeAlternatives(value valueType) []valueType {
	if len(value.alternatives) != 0 {
		return value.alternatives
	}
	return []valueType{value}
}

func typeSignature(value valueType) string {
	if value.elem != nil {
		return "list<" + typeSignature(*value.elem) + ">"
	}
	if len(value.alternatives) != 0 {
		parts := make([]string, 0, len(value.alternatives))
		for _, alternative := range value.alternatives {
			parts = append(parts, typeSignature(alternative))
		}
		sort.Strings(parts)
		return "union<" + strings.Join(parts, "|") + ">"
	}
	if value.inline != nil {
		keys := make([]string, 0, len(value.inline))
		for key := range value.inline {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var fields strings.Builder
		for _, key := range keys {
			fields.WriteString(key)
			fields.WriteByte(':')
			fields.Write(value.inline[key])
			fields.WriteByte(';')
		}
		return "inline{" + fields.String() + "}"
	}
	if value.additional != nil {
		return value.name + "<" + typeSignature(*value.additional) + ">"
	}
	return value.name
}

func ruleExpressions(current *rule.Rule) []string {
	var out []string
	for _, step := range current.Collect {
		if step.Foreach != "" {
			out = append(out, step.Foreach)
		}
	}
	if current.Resource != nil {
		out = append(out, current.Resource.From, current.Resource.Filter, current.Resource.Name, current.Resource.Key)
	}
	out = append(out, current.Check.Assert, current.Check.ReviewWhen)
	out = append(out, current.Evidence...)
	return out
}

func renderPath(expr celast.Expr) string {
	if expr == nil {
		return "<unknown>"
	}
	if expr.Kind() == celast.SelectKind {
		selectExpr := expr.AsSelect()
		return renderPath(selectExpr.Operand()) + "." + selectExpr.FieldName()
	}
	if expr.Kind() == celast.IdentKind {
		return expr.AsIdent()
	}
	return "<expression>"
}

func renderExpression(expr celast.Expr) string {
	if expr == nil {
		return "<unknown>"
	}
	if expr.Kind() == celast.CallKind {
		call := expr.AsCall()
		if call.FunctionName() == "_[_]" || call.FunctionName() == "index" {
			if call.Target() != nil && len(call.Args()) == 1 {
				return renderExpression(call.Target()) + "[" + renderExpression(call.Args()[0]) + "]"
			}
			if len(call.Args()) == 2 {
				return renderExpression(call.Args()[0]) + "[" + renderExpression(call.Args()[1]) + "]"
			}
		}
	}
	return renderPath(expr)
}

func cloneTypes(source map[string]valueType) map[string]valueType {
	clone := make(map[string]valueType, len(source))
	for name, value := range source {
		clone[name] = value
	}
	return clone
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
