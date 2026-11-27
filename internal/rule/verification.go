package rule

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"go.yaml.in/yaml/v3"

	"github.com/SummerQXY/gbencher/rules"
)

// VerificationLevel describes the evidence available for a rule.
type VerificationLevel string

const (
	VerificationNone    VerificationLevel = "none"
	VerificationStatic  VerificationLevel = "static"
	VerificationFixture VerificationLevel = "fixture"
	VerificationLive    VerificationLevel = "live"
)

// ClusterContextProvenanceKey is the fixture metadata key for the engine-provided cluster.
const ClusterContextProvenanceKey = "cluster"

// Verification is the verification level for each rule id.
type Verification struct {
	Rules map[string]VerificationLevel `yaml:"rules" json:"rules"`
}

// ComputeVerification derives verification levels from static schema checks and fixture metadata.
func ComputeVerification(set *Set, fixturesDir string, staticOK map[string]bool) (Verification, error) {
	if set == nil {
		return Verification{}, errors.New("rule set is required")
	}
	env, err := cel.NewEnv()
	if err != nil {
		return Verification{}, fmt.Errorf("create CEL environment: %w", err)
	}
	v := Verification{Rules: make(map[string]VerificationLevel, len(set.Rules))}
	for _, r := range set.Rules {
		if r != nil {
			v.Rules[r.ID] = VerificationNone
		}
	}
	if fixturesDir == "" {
		fixturesDir = filepath.Join("testdata", "rules")
	}
	entries, err := os.ReadDir(fixturesDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Verification{}, fmt.Errorf("read fixtures: %w", err)
	}
	fixtureCases := make(map[string]map[string]map[string]string)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			id := entry.Name()
			if _, ok := v.Rules[id]; !ok {
				continue
			}
			cases, readErr := os.ReadDir(filepath.Join(fixturesDir, id))
			if readErr != nil {
				return Verification{}, fmt.Errorf("read fixtures for %s: %w", id, readErr)
			}
			for _, file := range cases {
				if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
					continue
				}
				data, readErr := os.ReadFile(filepath.Join(fixturesDir, id, file.Name()))
				if readErr != nil {
					return Verification{}, fmt.Errorf("read fixture %s: %w", file.Name(), readErr)
				}
				var fixture struct {
					Meta struct {
						Provenance map[string]string `json:"provenance"`
					} `json:"meta"`
				}
				if err := json.Unmarshal(data, &fixture); err != nil {
					return Verification{}, fmt.Errorf("parse fixture %s: %w", file.Name(), err)
				}
				name := strings.TrimSuffix(file.Name(), ".json")
				fixtureCases[id] = ensureFixtureMap(fixtureCases[id])
				fixtureCases[id][name] = fixture.Meta.Provenance
			}
		}
	}
	for _, r := range set.Rules {
		if r == nil {
			continue
		}
		if staticOK[r.ID] && hasStaticStep(r) {
			v.Rules[r.ID] = VerificationStatic
		}
		cases := fixtureCases[r.ID]
		pass, hasPass := cases["pass"]
		fail, hasFail := cases["fail"]
		if hasPass && hasFail && fixtureProvenanceOK(env, r, pass) && fixtureProvenanceOK(env, r, fail) {
			v.Rules[r.ID] = VerificationFixture
		}
	}
	return v, nil
}

func ensureFixtureMap(value map[string]map[string]string) map[string]map[string]string {
	if value == nil {
		return make(map[string]map[string]string)
	}
	return value
}

func hasStaticStep(r *Rule) bool {
	for _, step := range r.Collect {
		if step.API != nil || step.Kubectl != "" {
			return true
		}
	}
	return false
}

func fixtureProvenanceOK(env *cel.Env, r *Rule, provenance map[string]string) bool {
	if referencesClusterContext(env, r) {
		value := provenance[ClusterContextProvenanceKey]
		if value != "captured" && value != "captured+mutated" {
			return false
		}
	}
	for _, step := range r.Collect {
		value := provenance[step.ID]
		if step.Gcloud != "" && value != "captured" && value != "captured+mutated" {
			return false
		}
		if (step.API != nil || step.Kubectl != "") && value != "captured" && value != "captured+mutated" && value != "schema" {
			return false
		}
	}
	return true
}

func referencesClusterContext(env *cel.Env, r *Rule) bool {
	var expressions []string
	for _, step := range r.Collect {
		if step.Foreach != "" {
			expressions = append(expressions, step.Foreach)
		}
	}
	if r.Resource != nil {
		expressions = append(expressions, r.Resource.From, r.Resource.Filter, r.Resource.Name, r.Resource.Key)
	}
	expressions = append(expressions, r.Check.Assert, r.Check.ReviewWhen)
	expressions = append(expressions, r.Evidence...)

	for _, expression := range expressions {
		if strings.TrimSpace(expression) == "" {
			continue
		}
		parsed, issues := env.Parse(expression)
		if issues != nil && issues.Err() != nil {
			if strings.Contains(expression, "ctx.cluster") {
				return true
			}
			continue
		}
		if usesClusterContext(parsed.NativeRep().Expr(), nil) {
			return true
		}
	}
	return false
}

func usesClusterContext(expression ast.Expr, shadowed []string) bool {
	if operand, field, ok := clusterSelection(expression); ok && field == "cluster" && isClusterSourceRoot(operand, shadowed) {
		return true
	}
	switch expression.Kind() {
	case ast.SelectKind:
		return usesClusterContext(expression.AsSelect().Operand(), shadowed)
	case ast.CallKind:
		call := expression.AsCall()
		if call.IsMemberFunction() && usesClusterContext(call.Target(), shadowed) {
			return true
		}
		for _, argument := range call.Args() {
			if usesClusterContext(argument, shadowed) {
				return true
			}
		}
	case ast.ListKind:
		for _, element := range expression.AsList().Elements() {
			if usesClusterContext(element, shadowed) {
				return true
			}
		}
	case ast.MapKind:
		for _, entry := range expression.AsMap().Entries() {
			if entry.Kind() == ast.MapEntryKind && (usesClusterContext(entry.AsMapEntry().Key(), shadowed) || usesClusterContext(entry.AsMapEntry().Value(), shadowed)) {
				return true
			}
		}
	case ast.StructKind:
		for _, entry := range expression.AsStruct().Fields() {
			if entry.Kind() == ast.StructFieldKind && usesClusterContext(entry.AsStructField().Value(), shadowed) {
				return true
			}
		}
	case ast.ComprehensionKind:
		comprehension := expression.AsComprehension()
		if usesClusterContext(comprehension.IterRange(), shadowed) || usesClusterContext(comprehension.AccuInit(), shadowed) {
			return true
		}
		loopVars := append(append([]string(nil), shadowed...), comprehension.IterVar(), comprehension.AccuVar())
		if comprehension.HasIterVar2() {
			loopVars = append(loopVars, comprehension.IterVar2())
		}
		if usesClusterContext(comprehension.LoopCondition(), loopVars) || usesClusterContext(comprehension.LoopStep(), loopVars) {
			return true
		}
		resultVars := append(append([]string(nil), shadowed...), comprehension.AccuVar())
		return usesClusterContext(comprehension.Result(), resultVars)
	}
	return false
}

func clusterSelection(expression ast.Expr) (ast.Expr, string, bool) {
	switch expression.Kind() {
	case ast.SelectKind:
		selection := expression.AsSelect()
		return selection.Operand(), selection.FieldName(), true
	case ast.CallKind:
		call := expression.AsCall()
		switch call.FunctionName() {
		case operators.OptSelect, operators.Index, operators.OptIndex:
			arguments := call.Args()
			if !call.IsMemberFunction() && len(arguments) == 2 && arguments[1].Kind() == ast.LiteralKind {
				field, ok := arguments[1].AsLiteral().Value().(string)
				if ok {
					return arguments[0], field, true
				}
			}
		}
	}
	return nil, "", false
}

func isClusterSourceRoot(expression ast.Expr, shadowed []string) bool {
	if expression.Kind() != ast.IdentKind {
		return false
	}
	name := expression.AsIdent()
	if absolute, ok := strings.CutPrefix(name, "."); ok {
		name = absolute
	} else if slices.Contains(shadowed, name) {
		return false
	}
	return name == "ctx" || name == "data"
}

// LoadVerification reads the embedded verification map after checking YAML structure.
func LoadVerification() (*Verification, error) {
	return LoadVerificationFS(rules.FS)
}

// LoadVerificationFS reads verification.yaml from an fs.FS.
func LoadVerificationFS(fsys fs.FS) (*Verification, error) {
	data, err := fs.ReadFile(fsys, "verification.yaml")
	if err != nil {
		return nil, fmt.Errorf("read verification.yaml: %w", err)
	}
	if err := CheckYAMLShape(data); err != nil {
		return nil, err
	}
	var v Verification
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&v); err != nil {
		return nil, fmt.Errorf("parse verification.yaml: %w", err)
	}
	if v.Rules == nil {
		return nil, errors.New("verification.yaml must contain a rules mapping")
	}
	for id, level := range v.Rules {
		if !validVerificationLevel(level) {
			return nil, fmt.Errorf("verification.yaml: invalid level %q for %s", level, id)
		}
	}
	return &v, nil
}

func validVerificationLevel(level VerificationLevel) bool {
	switch level {
	case VerificationNone, VerificationStatic, VerificationFixture, VerificationLive:
		return true
	default:
		return false
	}
}

// WriteVerification writes a stable, sorted verification map.
func WriteVerification(path string, v Verification) error {
	ids := make([]string, 0, len(v.Rules))
	for id := range v.Rules {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var b strings.Builder
	b.WriteString("rules:\n")
	for _, id := range ids {
		if !validVerificationLevel(v.Rules[id]) {
			return fmt.Errorf("invalid verification level %q for %s", v.Rules[id], id)
		}
		fmt.Fprintf(&b, "  %s: %s\n", id, v.Rules[id])
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// VerificationEqual reports whether the two maps contain identical rule levels.
func VerificationEqual(a, b Verification) bool {
	if len(a.Rules) != len(b.Rules) {
		return false
	}
	for id, level := range a.Rules {
		if b.Rules[id] != level {
			return false
		}
	}
	return true
}
