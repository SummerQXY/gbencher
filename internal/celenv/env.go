// Package celenv builds the CEL environment in which rule expressions are checked and
// evaluated, and implements the custom functions those expressions can call.
package celenv

import (
	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/ext"
)

// New returns the CEL environment shared by rule linting and evaluation.
//
// It declares data and params as maps from string to dyn and ctx as dyn. When withResource
// is true it also declares r, the resource under evaluation, as dyn; aggregate rules have no
// resource, so their expressions are compiled with withResource false and r stays undeclared.
//
// The environment enables optional types, cross-type numeric comparisons, the strings, lists,
// sets, math, encoders and bindings extensions, and the six custom functions of this package.
// It sets no cost limit and no interrupt: those belong to a program, so the caller applies
// them when it creates one.
func New(withResource bool) (*cel.Env, error) {
	opts := []cel.EnvOption{
		cel.Variable("data", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("params", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("ctx", cel.DynType),
		cel.OptionalTypes(),
		cel.CrossTypeNumericComparisons(true),
		ext.Strings(),
		ext.Lists(),
		ext.Sets(),
		ext.Math(),
		ext.Encoders(),
		ext.Bindings(),
	}
	if withResource {
		opts = append(opts, cel.Variable("r", cel.DynType))
	}
	opts = append(opts, functionOptions()...)
	return cel.NewEnv(opts...)
}
