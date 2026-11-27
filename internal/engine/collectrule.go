package engine

import "github.com/SummerQXY/gbencher/internal/rule"

func collectRuleParams(r *rule.Rule) map[string]any {
	return cloneMap(r.Params)
}
