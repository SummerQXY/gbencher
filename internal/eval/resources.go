package eval

import (
	"context"
	"fmt"
	"strings"

	"github.com/SummerQXY/gbencher/internal/rule"
)

// ResourceInstance is one normalized resource considered by a rule.
type ResourceInstance struct {
	Kind, Name, Key string
	Elem            any
}

// ExpandResult contains the instances produced by a resource rule.
type ExpandResult struct {
	Instances   []ResourceInstance
	Empty       bool
	EmptyReason string
}

// ExpandResources evaluates a resource rule or creates the single instance for an aggregate rule.
func ExpandResources(ctx context.Context, env *Env, r *rule.Rule, d *Data, c Context, params map[string]any) (ExpandResult, error) {
	if r == nil {
		return ExpandResult{}, fmt.Errorf("rule is nil")
	}
	if d == nil {
		d = NewData()
	}
	if r.Resource == nil {
		return ExpandResult{Instances: []ResourceInstance{{Kind: c.TargetKind, Name: c.TargetKey, Key: c.TargetKey}}}, nil
	}
	if env == nil {
		return ExpandResult{}, fmt.Errorf("evaluation environment is nil")
	}
	resources, err := env.List(ctx, r.Resource.From, d, c, params)
	if err != nil {
		return ExpandResult{}, fmt.Errorf("evaluate resource.from: %w", err)
	}
	if len(resources) == 0 {
		return ExpandResult{Instances: []ResourceInstance{}, Empty: true, EmptyReason: "no_resources"}, nil
	}
	out := ExpandResult{Instances: make([]ResourceInstance, 0, len(resources))}
	for i, elem := range resources {
		if r.Resource.Filter != "" {
			keep, err := env.Bool(ctx, r.Resource.Filter, d, elem, c, params)
			if err != nil {
				return ExpandResult{}, fmt.Errorf("evaluate resource.filter for element %d: %w", i, err)
			}
			if !keep {
				continue
			}
		}
		name := r.Resource.Name
		if name == "" {
			name = "r.name"
		}
		value, err := env.Value(ctx, name, d, elem, c, params)
		if err != nil {
			return ExpandResult{}, fmt.Errorf("evaluate resource.name for element %d: %w", i, err)
		}
		resourceName, ok := value.(string)
		if !ok {
			return ExpandResult{}, fmt.Errorf("resource.name for element %d did not produce a string", i)
		}
		resourceName = normalizeResourceName(resourceName, c)
		key := resourceName
		if r.Resource.Key != "" {
			value, err = env.Value(ctx, r.Resource.Key, d, elem, c, params)
			if err != nil {
				return ExpandResult{}, fmt.Errorf("evaluate resource.key for element %d: %w", i, err)
			}
			var keyOK bool
			key, keyOK = value.(string)
			if !keyOK {
				return ExpandResult{}, fmt.Errorf("resource.key for element %d did not produce a string", i)
			}
		}
		out.Instances = append(out.Instances, ResourceInstance{Kind: r.Resource.Kind, Name: resourceName, Key: key, Elem: elem})
	}
	if len(out.Instances) == 0 {
		out.Empty = true
		out.EmptyReason = "filtered_out"
	}
	return out, nil
}

func normalizeResourceName(name string, c Context) string {
	if strings.HasPrefix(name, "projects/") || strings.HasPrefix(name, "organizations/") || strings.HasPrefix(name, "folders/") {
		return name
	}
	if isClusterTarget(c) {
		clusterName := clusterName(c.Cluster)
		if clusterName != "" {
			return "clusters/" + clusterName + "/" + strings.TrimLeft(name, "/")
		}
	}
	if c.Project == "" {
		return name
	}
	return "projects/" + c.Project + "/" + strings.TrimLeft(name, "/")
}

func isClusterTarget(c Context) bool {
	return c.Cluster != nil || strings.Contains(c.TargetKey, "/clusters/") || strings.Contains(strings.ToLower(c.TargetKind), "cluster")
}

func clusterName(cluster any) string {
	switch value := cluster.(type) {
	case string:
		return value
	case map[string]any:
		if name, ok := value["name"].(string); ok {
			return name
		}
	}
	return ""
}
