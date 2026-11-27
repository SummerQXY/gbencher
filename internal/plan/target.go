package plan

import (
	"context"

	"github.com/SummerQXY/gbencher/internal/rule"
)

type Target struct {
	Type            string
	Key             string
	ProjectID       string
	Organization    string
	Folder          string
	ClusterName     string
	ClusterLocation string
	Cluster         any
}

type Unit struct {
	Rule   *rule.Rule
	Target Target
}

type TargetIssue struct {
	ProjectID string
	Kind      string
	Detail    string
}

type Deps interface {
	ProjectNumber(ctx context.Context, project string) (string, error)
	Ancestors(ctx context.Context, project string) (org, folder string, err error)
	Clusters(ctx context.Context, project string) ([]any, error)
}

func (t Target) Kind() string {
	switch t.Type {
	case "project":
		return "cloudresourcemanager.googleapis.com/Project"
	case "organization":
		return "cloudresourcemanager.googleapis.com/Organization"
	case "cluster":
		return "container.googleapis.com/Cluster"
	default:
		return ""
	}
}
