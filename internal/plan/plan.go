package plan

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/SummerQXY/gbencher/internal/rule"
)

func Build(ctx context.Context, rules []*rule.Rule, projects []string, d Deps) ([]Unit, []TargetIssue, error) {
	if d == nil {
		return nil, nil, errors.New("target dependencies are required")
	}
	if len(projects) == 0 {
		return nil, nil, errors.New("at least one project is required")
	}

	projectTargets := make([]Target, 0, len(projects))
	issues := make([]TargetIssue, 0)
	resolvedProjects := 0
	seenProjects := make(map[string]bool, len(projects))
	for _, project := range projects {
		if seenProjects[project] {
			continue
		}
		seenProjects[project] = true
		target := Target{Type: "project", Key: "projects/" + project, ProjectID: project}
		number, numberErr := d.ProjectNumber(ctx, project)
		if numberErr == nil && number == "" {
			numberErr = errors.New("project number is empty")
		}
		org, folder, ancestorErr := d.Ancestors(ctx, project)
		if numberErr == nil && ancestorErr == nil {
			resolvedProjects++
		} else {
			detail := issueDetail(numberErr, ancestorErr)
			issues = append(issues, TargetIssue{ProjectID: project, Kind: "project_unresolved", Detail: detail})
		}
		target.Organization = org
		target.Folder = folder
		projectTargets = append(projectTargets, target)
	}

	type clusterResult struct {
		targets []Target
		err     error
	}
	clusterResults := make(map[string]clusterResult)
	hasClusterRules := false
	for _, currentRule := range rules {
		if currentRule != nil && currentRule.Scope == "cluster" {
			hasClusterRules = true
			break
		}
	}
	if hasClusterRules {
		for _, projectTarget := range projectTargets {
			clusters, err := d.Clusters(ctx, projectTarget.ProjectID)
			result := clusterResult{}
			if err != nil {
				result.err = err
			} else {
				for _, cluster := range clusters {
					name, location, parseErr := clusterLocation(cluster)
					if parseErr != nil {
						result.err = parseErr
						break
					}
					result.targets = append(result.targets, Target{
						Type: "cluster", ProjectID: projectTarget.ProjectID, Organization: projectTarget.Organization,
						Folder: projectTarget.Folder, ClusterName: name, ClusterLocation: location, Cluster: cluster,
						Key: fmt.Sprintf("projects/%s/locations/%s/clusters/%s", projectTarget.ProjectID, location, name),
					})
				}
			}
			clusterResults[projectTarget.ProjectID] = result
			if result.err != nil {
				issues = append(issues, TargetIssue{ProjectID: projectTarget.ProjectID, Kind: "clusters_unresolved", Detail: result.err.Error()})
			}
		}
	}

	units := make([]Unit, 0, len(rules)*len(projects))
	orgSeen := make(map[string]bool)
	for _, currentRule := range rules {
		if currentRule == nil {
			return nil, issues, errors.New("rule must not be nil")
		}
		switch currentRule.Scope {
		case "project":
			for _, target := range projectTargets {
				units = append(units, Unit{Rule: currentRule, Target: target})
			}
		case "organization":
			if currentRule.EvaluatePer == "project" {
				for _, target := range projectTargets {
					units = append(units, Unit{Rule: currentRule, Target: target})
				}
				continue
			}
			for _, projectTarget := range projectTargets {
				orgID := projectTarget.Organization
				key := "organizations/" + orgID
				if orgSeen[currentRule.ID+"\x00"+key] {
					continue
				}
				orgSeen[currentRule.ID+"\x00"+key] = true
				target := Target{Type: "organization", Key: key, Organization: orgID}
				units = append(units, Unit{Rule: currentRule, Target: target})
			}
		case "cluster":
			for _, projectTarget := range projectTargets {
				result := clusterResults[projectTarget.ProjectID]
				if result.err != nil {
					units = append(units, Unit{Rule: currentRule, Target: projectTarget})
					continue
				}
				if len(result.targets) == 0 {
					units = append(units, Unit{Rule: currentRule, Target: projectTarget})
					continue
				}
				for _, target := range result.targets {
					units = append(units, Unit{Rule: currentRule, Target: target})
				}
			}
		default:
			return nil, issues, fmt.Errorf("rule %q has unsupported scope %q", currentRule.ID, currentRule.Scope)
		}
	}

	sort.Slice(units, func(i, j int) bool {
		if units[i].Rule.ID != units[j].Rule.ID {
			return units[i].Rule.ID < units[j].Rule.ID
		}
		return units[i].Target.Key < units[j].Target.Key
	})
	if resolvedProjects == 0 {
		return units, issues, errors.New("all projects could not be resolved")
	}
	return units, issues, nil
}

func issueDetail(errs ...error) string {
	var detail string
	for _, err := range errs {
		if err == nil {
			continue
		}
		if detail != "" {
			detail += "; "
		}
		detail += err.Error()
	}
	return detail
}

func clusterLocation(value any) (string, string, error) {
	cluster, ok := value.(map[string]any)
	if !ok {
		return "", "", errors.New("cluster entry is not an object")
	}
	name, _ := cluster["name"].(string)
	location, _ := cluster["location"].(string)
	if location == "" {
		location, _ = cluster["zone"].(string)
	}
	if name == "" || location == "" {
		return "", "", errors.New("cluster entry is missing name or location")
	}
	return name, location, nil
}
