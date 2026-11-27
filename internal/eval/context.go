package eval

import "time"

// Context contains target metadata used by CEL expressions and command templates.
type Context struct {
	Project, ProjectNumber, Organization, OrganizationDomain, Folder, Account string
	Cluster                                                                   any
	Now                                                                       time.Time
	TargetKey, TargetKind                                                     string
}

// CELMap returns the eight context fields exposed to CEL.
func (c Context) CELMap() map[string]any {
	return map[string]any{
		"project":             c.Project,
		"project_number":      c.ProjectNumber,
		"organization":        c.Organization,
		"organization_domain": c.OrganizationDomain,
		"folder":              c.Folder,
		"account":             c.Account,
		"cluster":             c.Cluster,
		"now":                 c.Now,
	}
}

// Vars returns target, parameter, and foreach variables used by command templates.
func (c Context) Vars(params map[string]any, extra map[string]any) map[string]any {
	vars := map[string]any{
		"project":        c.Project,
		"project_number": c.ProjectNumber,
		"organization":   c.Organization,
		"folder":         c.Folder,
		"cluster":        c.Cluster,
		"params":         params,
	}
	for key, value := range extra {
		vars[key] = value
	}
	return vars
}
