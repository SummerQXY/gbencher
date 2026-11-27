package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/SummerQXY/gbencher/internal/auth"
	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/engine"
	"github.com/SummerQXY/gbencher/internal/redact"
	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/spf13/cobra"
)

type authCheckFlags struct {
	projects                                   []string
	enables                                    []string
	format, account, impersonate, quotaProject string
}

type authCheckReport struct {
	Gcloud   authCheckGcloud    `json:"gcloud"`
	Identity authCheckIdentity  `json:"identity"`
	Projects []authCheckProject `json:"projects"`
	Kubectl  authCheckKubectl   `json:"kubectl"`
}

type authCheckGcloud struct {
	Found   bool   `json:"found"`
	Version string `json:"version"`
}

type authCheckIdentity struct {
	Account      string  `json:"account"`
	Impersonated *string `json:"impersonated"`
	QuotaProject *string `json:"quota_project"`
}

type authCheckProject struct {
	ID               string `json:"id"`
	OK               bool   `json:"ok"`
	Number           string `json:"number"`
	Organization     string `json:"organization"`
	ServicesReadable bool   `json:"services_readable"`
	QuotaUseOK       *bool  `json:"quota_use_ok"`
}

type authCheckKubectl struct {
	Found        bool                    `json:"found"`
	Version      string                  `json:"version,omitempty"`
	VersionError string                  `json:"version_error,omitempty"`
	Clusters     []authCheckClusterProbe `json:"clusters,omitempty"`
}

type authCheckClusterProbe struct {
	Project  string `json:"project"`
	Name     string `json:"name"`
	Location string `json:"location"`
	Outcome  string `json:"outcome"`
	Reason   string `json:"reason,omitempty"`
	Error    string `json:"error,omitempty"`
}

type authCheckRunner struct{ runner collect.Runner }

func (r authCheckRunner) Run(ctx context.Context, command collect.Exec, limits collect.Limits) (collect.Output, error) {
	if limits.Timeout <= 0 {
		limits.Timeout = 120 * time.Second
	}
	if limits.MaxOutput <= 0 {
		limits.MaxOutput = 64 << 20
	}
	return r.runner.Run(ctx, command, limits)
}

func authCmd(stdout, stderr io.Writer, env []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Check cloud authentication and access",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	f := authCheckFlags{}
	check := &cobra.Command{
		Use:   "check",
		Short: "Check credentials, project access and quota project",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			code := runAuthCheck(cmd.Context(), f, stdout, stderr, env)
			if code != 0 {
				return &exitError{code: code}
			}
			return nil
		},
	}
	flags := check.Flags()
	flags.StringArrayVar(&f.projects, "project", nil, "Project ID to check (repeatable)")
	flags.StringVar(&f.format, "format", "table", "Output format: table or json")
	flags.StringVar(&f.account, "account", "", "gcloud account")
	flags.StringVar(&f.impersonate, "impersonate-service-account", "", "Service account to impersonate")
	flags.StringVar(&f.quotaProject, "quota-project", "", "Quota project to check")
	flags.StringSliceVar(&f.enables, "enable", nil, "Enable optional checks: kubectl")
	cmd.AddCommand(check)
	return cmd
}

func runAuthCheck(parent context.Context, f authCheckFlags, stdout, stderr io.Writer, env []string) int {
	if len(f.projects) == 0 {
		return scanError(stderr, 2, "at least one --project is required", false)
	}
	if f.format != "json" && f.format != "table" {
		return scanError(stderr, 2, "--format must be table or json", false)
	}
	if err := validateList("--enable", f.enables, map[string]bool{"kubectl": true}); err != nil {
		return scanError(stderr, 2, err.Error(), false)
	}
	for _, project := range f.projects {
		if !projectIDPattern.MatchString(project) {
			return scanError(stderr, 2, fmt.Sprintf("invalid project ID %q", project), false)
		}
	}
	sort.Strings(f.projects)
	f.projects = slices.Compact(f.projects)
	if f.quotaProject != "" && !projectIDPattern.MatchString(f.quotaProject) {
		return scanError(stderr, 2, fmt.Sprintf("invalid quota project ID %q", f.quotaProject), false)
	}
	baseEnv := env
	if baseEnv == nil {
		baseEnv = os.Environ()
	}
	gcloud, err := lookPath("gcloud", baseEnv)
	if err != nil {
		return scanError(stderr, 3, "gcloud executable not found", false)
	}
	allow, err := rule.LoadAllowlist()
	if err != nil {
		return scanError(stderr, 3, "load command allowlist: "+err.Error(), false)
	}
	check := func(argv []string) error {
		return checkAuthCommand(allow, argv)
	}
	ctx := parent
	if ctx == nil {
		ctx = context.Background()
	}
	client, err := auth.Resolve(ctx, authCheckRunner{runner: collect.OSRunner{}}, gcloud, collect.ChildEnv(baseEnv, engine.GcloudEnvOverrides()), check, auth.Options{
		Account: f.account, Impersonate: f.impersonate, QuotaProject: f.quotaProject,
	})
	if err != nil {
		return scanError(stderr, 3, "gcloud authentication check: "+redact.String(err.Error()), false)
	}
	account := client.Identity.Account
	report := authCheckReport{
		Gcloud:   authCheckGcloud{Found: true, Version: client.Version},
		Identity: authCheckIdentity{Account: account},
		Projects: make([]authCheckProject, 0, len(f.projects)),
	}
	if f.impersonate != "" {
		value := f.impersonate
		report.Identity.Impersonated = &value
	}
	if f.quotaProject != "" {
		value := f.quotaProject
		report.Identity.QuotaProject = &value
	}
	failed := false
	for _, project := range f.projects {
		item := authCheckProject{ID: project}
		var projectErr error
		item.Number, projectErr = client.ProjectNumber(ctx, project)
		firstErr := projectErr
		orgID, _, ancestorsErr := client.Ancestors(ctx, project)
		item.Organization = orgID
		if firstErr == nil {
			firstErr = ancestorsErr
		}
		_, servicesErr := client.EnabledServices(ctx, project)
		item.ServicesReadable = servicesErr == nil
		if firstErr == nil {
			firstErr = servicesErr
		}
		quotaOK := true
		if f.quotaProject != "" {
			quotaOK = false
			quotaArgv := []string{"logging", "metrics", "list", "--project=" + project, "--limit=1", "--format=json"}
			quotaErr := checkAuthCommand(allow, quotaArgv)
			var quotaOut collect.Output
			if quotaErr == nil {
				quotaOut, quotaErr = client.Run(ctx, quotaArgv, collect.Limits{})
			}
			if quotaErr == nil {
				_, quotaErr = collect.DecodeJSON(quotaOut.Stdout)
			}
			quotaOK = quotaErr == nil
			item.QuotaUseOK = &quotaOK
			if quotaErr != nil && firstErr == nil {
				firstErr = quotaErr
			}
		}
		item.OK = projectErr == nil && ancestorsErr == nil && servicesErr == nil && quotaOK
		if !item.OK {
			failed = true
			if firstErr != nil {
				fmt.Fprintf(stderr, "auth check: project %s: %s\n", project, redact.StripControl(redact.String(firstErr.Error())))
			} else {
				fmt.Fprintf(stderr, "auth check: project %s: enabled services are not readable\n", project)
			}
		}
		report.Projects = append(report.Projects, item)
	}
	kubectlPath, kubectlPathErr := lookPath("kubectl", baseEnv)
	if kubectlPathErr == nil {
		report.Kubectl.Found = true
		out, runErr := (authCheckRunner{runner: collect.OSRunner{}}).Run(ctx, collect.Exec{Path: kubectlPath, Argv: []string{"version", "--client", "-o", "json"}, Env: collect.ChildEnv(baseEnv, nil)}, collect.Limits{})
		if versionErr := kubectlVersionError(out, runErr); versionErr != "" {
			report.Kubectl.VersionError = versionErr
		} else {
			var version struct {
				ClientVersion struct {
					GitVersion string `json:"gitVersion"`
				} `json:"clientVersion"`
			}
			if err := json.Unmarshal(out.Stdout, &version); err != nil {
				report.Kubectl.VersionError = "kubectl version output is invalid JSON"
			} else if version.ClientVersion.GitVersion == "" {
				report.Kubectl.VersionError = "kubectl version output has no clientVersion.gitVersion"
			} else {
				report.Kubectl.Version = version.ClientVersion.GitVersion
			}
		}
	}
	if slices.Contains(f.enables, "kubectl") {
		if kubectlPathErr != nil {
			report.Kubectl.VersionError = "kubectl executable not found"
			failed = true
		} else {
			executable, executableErr := os.Executable()
			manager, managerErr := auth.NewKubeconfigManager(ctx, executable, client.Identity)
			if executableErr != nil || managerErr != nil {
				failed = true
				report.Kubectl.VersionError = "Kubernetes probe configuration is unavailable"
			} else {
				defer func() { _ = manager.Close() }()
				for _, project := range f.projects {
					clusters, clustersErr := client.Clusters(ctx, project)
					if clustersErr != nil {
						failed = true
						report.Kubectl.Clusters = append(report.Kubectl.Clusters, authCheckClusterProbe{Project: project, Outcome: "error", Error: "cluster inventory could not be read"})
						continue
					}
					for _, cluster := range clusters {
						name, location := authCheckClusterIdentity(cluster)
						key := project + "/" + location + "/" + name
						result := engine.ProbeCluster(ctx, collect.OSRunner{}, kubectlPath, collect.ChildEnv(baseEnv, nil), manager, key, cluster)
						report.Kubectl.Clusters = append(report.Kubectl.Clusters, authCheckClusterProbe{Project: project, Name: name, Location: location, Outcome: result.Outcome, Reason: result.Reason, Error: result.Error})
						if result.Outcome != "reachable" {
							failed = true
						}
					}
				}
			}
		}
	}
	if f.format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(report); err != nil {
			return scanError(stderr, 3, "write auth check output: "+err.Error(), false)
		}
	} else {
		writeAuthCheckTable(stdout, report)
	}
	if failed {
		return 1
	}
	return 0
}

func authCheckClusterIdentity(value any) (string, string) {
	cluster, ok := value.(map[string]any)
	if !ok {
		return "", ""
	}
	name, _ := cluster["name"].(string)
	location, _ := cluster["location"].(string)
	if location == "" {
		location, _ = cluster["zone"].(string)
	}
	return name, location
}

func kubectlVersionError(out collect.Output, runErr error) string {
	switch {
	case runErr != nil:
		return "kubectl version command could not run"
	case out.TimedOut:
		return "kubectl version command timed out"
	case out.Truncated:
		return "kubectl version output exceeded the size limit"
	case out.ExitCode != 0:
		return "kubectl version command failed"
	}
	return ""
}

func checkAuthCommand(allow *rule.Allowlist, argv []string) error {
	entry, rest, ok := allow.MatchGcloud(argv, true)
	if !ok {
		return fmt.Errorf("engine command is not in the embedded allowlist")
	}
	if slices.Contains(entry.Bind, rule.BindNone) {
		return nil
	}
	if !slices.Contains(entry.Bind, rule.BindProject) {
		return fmt.Errorf("engine command has no project binding")
	}
	project := ""
	for _, arg := range rest {
		if value, found := strings.CutPrefix(arg, "--project="); found {
			project = value
			break
		}
	}
	if project == "" && len(entry.Path) > 1 && entry.Path[0] == "projects" && len(rest) > 0 {
		project = rest[0]
	}
	if project == "" {
		return fmt.Errorf("engine command is not bound to a project")
	}
	return nil
}

func writeAuthCheckTable(w io.Writer, report authCheckReport) {
	fmt.Fprintf(w, "gcloud\t%t\t%s\n", report.Gcloud.Found, authCheckTableText(report.Gcloud.Version))
	fmt.Fprintf(w, "account\t%s\n", authCheckTableText(report.Identity.Account))
	fmt.Fprintf(w, "project\tok\tnumber\torganization\tservices_readable\tquota_use_ok\n")
	for _, project := range report.Projects {
		quota := "n/a"
		if project.QuotaUseOK != nil {
			quota = fmt.Sprint(*project.QuotaUseOK)
		}
		fmt.Fprintf(w, "%s\t%t\t%s\t%s\t%t\t%s\n", authCheckTableText(project.ID), project.OK, authCheckTableText(project.Number), authCheckTableText(project.Organization), project.ServicesReadable, authCheckTableText(quota))
	}
	fmt.Fprintf(w, "kubectl\t%t\t%s\t%s\n", report.Kubectl.Found, authCheckTableText(report.Kubectl.Version), authCheckTableText(report.Kubectl.VersionError))
	for _, cluster := range report.Kubectl.Clusters {
		fmt.Fprintf(w, "cluster\t%s\t%s\t%s\t%s\n", authCheckTableText(cluster.Project), authCheckTableText(cluster.Name), authCheckTableText(cluster.Outcome), authCheckTableText(cluster.Reason))
	}
}

func authCheckTableText(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r == '\v' || r == '\f' || r == '\u0085' || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return ' '
		}
		return r
	}, value)
	return redact.StripControl(value)
}
