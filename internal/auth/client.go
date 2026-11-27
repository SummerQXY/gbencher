package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/SummerQXY/gbencher/internal/collect"
	"github.com/SummerQXY/gbencher/internal/failure"
	"github.com/SummerQXY/gbencher/internal/redact"
)

const tokenTTL = 50 * time.Minute

type Options struct {
	Account      string
	Impersonate  string
	QuotaProject string
}

type Check func(argv []string) error

type Client struct {
	Gcloud   string
	Identity Options
	Version  string
	Env      []string

	runner collect.Runner
	check  Check

	mu         sync.Mutex
	token      string
	tokenUntil time.Time
	now        func() time.Time
}

func Resolve(ctx context.Context, r collect.Runner, gcloud string, env []string, check Check, o Options) (*Client, error) {
	c := &Client{
		Gcloud:   gcloud,
		Identity: o,
		Env:      append([]string(nil), env...),
		runner:   r,
		check:    check,
		now:      time.Now,
	}
	versionOut, err := c.runUnpinned(ctx, []string{"--version"})
	if err != nil {
		return nil, err
	}
	version, err := firstVersionLine(versionOut.Stdout)
	if err != nil {
		return nil, err
	}
	c.Version = version
	if c.Identity.Account == "" {
		accountOut, err := c.runUnpinned(ctx, []string{"config", "get", "account"})
		if err != nil {
			return nil, err
		}
		c.Identity.Account = strings.TrimSpace(string(accountOut.Stdout))
		if c.Identity.Account == "" {
			return nil, fmt.Errorf("no configured gcloud account; run gcloud auth login")
		}
	}
	return c, nil
}

func (c *Client) CommonArgs() []string {
	args := []string{"--quiet"}
	if c.Identity.Account != "" {
		args = append(args, "--account="+c.Identity.Account)
	}
	if c.Identity.Impersonate != "" {
		args = append(args, "--impersonate-service-account="+c.Identity.Impersonate)
	}
	if c.Identity.QuotaProject != "" {
		args = append(args, "--billing-project="+c.Identity.QuotaProject)
	}
	return args
}

func (c *Client) Run(ctx context.Context, argv []string, l collect.Limits) (collect.Output, error) {
	fullArgv := append(append([]string(nil), argv...), c.CommonArgs()...)
	out, err := c.runner.Run(ctx, collect.Exec{
		Path: c.Gcloud,
		Argv: fullArgv,
		Env:  append([]string(nil), c.Env...),
	}, l)
	if err != nil {
		return out, err
	}
	if classified := collect.ClassifyGcloud(out); classified != nil {
		return out, classified
	}
	return out, nil
}

func (c *Client) Account(ctx context.Context) (string, error) {
	out, err := c.runInternal(ctx, []string{"config", "get", "account"})
	if err != nil {
		return "", err
	}
	account := strings.TrimSpace(string(out.Stdout))
	if account == "" {
		return "", fmt.Errorf("gcloud returned an empty account")
	}
	return account, nil
}

func (c *Client) ProjectNumber(ctx context.Context, project string) (string, error) {
	value, err := c.jsonCommand(ctx, []string{"projects", "describe", project, "--format=json"})
	if err != nil {
		return "", err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return "", invalidJSON("project description is not an object")
	}
	number, err := jsonString(object["projectNumber"])
	if err != nil || !isDigits(number) {
		return "", invalidJSON("project description has an invalid projectNumber")
	}
	return number, nil
}

func (c *Client) Ancestors(ctx context.Context, project string) (orgID, folderID string, err error) {
	value, err := c.jsonCommand(ctx, []string{"projects", "get-ancestors", project, "--format=json"})
	if err != nil {
		return "", "", err
	}
	ancestors, ok := value.([]any)
	if !ok {
		return "", "", invalidJSON("project ancestors are not an array")
	}
	for _, value := range ancestors {
		item, ok := value.(map[string]any)
		if !ok {
			return "", "", invalidJSON("project ancestor is not an object")
		}
		id, _ := item["id"].(string)
		kind, _ := item["type"].(string)
		switch kind {
		case "folder":
			if strings.TrimSpace(id) == "" {
				return "", "", invalidJSON("folder ancestor has no id")
			}
			if folderID == "" {
				folderID = id
			}
		case "organization":
			if strings.TrimSpace(id) == "" {
				return "", "", invalidJSON("organization ancestor has no id")
			}
			if orgID == "" {
				orgID = id
			}
		}
	}
	return orgID, folderID, nil
}

func (c *Client) OrganizationDomain(ctx context.Context, orgID string) (string, error) {
	value, err := c.jsonCommand(ctx, []string{"organizations", "describe", orgID, "--format=json"})
	if err != nil {
		return "", err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return "", invalidJSON("organization description is not an object")
	}
	domain, _ := object["displayName"].(string)
	if domain == "" {
		return "", invalidJSON("organization description has no displayName")
	}
	return domain, nil
}

func (c *Client) Clusters(ctx context.Context, project string) ([]any, error) {
	value, err := c.jsonCommand(ctx, []string{"container", "clusters", "list", "--project=" + project, "--format=json"})
	if err != nil {
		return nil, err
	}
	clusters, ok := value.([]any)
	if !ok {
		return nil, invalidJSON("cluster list is not an array")
	}
	return clusters, nil
}

func (c *Client) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.currentTime()
	if c.token != "" && now.Before(c.tokenUntil) {
		return c.token, nil
	}
	out, err := c.runInternal(ctx, []string{"auth", "print-access-token"})
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(out.Stdout))
	if token == "" {
		return "", fmt.Errorf("gcloud returned an empty access token")
	}
	c.token = token
	c.tokenUntil = c.currentTime().Add(tokenTTL)
	return token, nil
}

// InvalidateToken clears the cached credential only when it still matches the rejected token.
func (c *Client) InvalidateToken(token string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if token == "" || c.token != token {
		return false
	}
	c.token = ""
	c.tokenUntil = time.Time{}
	return true
}

func (c *Client) EnabledServices(ctx context.Context, project string) (map[string]bool, error) {
	value, err := c.jsonCommand(ctx, []string{"services", "list", "--enabled", "--project=" + project, "--format=json"})
	if err != nil {
		return nil, err
	}
	services, ok := value.([]any)
	if !ok {
		return nil, invalidJSON("enabled services are not an array")
	}
	result := make(map[string]bool, len(services))
	for _, value := range services {
		service, ok := value.(map[string]any)
		if !ok {
			return nil, invalidJSON("enabled service is not an object")
		}
		name, _ := service["serviceId"].(string)
		if name == "" {
			if config, ok := service["config"].(map[string]any); ok {
				name, _ = config["name"].(string)
			}
		}
		if strings.TrimSpace(name) == "" {
			return nil, invalidJSON("enabled service has no serviceId or config.name")
		}
		result[name] = true
	}
	return result, nil
}

func (c *Client) runInternal(ctx context.Context, argv []string) (collect.Output, error) {
	fullArgv := append([]string(nil), argv...)
	if !hasFormatFlag(fullArgv) && !isTextOutputCommand(fullArgv) {
		fullArgv = append(fullArgv, "--format=json")
	}
	if err := c.checkArgv(fullArgv); err != nil {
		return collect.Output{}, guardFailure(err)
	}
	return c.Run(ctx, fullArgv, collect.Limits{})
}

func (c *Client) jsonCommand(ctx context.Context, argv []string) (any, error) {
	out, err := c.runInternal(ctx, argv)
	if err != nil {
		return nil, err
	}
	value, err := collect.DecodeJSON(out.Stdout)
	if err != nil {
		return nil, collect.ClassifyParse(err)
	}
	return value, nil
}

func (c *Client) runUnpinned(ctx context.Context, argv []string) (collect.Output, error) {
	if err := c.checkArgv(argv); err != nil {
		return collect.Output{}, guardFailure(err)
	}
	out, err := c.runner.Run(ctx, collect.Exec{
		Path: c.Gcloud,
		Argv: append([]string(nil), argv...),
		Env:  append([]string(nil), c.Env...),
	}, collect.Limits{})
	if err != nil {
		return out, err
	}
	if classified := collect.ClassifyGcloud(out); classified != nil {
		return out, classified
	}
	return out, nil
}

func (c *Client) checkArgv(argv []string) error {
	if c.check == nil {
		return nil
	}
	return c.check(append([]string(nil), argv...))
}

func (c *Client) currentTime() time.Time {
	if c.now == nil {
		return time.Now()
	}
	return c.now()
}

func firstVersionLine(output []byte) (string, error) {
	lines := strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n")
	if len(lines) > 0 {
		fields := strings.Fields(strings.TrimSpace(lines[0]))
		if len(fields) == 4 && fields[0] == "Google" && fields[1] == "Cloud" && fields[2] == "SDK" && isVersion(fields[3]) {
			return fields[3], nil
		}
	}
	return "", fmt.Errorf("gcloud --version output has no Google Cloud SDK version")
}

func isVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if !isDigits(part) {
			return false
		}
	}
	return true
}

func guardFailure(err error) *failure.Failure {
	message := redact.StripControl(err.Error())
	message = redact.StripControl(redact.String(message))
	runes := []rune(message)
	if len(runes) > 500 {
		message = string(runes[:500])
	}
	return &failure.Failure{Class: failure.GuardRejected, Summary: message}
}

func hasFormatFlag(argv []string) bool {
	for _, arg := range argv {
		if arg == "--format" || strings.HasPrefix(arg, "--format=") {
			return true
		}
	}
	return false
}

func isTextOutputCommand(argv []string) bool {
	return strings.Join(argv, " ") == "config get account" || strings.Join(argv, " ") == "auth print-access-token"
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
