package engine

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/SummerQXY/gbencher/internal/failure"
	"github.com/SummerQXY/gbencher/internal/rule"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var workspaceReadOnlyScopes = map[string]bool{
	"https://www.googleapis.com/auth/admin.directory.user.readonly":  true,
	"https://www.googleapis.com/auth/cloud-identity.groups.readonly": true,
}

type WorkspaceTokenSource interface {
	Account() string
	Token(context.Context) (string, error)
	InvalidateToken(string) bool
}

type workspaceAuthManager struct {
	factory  func(context.Context, []string) (WorkspaceTokenSource, error)
	expected string
	mu       sync.Mutex
	sources  map[string]WorkspaceTokenSource
	account  string
}

func newWorkspaceAuthManager(factory func(context.Context, []string) (WorkspaceTokenSource, error), expected string) *workspaceAuthManager {
	if factory == nil {
		factory = defaultWorkspaceADC
	}
	return &workspaceAuthManager{factory: factory, expected: expected, sources: map[string]WorkspaceTokenSource{}}
}

func (m *workspaceAuthManager) Source(ctx context.Context, declared []string) (WorkspaceTokenSource, error) {
	scopes := allowedWorkspaceScopes(declared)
	if len(scopes) == 0 {
		return nil, &failure.Failure{Class: failure.Permission, Summary: "Workspace rule declares no permitted read-only scope"}
	}
	key := workspaceScopeKey(scopes)
	m.mu.Lock()
	defer m.mu.Unlock()
	if source := m.sources[key]; source != nil {
		return source, nil
	}
	source, err := m.factory(ctx, scopes)
	if err != nil || source == nil {
		return nil, &failure.Failure{Class: failure.Permission, Summary: "Workspace application default credentials are unavailable"}
	}
	account := strings.TrimSpace(source.Account())
	if account == "" {
		return nil, &failure.Failure{Class: failure.Permission, Summary: "Workspace application default credential identity cannot be verified"}
	}
	if m.expected != "" && account != m.expected {
		return nil, &failure.Failure{Class: failure.Permission, Summary: "Workspace application default identity does not match the explicitly selected account"}
	}
	if m.account != "" && account != m.account {
		return nil, &failure.Failure{Class: failure.Permission, Summary: "Workspace application default identities do not match"}
	}
	m.account = account
	m.sources[key] = source
	return source, nil
}

func (m *workspaceAuthManager) Account() *string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.account == "" {
		return nil
	}
	account := m.account
	return &account
}

type workspaceCredentials struct {
	account string
	source  oauth2.TokenSource
	refresh func(context.Context) (oauth2.TokenSource, error)
	mu      sync.Mutex
}

func (c *workspaceCredentials) Account() string { return c.account }
func (c *workspaceCredentials) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.source == nil {
		source, err := c.refresh(ctx)
		if err != nil {
			return "", err
		}
		c.source = source
	}
	token, err := c.source.Token()
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}
func (c *workspaceCredentials) InvalidateToken(string) bool {
	c.mu.Lock()
	c.source = nil
	c.mu.Unlock()
	return true
}

func defaultWorkspaceADC(ctx context.Context, scopes []string) (WorkspaceTokenSource, error) {
	credentials, err := google.FindDefaultCredentials(ctx, scopes...)
	if err != nil {
		return nil, errors.New("application default credentials are unavailable")
	}
	var document struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
	}
	if err := json.Unmarshal(credentials.JSON, &document); err != nil || document.Type != "service_account" || strings.TrimSpace(document.ClientEmail) == "" {
		return nil, errors.New("application default credential identity cannot be verified")
	}
	return &workspaceCredentials{account: document.ClientEmail, source: credentials.TokenSource, refresh: func(ctx context.Context) (oauth2.TokenSource, error) {
		credentials, err := google.FindDefaultCredentials(ctx, scopes...)
		if err != nil {
			return nil, errors.New("application default credentials are unavailable")
		}
		return credentials.TokenSource, nil
	}}, nil
}

func allowedWorkspaceScopes(declared []string) []string {
	allowed := map[string]bool{}
	for _, scope := range declared {
		if workspaceReadOnlyScopes[scope] {
			allowed[scope] = true
		}
	}
	out := make([]string, 0, len(allowed))
	for scope := range allowed {
		out = append(out, scope)
	}
	slices.Sort(out)
	return out
}

func workspaceScopeKey(scopes []string) string { return strings.Join(scopes, "\x00") }

func ruleRequiresWorkspace(r *rule.Rule) bool {
	if contains(r.Requires, "workspace-admin") {
		return true
	}
	for _, step := range r.Collect {
		if step.API != nil && (stepRequiresWorkspace(step, nil) || isWorkspaceAPI(step.API.URL)) {
			return true
		}
	}
	return false
}

func stepRequiresWorkspace(step rule.Step, r *rule.Rule) bool {
	return (r != nil && contains(r.Requires, "workspace-admin")) || contains(step.Requires, "workspace-admin") || (step.API != nil && (len(allowedWorkspaceScopes(step.API.Scopes)) > 0 || isWorkspaceAPI(step.API.URL)))
}

func isWorkspaceAPI(rawURL string) bool {
	return strings.HasPrefix(rawURL, "https://admin.googleapis.com/") || strings.HasPrefix(rawURL, "https://cloudidentity.googleapis.com/")
}
