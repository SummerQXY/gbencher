package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"
)

const kubeCredentialAPIVersion = "client.authentication.k8s.io/v1"

type execCredentialV1 struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Status     execCredentialV1Status `json:"status"`
}

type execCredentialV1Status struct {
	ExpirationTimestamp time.Time `json:"expirationTimestamp"`
	Token               string    `json:"token"`
}

// ExecCredentialV1 encodes a short-lived credential for kubectl's exec plugin protocol.
func ExecCredentialV1(token string, expiration time.Time) ([]byte, error) {
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("access token is empty")
	}
	if expiration.IsZero() {
		return nil, errors.New("credential expiration is required")
	}
	return json.Marshal(execCredentialV1{
		APIVersion: kubeCredentialAPIVersion,
		Kind:       "ExecCredential",
		Status: execCredentialV1Status{
			ExpirationTimestamp: expiration.UTC(),
			Token:               token,
		},
	})
}

// KubeconfigManager owns one scan's kubeconfig files and kubectl cache directory.
type KubeconfigManager struct {
	mu         sync.Mutex
	dir        string
	executable string
	identity   Options
	files      map[string]string
	closed     bool
	closeOnce  sync.Once
	closeErr   error
	stopCancel func() bool
}

// NewKubeconfigManager creates an isolated directory that is removed when ctx is canceled
// or the manager is closed.
func NewKubeconfigManager(ctx context.Context, executable string, identity Options) (*KubeconfigManager, error) {
	if ctx == nil {
		return nil, errors.New("run context is required")
	}
	if executable == "" {
		return nil, errors.New("gbench executable is required")
	}
	if err := validateIdentity(identity); err != nil {
		return nil, err
	}
	absExecutable, err := filepath.Abs(executable)
	if err != nil {
		return nil, errors.New("cannot resolve gbench executable")
	}
	dir, err := os.MkdirTemp("", "gbench-kube-")
	if err != nil {
		return nil, errors.New("cannot create Kubernetes temporary directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, errors.New("cannot secure Kubernetes temporary directory")
	}
	cacheDir := filepath.Join(dir, "cache")
	if err := os.Mkdir(cacheDir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, errors.New("cannot create Kubernetes cache directory")
	}
	manager := &KubeconfigManager{dir: dir, executable: absExecutable, identity: identity, files: make(map[string]string)}
	stopCancel := context.AfterFunc(ctx, func() { _ = manager.Close() })
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		stopCancel()
	} else {
		manager.stopCancel = stopCancel
		manager.mu.Unlock()
	}
	return manager, nil
}

// Dir returns this scan's private temporary directory.
func (m *KubeconfigManager) Dir() string {
	if m == nil {
		return ""
	}
	return m.dir
}

// CacheDir returns this scan's private kubectl cache directory.
func (m *KubeconfigManager) CacheDir() string {
	if m == nil {
		return ""
	}
	return filepath.Join(m.dir, "cache")
}

// Create writes or reuses a kubeconfig derived only from the supplied cluster description.
func (m *KubeconfigManager) Create(cluster any) (string, error) {
	if m == nil {
		return "", errors.New("Kubernetes temporary directory is unavailable")
	}
	clusterObject, ok := cluster.(map[string]any)
	if !ok {
		return "", errors.New("cluster description is invalid")
	}
	name, _ := clusterObject["name"].(string)
	location, _ := clusterObject["location"].(string)
	if location == "" {
		location, _ = clusterObject["zone"].(string)
	}
	endpoint, _ := clusterObject["endpoint"].(string)
	authData, _ := clusterObject["masterAuth"].(map[string]any)
	ca, _ := authData["clusterCaCertificate"].(string)
	server, err := kubeServerURL(endpoint)
	if err != nil || name == "" || location == "" || !validBase64(ca) {
		return "", errors.New("cluster description lacks a valid endpoint or certificate authority")
	}
	identityBytes, _ := json.Marshal([]string{name, location, server, ca, m.executable, m.identity.Account, m.identity.Impersonate, m.identity.QuotaProject})
	hash := sha256.Sum256(identityBytes)
	key := hex.EncodeToString(hash[:])

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return "", errors.New("Kubernetes temporary directory is closed")
	}
	if path := m.files[key]; path != "" {
		return path, nil
	}
	data, err := marshalKubeconfig(server, ca, m.executable, m.identity, name, location)
	if err != nil {
		return "", errors.New("cannot encode Kubernetes configuration")
	}
	path := filepath.Join(m.dir, "config-"+key+".yaml")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", errors.New("cannot create Kubernetes configuration")
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", errors.New("cannot write Kubernetes configuration")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", errors.New("cannot write Kubernetes configuration")
	}
	m.files[key] = path
	return path, nil
}

// Close removes this scan's temporary directory. It is safe to call more than once.
func (m *KubeconfigManager) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		dir := m.dir
		stopCancel := m.stopCancel
		m.mu.Unlock()
		if stopCancel != nil {
			stopCancel()
		}
		if err := os.RemoveAll(dir); err != nil {
			m.closeErr = fmt.Errorf("remove Kubernetes temporary directory: %w", err)
		}
	})
	return m.closeErr
}

type kubeconfigDocument struct {
	APIVersion     string              `yaml:"apiVersion"`
	Kind           string              `yaml:"kind"`
	Clusters       []kubeconfigCluster `yaml:"clusters"`
	Contexts       []kubeconfigContext `yaml:"contexts"`
	CurrentContext string              `yaml:"current-context"`
	Users          []kubeconfigUser    `yaml:"users"`
}

type kubeconfigCluster struct {
	Name    string               `yaml:"name"`
	Cluster kubeconfigClusterRef `yaml:"cluster"`
}

type kubeconfigClusterRef struct {
	Server                   string `yaml:"server"`
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
}

type kubeconfigContext struct {
	Name    string               `yaml:"name"`
	Context kubeconfigContextRef `yaml:"context"`
}

type kubeconfigContextRef struct {
	Cluster string `yaml:"cluster"`
	User    string `yaml:"user"`
}

type kubeconfigUser struct {
	Name string            `yaml:"name"`
	User kubeconfigUserRef `yaml:"user"`
}

type kubeconfigUserRef struct {
	Exec kubeconfigExec `yaml:"exec"`
}

type kubeconfigExec struct {
	APIVersion         string   `yaml:"apiVersion"`
	Command            string   `yaml:"command"`
	Args               []string `yaml:"args"`
	InteractiveMode    string   `yaml:"interactiveMode"`
	ProvideClusterInfo bool     `yaml:"provideClusterInfo"`
}

func marshalKubeconfig(server, ca, executable string, identity Options, clusterName, location string) ([]byte, error) {
	key := clusterName + "." + location
	args := []string{"__kube-credential", "--account=" + identity.Account}
	if identity.Impersonate != "" {
		args = append(args, "--impersonate-service-account="+identity.Impersonate)
	}
	if identity.QuotaProject != "" {
		args = append(args, "--quota-project="+identity.QuotaProject)
	}
	document := kubeconfigDocument{
		APIVersion:     "v1",
		Kind:           "Config",
		CurrentContext: key,
		Clusters: []kubeconfigCluster{{Name: key, Cluster: kubeconfigClusterRef{
			Server: server, CertificateAuthorityData: ca,
		}}},
		Contexts: []kubeconfigContext{{Name: key, Context: kubeconfigContextRef{Cluster: key, User: "gbench"}}},
		Users: []kubeconfigUser{{Name: "gbench", User: kubeconfigUserRef{Exec: kubeconfigExec{
			APIVersion: kubeCredentialAPIVersion, Command: executable, Args: args,
			InteractiveMode: "Never", ProvideClusterInfo: false,
		}}}},
	}
	return yaml.Marshal(document)
}

func kubeServerURL(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || strings.ContainsAny(endpoint, "\r\n\t ") {
		return "", errors.New("invalid Kubernetes endpoint")
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("invalid Kubernetes endpoint")
	}
	return "https://" + parsed.Host, nil
}

func validBase64(value string) bool {
	if value == "" {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(value)
	return err == nil
}

func validateIdentity(identity Options) error {
	for _, value := range []string{identity.Account, identity.Impersonate, identity.QuotaProject} {
		if strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("credential identity contains an invalid character")
		}
	}
	if strings.TrimSpace(identity.Account) == "" {
		return errors.New("credential account is required")
	}
	return nil
}
