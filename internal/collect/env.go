// Package collect provides a subprocess runner that executes an external
// command with a timeout, output length limits, and process-group cleanup.
//
// It also exposes ChildEnv, which filters the parent environment to a
// whitelist of variables that gcloud needs at runtime, plus common shell and
// locale variables, dropping every other variable including secret-bearing
// ones like GOOGLE_APPLICATION_CREDENTIALS and unchecked CLOUDSDK_* entries.
package collect

import (
	"sort"
	"strings"
)

// ChildEnv filters base environment variables to a closed whitelist and then
// applies overrides. The whitelist is: PATH, HOME, USER, LOGNAME, LANG, any
// name with the prefix LC_, TZ, TMPDIR, SSL_CERT_FILE, SSL_CERT_DIR,
// HTTP_PROXY, HTTPS_PROXY, NO_PROXY and their lower-case forms, plus the
// CLOUDSDK_ variables that are explicitly known to affect gcloud behaviour:
// CLOUDSDK_CONFIG, CLOUDSDK_PYTHON, CLOUDSDK_PYTHON_ARGS,
// CLOUDSDK_PYTHON_SITEPACKAGES, CLOUDSDK_ENCODING. Every other CLOUDSDK_*
// variable and GOOGLE_APPLICATION_CREDENTIALS are dropped. Overrides are
// applied last and always win. The returned slice is sorted by variable name.
func ChildEnv(base []string, overrides map[string]string) []string {
	kept := make(map[string]string)
	for _, kv := range base {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if keepEnvName(k) {
			kept[k] = v
		}
	}
	for k, v := range overrides {
		kept[k] = v
	}
	result := make([]string, 0, len(kept))
	for k, v := range kept {
		result = append(result, k+"="+v)
	}
	sort.Strings(result)
	return result
}

// keepEnvName reports whether the environment variable name is in the
// whitelist of variables that may be passed to a gcloud subprocess.
func keepEnvName(name string) bool {
	switch name {
	// Common shell and locale variables.
	case "PATH", "HOME", "USER", "LOGNAME", "LANG", "TZ", "TMPDIR":
		return true
	// TLS certificate paths.
	case "SSL_CERT_FILE", "SSL_CERT_DIR":
		return true
	// Proxy variables (upper and lower case).
	case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
		"http_proxy", "https_proxy", "no_proxy":
		return true
	// CLOUDSDK_ variables that are explicitly allowed.
	case "CLOUDSDK_CONFIG", "CLOUDSDK_PYTHON", "CLOUDSDK_PYTHON_ARGS",
		"CLOUDSDK_PYTHON_SITEPACKAGES", "CLOUDSDK_ENCODING":
		return true
	default:
		// LC_ALL, LC_CTYPE, LC_MESSAGES, etc.
		return strings.HasPrefix(name, "LC_")
	}
}
