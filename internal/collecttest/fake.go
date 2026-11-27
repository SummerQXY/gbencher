// Package collecttest provides test helpers for the collect package.
package collecttest

import (
	"os"
	"path/filepath"
	"testing"
)

// FakeGcloud writes script to a temporary directory as an executable shell
// script and returns the directory path. The caller can use PathWith to add
// this directory to PATH so that the script runs in place of gcloud.
func FakeGcloud(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "gcloud")
	content := "#!/bin/sh\n" + script
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// PathWith prepends dir to the PATH environment variable.
func PathWith(dir string) string {
	path := os.Getenv("PATH")
	return dir + string(os.PathListSeparator) + path
}
