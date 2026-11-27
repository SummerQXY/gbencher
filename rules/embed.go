// Package rules embeds the rule corpus and the command allowlist that ship inside the binary.
package rules

import "embed"

// FS holds the embedded files. Each baseline has its own directory, cis-<name>-<version>, with one
// YAML file per chapter. The root also contains the allowlist and verification metadata.
//
//go:embed cis-*/*.yaml allowlist.yaml verification.yaml
var FS embed.FS
