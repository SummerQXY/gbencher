// Package profiles embeds the default scan profile.
package profiles

import _ "embed"

// Default is the profile a scan uses when none is named.
//
//go:embed default.yaml
var Default []byte
