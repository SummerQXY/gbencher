package schemas

import "embed"

// FS contains the pinned public Discovery and Kubernetes schema extracts used by offline lint.
//
//go:embed bigquery-v2.json dlp-v2.json admin-directory-v1.json kubernetes-v1.32.0.json gke-managedcertificate-v1.json container-v1-kubeconfig.json
var FS embed.FS
