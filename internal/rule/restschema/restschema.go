package restschema

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/testdata/schemas"
)

// Result contains endpoint errors, advisory paths, and rules whose fields are fully checked.
type Result struct {
	Errors    []string
	Warnings  []string
	Endpoints map[string]bool
	StaticOK  map[string]bool
}

type schemaFile struct {
	Source    string                                `json:"source"`
	Version   string                                `json:"version"`
	Resources map[string]resourceSchema             `json:"resources"`
	Schemas   map[string]map[string]json.RawMessage `json:"schemas"`
}

type resourceSchema struct {
	HTTPMethod string                     `json:"httpMethod"`
	Response   map[string]json.RawMessage `json:"response"`
	Parameters map[string]parameterSchema `json:"parameters"`
}

type parameterSchema struct {
	Location string   `json:"location"`
	Type     string   `json:"type"`
	Enum     []string `json:"enum"`
}

var pathPattern = regexp.MustCompile(`(?:r|data\.[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*)(?:\.\??[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])*`)
var selectorPattern = regexp.MustCompile(`\.\??([A-Za-z_][A-Za-z0-9_]*)`)
var indexPattern = regexp.MustCompile(`\[[^\]]*\]`)
var macroVariablePattern = regexp.MustCompile(`\.(?:exists|all|filter|map)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,`)

func Check(set *rule.Set) Result {
	out := Result{Endpoints: map[string]bool{}, StaticOK: map[string]bool{}}
	if set == nil {
		out.Errors = append(out.Errors, "rule set is required")
		return out
	}
	corpus, err := loadSchemas()
	if err != nil {
		out.Errors = append(out.Errors, err.Error())
		return out
	}
	for _, current := range set.Rules {
		if current == nil {
			continue
		}
		apiCount := 0
		ok := true
		for _, step := range current.Collect {
			if step.API == nil {
				continue
			}
			apiCount++
			if err := checkEndpoint(step.API, corpus); err != nil {
				out.Errors = append(out.Errors, fmt.Sprintf("%s collect.%s: %v", current.ID, step.ID, err))
				ok = false
				continue
			}
			out.Endpoints[current.ID] = true
		}
		if apiCount == 0 {
			continue
		}
		if !strings.HasPrefix(current.ID, "cis-gcp-7.") {
			continue
		}
		for _, expression := range ruleExpressions(current) {
			unknown, unresolved := inspectExpression(current, expression, corpus)
			for _, item := range unknown {
				out.Errors = append(out.Errors, fmt.Sprintf("%s CEL path %s does not exist in the pinned API schema", current.ID, item))
				ok = false
			}
			for _, item := range unresolved {
				out.Warnings = append(out.Warnings, fmt.Sprintf("%s CEL path %s could not be statically resolved", current.ID, item))
				ok = false
			}
		}
		if ok {
			out.StaticOK[current.ID] = true
		}
	}
	sort.Strings(out.Errors)
	sort.Strings(out.Warnings)
	return out
}

func loadSchemas() (map[string]*schemaFile, error) {
	files := map[string]string{"bigquery.googleapis.com": "bigquery-v2.json", "dlp.googleapis.com": "dlp-v2.json", "admin.googleapis.com": "admin-directory-v1.json"}
	out := make(map[string]*schemaFile, len(files))
	for host, name := range files {
		data, err := fs.ReadFile(schemas.FS, name)
		if err != nil {
			return nil, fmt.Errorf("read pinned schema %s: %w", name, err)
		}
		var parsed schemaFile
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, fmt.Errorf("parse pinned schema %s: %w", name, err)
		}
		if parsed.Source == "" || parsed.Version == "" || len(parsed.Resources) == 0 || len(parsed.Schemas) == 0 {
			return nil, fmt.Errorf("pinned schema %s is missing source metadata or definitions", name)
		}
		out[host] = &parsed
	}
	return out, nil
}

func checkEndpoint(api *rule.APIStep, corpus map[string]*schemaFile) error {
	u, err := url.Parse(api.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Fragment != "" {
		return fmt.Errorf("invalid HTTPS endpoint URL")
	}
	service, ok := corpus[u.Host]
	if !ok {
		return fmt.Errorf("host %q has no pinned API schema", u.Host)
	}
	path := strings.TrimSuffix(u.Path, "/")
	methodName := ""
	switch u.Host {
	case "bigquery.googleapis.com":
		switch path {
		case "/bigquery/v2/projects/{{ .project }}/datasets":
			methodName = "datasets.list"
		case "/bigquery/v2/projects/{{ .project }}/datasets/{{ .ds.datasetReference.datasetId }}":
			methodName = "datasets.get"
		case "/bigquery/v2/projects/{{ .project }}/datasets/{{ .ds.datasetReference.datasetId }}/tables":
			methodName = "tables.list"
		case "/bigquery/v2/projects/{{ .project }}/datasets/{{ .t.tableReference.datasetId }}/tables/{{ .t.tableReference.tableId }}":
			methodName = "tables.get"
		}
	case "dlp.googleapis.com":
		if path == "/v2/projects/{{ .project }}/locations/global/discoveryConfigs" {
			methodName = "projects.locations.discoveryConfigs.list"
		}
	case "admin.googleapis.com":
		if path == "/admin/directory/v1/users" {
			methodName = "users.list"
		}
	}
	method, ok := service.Resources[methodName]
	if !ok || methodName == "" {
		return fmt.Errorf("path %q is not a documented endpoint in the pinned schema", path)
	}
	if api.Method != method.HTTPMethod {
		return fmt.Errorf("method %q is not documented for %s", api.Method, methodName)
	}
	for key, values := range u.Query() {
		parameter, ok := method.Parameters[key]
		if !ok || parameter.Location != "query" || len(values) != 1 {
			return fmt.Errorf("query parameter %q is not documented for %s", key, methodName)
		}
		if err := validateParameterValue(key, values[0], parameter); err != nil {
			return fmt.Errorf("query parameter %q for %s: %w", key, methodName, err)
		}
	}
	return nil
}

func validateParameterValue(name, value string, parameter parameterSchema) error {
	if len(parameter.Enum) > 0 {
		for _, allowed := range parameter.Enum {
			if value == allowed {
				return nil
			}
		}
		return fmt.Errorf("value %q is not in the documented enum", value)
	}
	switch parameter.Type {
	case "boolean":
		if value != "true" && value != "false" {
			return fmt.Errorf("value %q is not a boolean", value)
		}
	case "integer":
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			return fmt.Errorf("value %q is not an integer", value)
		}
	case "number":
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			return fmt.Errorf("value %q is not a number", value)
		}
	case "string":
		return nil
	default:
		return fmt.Errorf("parameter %s has unsupported pinned type %q", name, parameter.Type)
	}
	return nil
}

func ruleExpressions(r *rule.Rule) []string {
	var out []string
	for _, step := range r.Collect {
		if step.API != nil && step.Foreach != "" {
			out = append(out, step.Foreach)
		}
	}
	if r.Resource != nil {
		out = append(out, r.Resource.Filter, r.Resource.Name)
	}
	out = append(out, r.Check.Assert, r.Check.ReviewWhen)
	out = append(out, r.Evidence...)
	return out
}

func inspectExpression(r *rule.Rule, expression string, corpus map[string]*schemaFile) ([]string, []string) {
	var unknown, unresolved []string
	if strings.TrimSpace(expression) == "" {
		return nil, nil
	}
	clean := stripStringLiterals(expression)
	macroVariables := make(map[string]bool)
	for _, match := range macroVariablePattern.FindAllStringSubmatch(clean, -1) {
		macroVariables[match[1]] = true
	}
	for _, candidate := range pathPattern.FindAllString(clean, -1) {
		root, path, ok := splitPath(candidate)
		if !ok {
			continue
		}
		typ, tracked := expressionRootType(r, root, corpus)
		if !tracked {
			if macroVariables[root] || strings.HasPrefix(root, "data.") {
				unresolved = append(unresolved, candidate)
			}
			continue
		}
		if len(path) == 0 {
			continue
		}
		for _, field := range path {
			if field == "orValue" || field == "map" || field == "filter" || field == "exists" || field == "all" || field == "flatten" || field == "contains" || field == "startsWith" || field == "endsWith" {
				continue
			}
			var found bool
			typ, found = resolveField(typ, field, corpus)
			if !found {
				unknown = append(unknown, candidate)
				break
			}
		}
	}
	return unique(unknown), unique(unresolved)
}

func expressionRootType(r *rule.Rule, root string, corpus map[string]*schemaFile) (string, bool) {
	if root == "r" && r.Resource != nil {
		switch r.Resource.Kind {
		case "bigquery.googleapis.com/Dataset":
			return "Dataset", true
		case "bigquery.googleapis.com/Table":
			return "Table", true
		}
	}
	if strings.HasPrefix(root, "data.") {
		stepID := strings.TrimPrefix(root, "data.")
		for _, step := range r.Collect {
			if step.ID != stepID || step.API == nil {
				continue
			}
			switch {
			case strings.Contains(step.API.URL, "bigquery.googleapis.com") && strings.HasSuffix(step.API.URL, "/datasets?all=true"):
				return "DatasetList_DatasetsItem", true
			case strings.Contains(step.API.URL, "bigquery.googleapis.com") && strings.HasSuffix(step.API.URL, "/tables"):
				return "TableList_TablesItem", true
			case strings.Contains(step.API.URL, "bigquery.googleapis.com"):
				return "Table", true
			case strings.Contains(step.API.URL, "dlp.googleapis.com"):
				return "GooglePrivacyDlpV2DiscoveryConfig", true
			}
		}
	}
	if strings.Contains(r.ID, "7.4") {
		known := map[string]string{"d": "DatasetList_DatasetsItem", "t": "TableList_TablesItem", "f": "TableFieldSchema", "sf": "TableFieldSchema", "c": "GooglePrivacyDlpV2DiscoveryConfig", "tg": "GooglePrivacyDlpV2DiscoveryTarget"}
		if root == "t" {
			for _, expression := range ruleExpressions(r) {
				if strings.Contains(expression, "data.table_details.exists(t,") {
					return "Table", true
				}
			}
		}
		if typ, ok := known[root]; ok {
			return typ, true
		}
	}
	if strings.Contains(r.ID, "7.") {
		known := map[string]string{"a": "Dataset_AccessItem", "d": "DatasetList_DatasetsItem", "t": "TableList_TablesItem", "f": "TableFieldSchema", "sf": "TableFieldSchema"}
		if typ, ok := known[root]; ok {
			return typ, true
		}
	}
	return "", false
}

func resolveField(typ, field string, corpus map[string]*schemaFile) (string, bool) {
	for _, service := range corpus {
		if fields, ok := service.Schemas[typ]; ok {
			raw, exists := fields[field]
			if !exists {
				return "", false
			}
			var value map[string]json.RawMessage
			if json.Unmarshal(raw, &value) == nil {
				for key, ref := range value {
					if key == "$ref" || key == "$array" {
						var target string
						if json.Unmarshal(ref, &target) == nil {
							return target, true
						}
					}
				}
			}
			return "", true
		}
	}
	return "", false
}

func splitPath(candidate string) (string, []string, bool) {
	rootEnd := strings.IndexByte(candidate, '.')
	bracket := strings.IndexByte(candidate, '[')
	if rootEnd < 0 || (bracket >= 0 && bracket < rootEnd) {
		return "", nil, false
	}
	root := candidate[:rootEnd]
	if root == "data" {
		nextDot := strings.IndexByte(candidate[rootEnd+1:], '.')
		if nextDot < 0 {
			return "", nil, false
		}
		rootEnd += nextDot + 1
		root = candidate[:rootEnd]
	}
	var path []string
	selectors := indexPattern.ReplaceAllString(candidate[rootEnd:], "")
	for _, match := range selectorPattern.FindAllStringSubmatch(selectors, -1) {
		path = append(path, match[1])
	}
	return root, path, true
}

func stripStringLiterals(value string) string {
	var out strings.Builder
	quote := rune(0)
	escaped := false
	for _, current := range value {
		if quote != 0 {
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == quote {
				quote = 0
			}
			out.WriteByte(' ')
			continue
		}
		if current == '\'' || current == '"' {
			quote = current
			out.WriteByte(' ')
			continue
		}
		out.WriteRune(current)
	}
	return out.String()
}

func unique(values []string) []string {
	seen := make(map[string]bool, len(values))
	var out []string
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
