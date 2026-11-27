package plan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/SummerQXY/gbencher/internal/rule"
)

type Guard struct {
	Allow *rule.Allowlist
}

const maxPercentDecodePasses = 8

var errEncodingTooDeep = errors.New("REST URL encoding is too deeply nested")

func (g Guard) CheckGcloud(argv []string, target Target, crossProject, foreach bool) error {
	if g.Allow == nil {
		return errors.New("command not allowed: allowlist is unavailable")
	}
	entry, rest, ok := g.Allow.MatchGcloud(argv, false)
	if !ok {
		return errors.New("command not allowed")
	}
	if !bindingAllowed(entry.Bind, entry.Path, rest, target, crossProject, foreach) {
		return errors.New("command target binding does not match the unit")
	}
	for _, arg := range argv {
		if strings.HasPrefix(arg, "-") && g.Allow.ForbiddenFlag("gcloud", arg) {
			return fmt.Errorf("gcloud flag is not allowed: %s", arg)
		}
	}
	if target.Type != "organization" && !crossProject {
		for _, arg := range argv {
			for _, project := range projectReferences(arg) {
				if project != target.ProjectID {
					return fmt.Errorf("project reference %q is outside target %q", project, target.ProjectID)
				}
			}
			if arg == "--project" {
				return errors.New("--project must use the attached value form")
			}
		}
	}
	return nil
}

func bindingAllowed(binds []rule.Bind, path, rest []string, target Target, crossProject, foreach bool) bool {
	for _, bind := range binds {
		switch bind {
		case rule.BindNone:
			return true
		case rule.BindDerived:
			if foreach {
				return true
			}
		case rule.BindProject:
			if target.ProjectID == "" {
				continue
			}
			projectFlag := attachedFlag(rest, "--project")
			positional := firstPositional(rest)
			if positionalProjectArgument(path) && projectFlag != "" && positional != "" && projectFlag != positional {
				continue
			}
			if projectFlag == target.ProjectID || positional == target.ProjectID || crossProject && (projectFlag != "" || positional != "") {
				return true
			}
		case rule.BindOrganization:
			if target.Organization == "" {
				continue
			}
			if attachedFlag(rest, "--organization") == target.Organization || firstPositional(rest) == target.Organization || filterHasOrganization(rest, target.Organization) {
				return true
			}
		}
	}
	return false
}

func positionalProjectArgument(path []string) bool {
	if len(path) > 1 && path[0] == "projects" {
		return path[1] != "list"
	}
	return len(path) == 3 && path[0] == "compute" && path[1] == "project-info" && path[2] == "describe"
}

func attachedFlag(args []string, name string) string {
	for _, arg := range args {
		if strings.HasPrefix(arg, name+"=") {
			return strings.TrimPrefix(arg, name+"=")
		}
	}
	return ""
}

func firstPositional(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			return arg
		}
		if strings.Contains(arg, "=") || booleanFlag(arg) {
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			i++
		}
	}
	return ""
}

func booleanFlag(arg string) bool {
	switch arg {
	case "--quiet", "--recursive", "--all", "--flatten", "--impersonate-service-account":
		return true
	default:
		return false
	}
}

func filterHasOrganization(args []string, org string) bool {
	found := false
	for i, arg := range args {
		value := ""
		if strings.HasPrefix(arg, "--filter=") {
			value = strings.TrimPrefix(arg, "--filter=")
		} else if arg == "--filter" && i+1 < len(args) {
			value = args[i+1]
		} else {
			continue
		}
		found = true
		if !exactParentFilter(value, org) {
			return false
		}
	}
	return found
}

func exactParentFilter(value, org string) bool {
	tokens, ok := splitFilterTerms(value)
	if !ok {
		return false
	}
	found := false
	expectTerm := true
	for _, token := range tokens {
		if strings.EqualFold(token, "AND") {
			if expectTerm {
				return false
			}
			expectTerm = true
			continue
		}
		if strings.EqualFold(token, "OR") || strings.EqualFold(token, "NOT") {
			return false
		}
		field, fieldValue, valid := parseFilterTerm(token)
		if !valid {
			return false
		}
		if field == "parent.id" {
			if fieldValue != org {
				return false
			}
			found = true
		}
		expectTerm = false
	}
	return found && !expectTerm
}

func splitFilterTerms(value string) ([]string, bool) {
	terms := make([]string, 0)
	for index := 0; index < len(value); {
		for index < len(value) && filterWhitespace(value[index]) {
			index++
		}
		if index == len(value) {
			break
		}
		if value[index] == '(' || value[index] == ')' {
			return nil, false
		}
		start := index
		var quote byte
		for index < len(value) {
			current := value[index]
			if quote != 0 {
				if current == '\\' && index+1 < len(value) {
					index += 2
					continue
				}
				if current == quote {
					quote = 0
				}
				index++
				continue
			}
			if current == '\'' || current == '"' {
				quote = current
				index++
				continue
			}
			if current == '(' || current == ')' {
				return nil, false
			}
			if filterWhitespace(current) {
				break
			}
			index++
		}
		if quote != 0 {
			return nil, false
		}
		terms = append(terms, value[start:index])
	}
	return terms, len(terms) > 0
}

func parseFilterTerm(term string) (string, string, bool) {
	separator := strings.IndexByte(term, '=')
	if separator <= 0 || separator == len(term)-1 || strings.IndexByte(term[separator+1:], '=') >= 0 {
		return "", "", false
	}
	field := term[:separator]
	for index, character := range []byte(field) {
		if !filterIdentifier(character) && !(index > 0 && character == '-') {
			return "", "", false
		}
		if index == 0 && (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && character != '_' {
			return "", "", false
		}
	}
	value := term[separator+1:]
	if value[0] == '\'' || value[0] == '"' {
		quote := value[0]
		if len(value) < 2 || value[len(value)-1] != quote || strings.Contains(value[1:len(value)-1], "\\") || strings.ContainsRune(value[1:len(value)-1], rune(quote)) {
			return "", "", false
		}
		value = value[1 : len(value)-1]
	} else {
		if strings.ContainsAny(value, "'\"()|!<>,") || strings.HasPrefix(value, "-") {
			return "", "", false
		}
	}
	return field, value, value != ""
}

func filterIdentifier(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_' || value == '.'
}

func filterWhitespace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\r'
}

func projectReferences(arg string) []string {
	var projects []string
	for rest := arg; ; {
		index := strings.Index(rest, "projects/")
		if index < 0 {
			break
		}
		rest = rest[index+len("projects/"):]
		end := len(rest)
		for i, r := range rest {
			if r == '/' || r == ',' || r == ']' || r == ')' || r == '}' || r == '\'' || r == '"' || r == ' ' {
				end = i
				break
			}
		}
		if end > 0 {
			projects = append(projects, rest[:end])
		}
		if end == len(rest) {
			break
		}
		rest = rest[end:]
	}
	if strings.HasPrefix(arg, "--project=") {
		projects = append(projects, strings.TrimPrefix(arg, "--project="))
	}
	return projects
}

func organizationReferences(arg string) []string {
	var organizations []string
	for rest := arg; ; {
		index := strings.Index(rest, "organizations/")
		if index < 0 {
			break
		}
		rest = rest[index+len("organizations/"):]
		end := len(rest)
		for i, r := range rest {
			if r == '/' || r == ',' || r == ']' || r == ')' || r == '}' || r == '\'' || r == '"' || r == ' ' {
				end = i
				break
			}
		}
		if end > 0 {
			organizations = append(organizations, rest[:end])
		}
		if end == len(rest) {
			break
		}
		rest = rest[end:]
	}
	return organizations
}

func (g Guard) CheckKubectl(argv []string, target Target) error {
	if g.Allow == nil {
		return errors.New("kubectl command not allowed: allowlist is unavailable")
	}
	if len(argv) == 0 {
		return errors.New("kubectl command not allowed: missing verb")
	}
	for _, arg := range argv {
		if strings.HasPrefix(arg, "-") && g.Allow.ForbiddenFlag("kubectl", arg) {
			return fmt.Errorf("kubectl flag is not allowed: %s", arg)
		}
	}
	verb := argv[0]
	resource := ""
	for _, arg := range argv[1:] {
		if !strings.HasPrefix(arg, "-") {
			resource = strings.SplitN(arg, "/", 2)[0]
			break
		}
	}
	if !g.Allow.KubectlAllowed(verb, resource) {
		return fmt.Errorf("kubectl command is not allowed: %s", verb)
	}
	return nil
}

func (g Guard) CheckAPI(method, rawURL string, target Target) error {
	if g.Allow == nil {
		return errors.New("REST request not allowed: allowlist is unavailable")
	}
	if err := g.Allow.RESTAllowed(method, rawURL); err != nil {
		return err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("REST URL is invalid: %w", err)
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return errors.New("REST URL query has invalid encoding")
	}
	canonicalPath, err := fullyPathUnescape(u.EscapedPath())
	if err != nil {
		return errors.New("REST URL path has invalid encoding")
	}
	if strings.Count(canonicalPath, "/") > strings.Count(u.Path, "/") {
		return errors.New("REST URL path contains a multiply encoded separator")
	}
	segments := strings.Split(canonicalPath, "/")
	for _, segment := range segments {
		if segment == "." || segment == ".." {
			return errors.New("REST URL path contains a dot segment")
		}
	}
	escapedSegments := strings.Split(u.EscapedPath(), "/")
	if len(segments) != len(escapedSegments) {
		return errors.New("REST URL path contains an encoded separator")
	}
	for index := 0; index+1 < len(segments); index++ {
		reference, value := segments[index], segments[index+1]
		if strings.Contains(strings.ToLower(escapedSegments[index+1]), "%2f") {
			return errors.New("REST resource reference contains an encoded separator")
		}
		switch reference {
		case "projects":
			if target.Type == "organization" || target.ProjectID == "" || value != target.ProjectID {
				return errors.New("REST project reference is outside the unit target")
			}
		case "organizations":
			if target.Organization == "" || value != target.Organization {
				return errors.New("REST organization reference is outside the unit target")
			}
		}
	}
	for _, values := range query {
		for _, value := range values {
			canonicalValue, decodeErr := fullyPathUnescape(value)
			if errors.Is(decodeErr, errEncodingTooDeep) {
				return errors.New("REST project reference has excessive encoding depth")
			}
			if decodeErr != nil && (strings.Contains(value, "projects") || strings.Contains(value, "organizations")) {
				return errors.New("REST resource reference has invalid encoding")
			}
			if decodeErr == nil {
				value = canonicalValue
			}
			if strings.Contains(value, "projects/") && len(projectReferences(value)) == 0 {
				return errors.New("REST project reference is invalid")
			}
			for _, project := range projectReferences(value) {
				if target.Type == "organization" || target.ProjectID == "" || project != target.ProjectID {
					return errors.New("REST project reference is outside the unit target")
				}
			}
			if strings.Contains(value, "organizations/") && len(organizationReferences(value)) == 0 {
				return errors.New("REST organization reference is invalid")
			}
			for _, organization := range organizationReferences(value) {
				if target.Organization == "" || organization != target.Organization {
					return errors.New("REST organization reference is outside the unit target")
				}
			}
		}
	}
	return nil
}

func fullyPathUnescape(value string) (string, error) {
	for range maxPercentDecodePasses {
		decoded, err := url.PathUnescape(value)
		if err != nil {
			return "", err
		}
		if decoded == value {
			return value, nil
		}
		value = decoded
	}
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return "", err
	}
	if decoded != value {
		return "", errEncodingTooDeep
	}
	return value, nil
}

// CheckAPIBody rejects JSON body references to projects outside the unit target.
func (g Guard) CheckAPIBody(body []byte, target Target) error {
	if len(body) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return errors.New("REST body is not valid JSON")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return errors.New("REST body is not a single JSON value")
	}
	if err := checkBodyReferences(value, target); err != nil {
		return err
	}
	return nil
}

// CheckAPIRequest validates the final rendered method, URL and JSON body for a unit target.
func (g Guard) CheckAPIRequest(method, rawURL string, body []byte, target Target) error {
	if err := g.CheckAPI(method, rawURL, target); err != nil {
		return err
	}
	return g.CheckAPIBody(body, target)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func checkBodyReferences(value any, target Target) error {
	switch value := value.(type) {
	case string:
		decoded := value
		for range maxPercentDecodePasses {
			next, err := url.PathUnescape(decoded)
			if err != nil {
				if strings.Contains(decoded, "projects") || strings.Contains(decoded, "organizations") {
					return errors.New("REST body resource reference has invalid encoding")
				}
				break
			}
			if next == decoded {
				break
			}
			decoded = next
		}
		next, decodeErr := url.PathUnescape(decoded)
		if decodeErr == nil && next != decoded {
			return errors.New("REST body encoding is too deeply nested")
		}
		if strings.Contains(decoded, "projects/") {
			projects := projectReferences(decoded)
			if len(projects) == 0 {
				return errors.New("REST body project reference is invalid")
			}
			for _, project := range projects {
				if target.Type == "organization" || target.ProjectID == "" || project != target.ProjectID {
					return errors.New("REST body project reference is outside the unit target")
				}
			}
		}
		if strings.Contains(decoded, "organizations/") {
			organizations := organizationReferences(decoded)
			if len(organizations) == 0 {
				return errors.New("REST body organization reference is invalid")
			}
			for _, organization := range organizations {
				if target.Organization == "" || organization != target.Organization {
					return errors.New("REST body organization reference is outside the unit target")
				}
			}
		}
	case []any:
		for _, item := range value {
			if err := checkBodyReferences(item, target); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, item := range value {
			if err := checkBodyReferences(key, target); err != nil {
				return err
			}
			if err := checkBodyReferences(item, target); err != nil {
				return err
			}
		}
	}
	return nil
}
