package rule

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/SummerQXY/gbencher/rules"
)

// Bind is a kind of target binding. A command entry lists the kinds a use of the command may
// have. What each kind demands of a command line is enforced where commands are built; this
// package holds the data and the matching.
type Bind string

const (
	// BindProject: --project=<target>, or the first positional argument is the target project.
	BindProject Bind = "project"
	// BindOrganization: --organization=<org>, the first positional argument is the
	// organization, or --filter contains parent.id=<org>.
	BindOrganization Bind = "organization"
	// BindDerived: the value comes from the data of an earlier step of the same unit, so the
	// command is only allowed in a foreach step.
	BindDerived Bind = "derived"
	// BindNone: a local command that refers to no target.
	BindNone Bind = "none"
)

// bindKinds lists every valid Bind.
func bindKinds() []Bind {
	return []Bind{BindProject, BindOrganization, BindDerived, BindNone}
}

// GcloudEntry is one command gcloud may run.
type GcloudEntry struct {
	// Path holds the words of the command path, such as ["compute", "instances", "list"].
	Path []string
	// Bind lists the kinds of target binding a use of the command may have.
	Bind []Bind
}

// RESTHost is a host that REST steps may call and the methods they may use on it.
type RESTHost struct {
	Host    string
	Methods []string
}

// Allowlist is the set of commands, REST endpoints and flags a scan may use. No method changes
// it, so it can be shared between goroutines as long as its fields are left alone.
type Allowlist struct {
	// Gcloud holds the commands rules may run. EngineGcloud holds the commands only the engine
	// runs; rules cannot use them.
	Gcloud, EngineGcloud []GcloudEntry
	// GcloudFlags is the positive list of the flags a gcloud step may contain.
	GcloudFlags []string

	// KubectlVerbs are the verbs a kubectl step may use. KubectlResources are the resources
	// the verb get may name.
	KubectlVerbs, KubectlResources []string
	// KubectlFlags is the positive list of the flags a kubectl step may contain.
	KubectlFlags []string

	// REST holds the hosts REST steps may call and the methods allowed on each. RESTPostSuffixes
	// are the path endings, such as ":getIamPolicy", that make a POST allowed as well.
	REST             []RESTHost
	RESTPostSuffixes []string

	// ForbiddenGcloudFlags and ForbiddenKubectlFlags name the flags no rule may carry. They set
	// identity, endpoint or debug behavior, which the engine controls. A name on them is
	// forbidden even if the positive list of the tool names it too.
	ForbiddenGcloudFlags, ForbiddenKubectlFlags []string
}

// allowlistDoc is the shape of rules/allowlist.yaml.
type allowlistDoc struct {
	Gcloud                []commandDoc `yaml:"gcloud"`
	EngineGcloud          []commandDoc `yaml:"engine_gcloud"`
	GcloudFlags           []string     `yaml:"gcloud_flags"`
	KubectlVerbs          []string     `yaml:"kubectl_verbs"`
	KubectlResources      []string     `yaml:"kubectl_resources"`
	KubectlFlags          []string     `yaml:"kubectl_flags"`
	REST                  []restDoc    `yaml:"rest"`
	RESTPostSuffixes      []string     `yaml:"rest_post_suffixes"`
	ForbiddenGcloudFlags  []string     `yaml:"forbidden_gcloud_flags"`
	ForbiddenKubectlFlags []string     `yaml:"forbidden_kubectl_flags"`
}

type commandDoc struct {
	Path string   `yaml:"path"`
	Bind []string `yaml:"bind"`
}

type restDoc struct {
	Host    string   `yaml:"host"`
	Methods []string `yaml:"methods"`
}

// ParseAllowlist parses an allowlist document. The document first goes through CheckYAMLShape,
// and its error is returned as it is: the limits on size, anchors and aliases, repeated keys
// and mapping size apply here as they do to rule files. Then every key must be a known one, at
// every level, and
//
//   - a command path must have at least one word and must not repeat within its list;
//   - bind must be a list of at least one of project, organization, derived and none;
//   - every entry of rest_post_suffixes must be a custom method suffix, a colon followed by the
//     method name such as ":getIamPolicy". An empty suffix would match every URL.
//
// A list that is left out stays empty. An empty gcloud_flags or kubectl_flags forbids every flag
// of that tool.
func ParseAllowlist(data []byte) (*Allowlist, error) {
	if err := CheckYAMLShape(data); err != nil {
		return nil, err
	}

	var doc allowlistDoc
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("allowlist: the document is empty")
		}
		return nil, fmt.Errorf("allowlist: %s", strings.TrimPrefix(err.Error(), "yaml: "))
	}

	gcloud, err := commandEntries("gcloud", doc.Gcloud)
	if err != nil {
		return nil, err
	}
	engine, err := commandEntries("engine_gcloud", doc.EngineGcloud)
	if err != nil {
		return nil, err
	}
	for i, s := range doc.RESTPostSuffixes {
		if len(s) < 2 || s[0] != ':' {
			return nil, fmt.Errorf("allowlist: rest_post_suffixes[%d]: %q is not a custom method suffix such as \":getIamPolicy\"", i, s)
		}
	}

	a := &Allowlist{
		Gcloud:                gcloud,
		EngineGcloud:          engine,
		GcloudFlags:           doc.GcloudFlags,
		KubectlVerbs:          doc.KubectlVerbs,
		KubectlResources:      doc.KubectlResources,
		KubectlFlags:          doc.KubectlFlags,
		RESTPostSuffixes:      doc.RESTPostSuffixes,
		ForbiddenGcloudFlags:  doc.ForbiddenGcloudFlags,
		ForbiddenKubectlFlags: doc.ForbiddenKubectlFlags,
	}
	for _, h := range doc.REST {
		a.REST = append(a.REST, RESTHost{Host: h.Host, Methods: h.Methods})
	}
	return a, nil
}

// commandEntries checks the entries of one command list, named list in errors, and converts
// them. A path is split into words at any run of whitespace, so two spellings of the same words
// count as the same path.
func commandEntries(list string, docs []commandDoc) ([]GcloudEntry, error) {
	entries := make([]GcloudEntry, 0, len(docs))
	firstAt := make(map[string]int, len(docs))
	for i, d := range docs {
		words := strings.Fields(d.Path)
		if len(words) == 0 {
			return nil, fmt.Errorf("allowlist: %s[%d]: path is empty", list, i)
		}
		path := strings.Join(words, " ")
		if first, dup := firstAt[path]; dup {
			return nil, fmt.Errorf("allowlist: %s[%d]: duplicate path %q, first listed as %s[%d]", list, i, path, list, first)
		}
		firstAt[path] = i

		if len(d.Bind) == 0 {
			return nil, fmt.Errorf("allowlist: %s[%d] %q: bind is empty, want at least one of %v", list, i, path, bindKinds())
		}
		binds := make([]Bind, len(d.Bind))
		for j, b := range d.Bind {
			if !slices.Contains(bindKinds(), Bind(b)) {
				return nil, fmt.Errorf("allowlist: %s[%d] %q: bind value %q is not valid, want one of %v", list, i, path, b, bindKinds())
			}
			binds[j] = Bind(b)
		}
		entries = append(entries, GcloudEntry{Path: words, Bind: binds})
	}
	return entries, nil
}

// LoadAllowlist parses the allowlist that is embedded in the binary. It holds no state: every
// call parses the file again.
func LoadAllowlist() (*Allowlist, error) {
	data, err := rules.FS.ReadFile("allowlist.yaml")
	if err != nil {
		return nil, fmt.Errorf("read the embedded allowlist: %w", err)
	}
	a, err := ParseAllowlist(data)
	if err != nil {
		return nil, fmt.Errorf("embedded allowlist.yaml: %w", err)
	}
	return a, nil
}

// MatchGcloud finds the entry that admits a gcloud command line. argv is the line without the
// leading "gcloud". The entry is the longest one whose path is a prefix of argv. The words are
// compared whole and exactly, so "compute instances delete list" does not match the entry
// "compute instances list". rest is what follows the path in argv; it shares argv's memory.
// When nothing matches, entry and rest are nil.
//
// Only the Gcloud list is searched, unless engine is set: then EngineGcloud is searched as well
// and the longest match across both lists wins. On equal length the engine entry wins, because
// the engine asks for its own commands. The returned entry points into the Allowlist and must
// not be changed.
//
// A path that starts with a flag, such as "--version", is a whole command line and not a
// prefix: it matches only an argv that is exactly that path. Read as a prefix it would admit
// the flag followed by any other words.
func (a *Allowlist) MatchGcloud(argv []string, engine bool) (entry *GcloudEntry, rest []string, ok bool) {
	var best *GcloudEntry
	if engine {
		best = longestMatch(a.EngineGcloud, argv, best)
	}
	best = longestMatch(a.Gcloud, argv, best)
	if best == nil {
		return nil, nil, false
	}
	return best, argv[len(best.Path):], true
}

// longestMatch returns the entry with the longest path that matches argv, or best when no entry
// of entries is longer than it.
func longestMatch(entries []GcloudEntry, argv []string, best *GcloudEntry) *GcloudEntry {
	for i := range entries {
		e := &entries[i]
		if pathMatches(e.Path, argv) && (best == nil || len(e.Path) > len(best.Path)) {
			best = e
		}
	}
	return best
}

// pathMatches reports whether a command path admits argv, see MatchGcloud. An empty path
// admits nothing: read as a prefix it would match every command line.
func pathMatches(path, argv []string) bool {
	if len(path) == 0 || len(path) > len(argv) {
		return false
	}
	if strings.HasPrefix(path[0], "-") {
		return len(path) == len(argv) && slices.Equal(path, argv)
	}
	return slices.Equal(path, argv[:len(path)])
}

// ForbiddenFlag reports whether a rule must not carry arg for tool, which is "gcloud" or
// "kubectl". arg is one word of the command line, with or without an attached value:
// "--account=x" and "--account" are the same flag, named by the text before the first "=".
//
// For both tools the policy is a positive list: a word that starts with "-" is forbidden unless
// its name is in GcloudFlags or KubectlFlags, and a word that does not start with "-" is not a
// flag. A list of forbidden names can never be complete. gcloud rejects abbreviated flags, but it
// has hidden global flags that replace the credentials or change the API domain
// (--credential-file-override, --authorization-token-file, --authority-selector,
// --universe-domain) and a global short flag (-q is --quiet). kubectl has global short flags (-s
// is --server, and there are -n and -v) that can be attached to their value (-sfoo, -ojson) or
// combined (-As). Anything that is not listed is refused, whatever it is called, so a flag nobody
// has thought of yet is refused too.
//
// ForbiddenGcloudFlags and ForbiddenKubectlFlags are looked at first, so a flag on one stays
// forbidden even if the positive list names it by mistake; callers can use those lists to say why
// a flag was rejected.
//
// The policy is about the flags a rule writes in its own command. The flags the engine adds to its
// own calls (for gcloud --quiet, --format, the account, impersonation and quota project; for
// kubectl the kubeconfig and the request timeout) are not subject to it, so ForbiddenFlag has to
// run on the words of the rule before the engine adds anything.
//
// Any other tool has no policy and nothing is admitted, so the answer is true. A misspelled tool
// name must not turn into a check that passes.
func (a *Allowlist) ForbiddenFlag(tool, arg string) bool {
	switch tool {
	case "gcloud":
		return flagForbidden(arg, a.ForbiddenGcloudFlags, a.GcloudFlags)
	case "kubectl":
		return flagForbidden(arg, a.ForbiddenKubectlFlags, a.KubectlFlags)
	}
	return true
}

// flagForbidden applies the flag policy of one tool to arg, see ForbiddenFlag: a name on
// forbidden is refused first, then any word that starts with "-" and whose name is not on listed.
func flagForbidden(arg string, forbidden, listed []string) bool {
	name, _, _ := strings.Cut(arg, "=")
	if slices.Contains(forbidden, name) {
		return true
	}
	return strings.HasPrefix(arg, "-") && !slices.Contains(listed, name)
}

// resourceFreeVerb reports whether a kubectl verb takes no resource, so that none is checked.
// A verb added to the data that is not named here must be given a listed resource: forgetting
// to update this function then rejects too much and never too little.
func resourceFreeVerb(verb string) bool {
	return verb == "api-resources" || verb == "version"
}

// KubectlAllowed reports whether a kubectl step may use verb on resource. The verb must be in
// KubectlVerbs. For every verb but api-resources and version the resource must be in
// KubectlResources, spelled exactly as listed (managedcertificates.networking.gke.io is one
// name). For those two the resource is ignored and callers pass "".
func (a *Allowlist) KubectlAllowed(verb, resource string) bool {
	if !slices.Contains(a.KubectlVerbs, verb) {
		return false
	}
	return resourceFreeVerb(verb) || slices.Contains(a.KubectlResources, resource)
}

// RESTAllowed returns nil when a REST step may send method to rawURL, and otherwise an error
// that says why not. The URL must use https, have no userinfo and no explicit port, and its
// host must be in the REST list. The method must be one of the methods of that host. A POST is
// also allowed when the URL path ends in one of RESTPostSuffixes.
//
// A port is refused even when it is the default 443 or empty ("host:"): the list names hosts,
// not services on them. The suffix is looked for in the path as it is sent, so a colon written
// as %3A does not count, and a suffix in the query or the fragment does not count either. The
// host is compared exactly after lowercasing ASCII letters only: Unicode case folding would
// equate look-alike hosts with a listed one (a long s with "s", the Kelvin sign with "k") and
// send the access token to the wrong place. Errors show a host with its non-ASCII characters
// escaped, so a look-alike cannot pass for the real one, and never repeat the URL, which may
// carry credentials.
func (a *Allowlist) RESTAllowed(method, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		// A *url.Error spells out the whole URL, so only its cause is kept.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return fmt.Errorf("rest: invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("rest: the URL scheme is %q, only https is allowed", u.Scheme)
	}
	if u.User != nil {
		return errors.New("rest: the URL must not contain userinfo")
	}
	if u.Port() != "" || strings.HasSuffix(u.Host, ":") {
		return errors.New("rest: the URL must not contain an explicit port")
	}

	host := asciiLower(u.Hostname())
	var listed, methodAllowed bool
	for _, h := range a.REST {
		if h.Host != host {
			continue
		}
		listed = true
		if slices.Contains(h.Methods, method) {
			methodAllowed = true
		}
	}
	switch {
	case !listed:
		return fmt.Errorf("rest: host %+q is not in the allowlist", host)
	case methodAllowed:
		return nil
	case method == "POST":
		path := u.EscapedPath()
		if slices.ContainsFunc(a.RESTPostSuffixes, func(s string) bool { return strings.HasSuffix(path, s) }) {
			return nil
		}
		return fmt.Errorf("rest: POST to host %+q needs a URL path that ends in one of %s", host, strings.Join(a.RESTPostSuffixes, ", "))
	}
	return fmt.Errorf("rest: method %q is not allowed for host %+q", method, host)
}

// asciiLower lowercases the letters A to Z and leaves every other byte alone. strings.ToLower
// would also map characters such as the Kelvin sign to ASCII letters.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
