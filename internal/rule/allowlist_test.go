package rule_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/SummerQXY/gbencher/internal/rule"
	"github.com/SummerQXY/gbencher/rules"
)

// mustLoadAllowlist loads the allowlist that is compiled into the binary.
func mustLoadAllowlist(t *testing.T) *rule.Allowlist {
	t.Helper()
	a, err := rule.LoadAllowlist()
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	return a
}

// mustParseAllowlist parses a small allowlist written inline, for the cases the embedded data
// cannot express.
func mustParseAllowlist(t *testing.T, doc string) *rule.Allowlist {
	t.Helper()
	a, err := rule.ParseAllowlist([]byte(doc))
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	return a
}

// pathOf renders the path of a matched entry as one string. It is "" when nothing matched.
func pathOf(e *rule.GcloudEntry) string {
	if e == nil {
		return ""
	}
	return strings.Join(e.Path, " ")
}

// sameSet fails the test unless got and want hold the same strings in any order, and says what
// is missing and what is extra.
func sameSet(t *testing.T, name string, got, want []string) {
	t.Helper()
	g, w := slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))
	if slices.Equal(g, w) {
		return
	}
	var missing, extra []string
	for _, s := range w {
		if !slices.Contains(g, s) {
			missing = append(missing, s)
		}
	}
	for _, s := range g {
		if !slices.Contains(w, s) {
			extra = append(extra, s)
		}
	}
	t.Errorf("%s: missing %q, extra %q (got %d entries, want %d)", name, missing, extra, len(g), len(w))
}

func TestMatchGcloud_DeleteVerbNotAllowed(t *testing.T) {
	a := mustLoadAllowlist(t)

	cases := []struct {
		name string
		argv []string
	}{
		// A resource named like a read verb must not make a delete command pass.
		{"delete verb followed by a read verb", []string{"compute", "instances", "delete", "list", "--project=example-prod"}},
		{"path cut short", []string{"compute", "instances", "--project=example-prod"}},
		{"verb extended by more letters", []string{"compute", "instances", "list-all"}},
		{"verb with extra letters in front", []string{"compute", "instances", "xlist"}},
		{"group that is a part of the real word", []string{"compute", "instance", "list"}},
		{"group extended by more letters", []string{"compute", "instances-x", "list"}},
		{"flag in front of the command", []string{"--project=example-prod", "compute", "instances", "list"}},
		{"different letter case", []string{"Compute", "Instances", "List"}},
		{"unknown group", []string{"bogus", "list"}},
		{"no words", nil},
	}
	for _, c := range cases {
		for _, engine := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s engine=%v", c.name, engine), func(t *testing.T) {
				e, rest, ok := a.MatchGcloud(c.argv, engine)
				if ok || e != nil || rest != nil {
					t.Fatalf("MatchGcloud(%q, %v) = %q, %q, %v; want no match", c.argv, engine, pathOf(e), rest, ok)
				}
			})
		}
	}

	// ParseAllowlist refuses an empty path, but an Allowlist can also be built by hand. An
	// entry without words must admit nothing, not every command line.
	t.Run("entry without words", func(t *testing.T) {
		hand := &rule.Allowlist{
			Gcloud:       []rule.GcloudEntry{{Bind: []rule.Bind{rule.BindProject}}},
			EngineGcloud: []rule.GcloudEntry{{Path: []string{}, Bind: []rule.Bind{rule.BindNone}}},
		}
		for _, argv := range [][]string{nil, {"compute", "instances", "list"}, {"--version"}} {
			if e, _, ok := hand.MatchGcloud(argv, true); ok || e != nil {
				t.Errorf("MatchGcloud(%q) matched an entry without words", argv)
			}
		}
	})
}

func TestMatchGcloud_LongestPathWins(t *testing.T) {
	t.Run("embedded data", func(t *testing.T) {
		a := mustLoadAllowlist(t)
		for _, c := range []struct {
			argv []string
			want string
		}{
			{[]string{"compute", "networks", "subnets", "list", "--project=example-prod"}, "compute networks subnets list"},
			{[]string{"compute", "networks", "list", "--project=example-prod"}, "compute networks list"},
		} {
			e, rest, ok := a.MatchGcloud(c.argv, false)
			if !ok || pathOf(e) != c.want {
				t.Errorf("MatchGcloud(%q) = %q, %v; want %q", c.argv, pathOf(e), ok, c.want)
				continue
			}
			if want := c.argv[len(e.Path):]; !slices.Equal(rest, want) {
				t.Errorf("MatchGcloud(%q) rest = %q, want %q", c.argv, rest, want)
			}
		}
	})

	// No embedded entry is a prefix of another one, so the choice between a shorter and a longer
	// match is exercised on allowlists written for it.
	const (
		shortFirst = `
gcloud:
  - {path: "compute networks", bind: [project]}
  - {path: "compute networks subnets list", bind: [organization]}
`
		longFirst = `
gcloud:
  - {path: "compute networks subnets list", bind: [organization]}
  - {path: "compute networks", bind: [project]}
`
		twoLists = `
gcloud:
  - {path: "projects list sub", bind: [project]}
  - {path: "services list", bind: [project]}
  - {path: "iam roles", bind: [project]}
engine_gcloud:
  - {path: "projects list", bind: [none]}
  - {path: "services list sub", bind: [none]}
  - {path: "iam roles", bind: [none]}
`
	)
	cases := []struct {
		name     string
		doc      string
		engine   bool
		argv     string
		wantPath string // "" for no match
		wantBind []rule.Bind
	}{
		{"shorter entry listed first", shortFirst, false, "compute networks subnets list --project=example-prod", "compute networks subnets list", []rule.Bind{rule.BindOrganization}},
		{"longer entry listed first", longFirst, false, "compute networks subnets list --project=example-prod", "compute networks subnets list", []rule.Bind{rule.BindOrganization}},
		{"shorter entry still matches its own words", shortFirst, false, "compute networks list", "compute networks", []rule.Bind{rule.BindProject}},
		{"longer entry is no prefix of the words", longFirst, false, "compute networks subnets describe", "compute networks", []rule.Bind{rule.BindProject}},
		{"longer rule entry beats a shorter engine entry", twoLists, true, "projects list sub", "projects list sub", []rule.Bind{rule.BindProject}},
		{"longer engine entry beats a shorter rule entry", twoLists, true, "services list sub", "services list sub", []rule.Bind{rule.BindNone}},
		{"engine entry that is a prefix", twoLists, true, "projects list other", "projects list", []rule.Bind{rule.BindNone}},
		{"engine entry is invisible without engine", twoLists, false, "projects list other", "", nil},
		{"the same path in both lists prefers the engine entry", twoLists, true, "iam roles", "iam roles", []rule.Bind{rule.BindNone}},
		{"the same path in both lists without engine", twoLists, false, "iam roles", "iam roles", []rule.Bind{rule.BindProject}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := mustParseAllowlist(t, c.doc)
			argv := strings.Fields(c.argv)
			e, rest, ok := a.MatchGcloud(argv, c.engine)
			if c.wantPath == "" {
				if ok || e != nil {
					t.Fatalf("MatchGcloud(%q, %v) = %q, want no match", argv, c.engine, pathOf(e))
				}
				return
			}
			if !ok || pathOf(e) != c.wantPath {
				t.Fatalf("MatchGcloud(%q, %v) = %q, %v; want %q", argv, c.engine, pathOf(e), ok, c.wantPath)
			}
			if !slices.Equal(e.Bind, c.wantBind) {
				t.Errorf("Bind = %q, want %q", e.Bind, c.wantBind)
			}
			if want := argv[len(e.Path):]; !slices.Equal(rest, want) {
				t.Errorf("rest = %q, want %q", rest, want)
			}
		})
	}
}

func TestMatchGcloud_PositionalAfterPath(t *testing.T) {
	a := mustLoadAllowlist(t)

	argv := []string{"org-policies", "describe", "constraints/iam.allowedPolicyMemberDomains", "--project=example-prod"}
	e, rest, ok := a.MatchGcloud(argv, false)
	if !ok {
		t.Fatalf("MatchGcloud(%q) did not match", argv)
	}
	if got := pathOf(e); got != "org-policies describe" {
		t.Errorf("matched %q, want %q", got, "org-policies describe")
	}
	if want := []string{"constraints/iam.allowedPolicyMemberDomains", "--project=example-prod"}; !slices.Equal(rest, want) {
		t.Errorf("rest = %q, want %q", rest, want)
	}

	t.Run("nothing after the path", func(t *testing.T) {
		e, rest, ok := a.MatchGcloud([]string{"services", "list"}, false)
		if !ok || pathOf(e) != "services list" || len(rest) != 0 {
			t.Fatalf("MatchGcloud = %q, %q, %v; want services list with no rest", pathOf(e), rest, ok)
		}
	})
}

func TestMatchGcloud_EngineEntriesOnlyWhenEngine(t *testing.T) {
	a := mustLoadAllowlist(t)

	cases := []struct {
		name     string
		argv     []string
		engine   bool
		wantPath string // "" for no match
	}{
		{"engine command is not a rule command", []string{"projects", "describe", "example-prod"}, false, ""},
		{"engine command with engine", []string{"projects", "describe", "example-prod"}, true, "projects describe"},
		{"rule command with engine", []string{"services", "list", "--enabled", "--project=example-prod"}, true, "services list"},
		{"rule command without engine", []string{"services", "list", "--enabled", "--project=example-prod"}, false, "services list"},
		{"version with engine", []string{"--version"}, true, "--version"},
		{"version without engine", []string{"--version"}, false, ""},
		// "--version" is a whole command line. It must not turn into a prefix that admits more.
		{"version followed by a word", []string{"--version", "compute"}, true, ""},
		{"version followed by a flag", []string{"--version", "--project=example-prod"}, true, ""},
		{"version after a word", []string{"projects", "--version"}, true, ""},
		{"version command spelled as a word", []string{"version"}, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, rest, ok := a.MatchGcloud(c.argv, c.engine)
			if c.wantPath == "" {
				if ok || e != nil {
					t.Fatalf("MatchGcloud(%q, %v) = %q, want no match", c.argv, c.engine, pathOf(e))
				}
				return
			}
			if !ok || pathOf(e) != c.wantPath {
				t.Fatalf("MatchGcloud(%q, %v) = %q, %v; want %q", c.argv, c.engine, pathOf(e), ok, c.wantPath)
			}
			if want := c.argv[len(e.Path):]; !slices.Equal(rest, want) {
				t.Errorf("rest = %q, want %q", rest, want)
			}
		})
	}
}

func TestForbiddenFlag_BothForms(t *testing.T) {
	a := mustLoadAllowlist(t)

	cases := []struct {
		tool, arg string
		want      bool
	}{
		// gcloud: the name before "=" is what counts, so the bare and the attached form of a flag
		// agree. First the flags on the forbidden list.
		{"gcloud", "--account=x", true},
		{"gcloud", "--account", true},
		{"gcloud", "--impersonate-service-account=scanner@example-sec.iam.gserviceaccount.com", true},
		{"gcloud", "--log-http", true},
		{"gcloud", "--flags-file=f", true},
		// Hidden global flags that change the credentials or the API domain.
		{"gcloud", "--authority-selector", true},
		{"gcloud", "--authority-selector=x", true},
		{"gcloud", "--authorization-token-file", true},
		{"gcloud", "--authorization-token-file=f", true},
		{"gcloud", "--credential-file-override", true},
		{"gcloud", "--credential-file-override=f", true},
		{"gcloud", "--universe-domain", true},
		{"gcloud", "--universe-domain=example.test", true},
		// The policy is a positive list, so a flag that is not listed is forbidden whatever it
		// is called: gcloud has a global short flag (-q is --quiet), hidden global flags, and
		// flags that do not exist yet. It rejects abbreviations itself; they stay forbidden here
		// too, as does the end-of-options marker.
		{"gcloud", "-q", true},
		{"gcloud", "-h", true},
		{"gcloud", "--quiet", true},
		{"gcloud", "--acc=x", true},
		{"gcloud", "--accounts=x", true},
		{"gcloud", "--proj=example-prod", true},
		{"gcloud", "--some-future-flag=1", true},
		{"gcloud", "--", true},
		{"gcloud", "-", true},
		// The flags a rule writes.
		{"gcloud", "--project=example-prod", false},
		{"gcloud", "--format=json", false},
		{"gcloud", "--filter=parent.id=123", false},
		{"gcloud", "--limit=1", false},
		// Not a flag at all: a positional argument or the value of a flag.
		{"gcloud", "example-prod", false},
		{"gcloud", "constraints/iam.allowedPolicyMemberDomains", false},
		{"gcloud", "json", false},
		{"gcloud", "", false},

		// kubectl: a word that starts with "-" is forbidden unless its name is on the positive list.
		{"kubectl", "-s", true},
		{"kubectl", "-sfoo", true},
		{"kubectl", "-As", true},
		{"kubectl", "--server", true},
		{"kubectl", "--serv", true},
		{"kubectl", "-ojson", true},
		{"kubectl", "--as", true},
		{"kubectl", "--server=https://example.invalid", true},
		{"kubectl", "--request-timeout=15s", true},
		{"kubectl", "-n", true},
		{"kubectl", "-v=6", true},
		{"kubectl", "--", true},
		{"kubectl", "-", true},
		{"kubectl", "-o", false},
		{"kubectl", "-o=json", false},
		{"kubectl", "--all-namespaces", false},
		{"kubectl", "--namespace=x", false},
		// Not a flag at all: the value of -o, a verb, a resource.
		{"kubectl", "json", false},
		{"kubectl", "pods", false},
		{"kubectl", "", false},

		// A tool without a policy admits nothing, so a misspelled tool name cannot open a gap.
		{"kubctl", "-s", true},
		{"helm", "--project=example-prod", true},
		{"", "--project=example-prod", true},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s %q", c.tool, c.arg), func(t *testing.T) {
			if got := a.ForbiddenFlag(c.tool, c.arg); got != c.want {
				t.Errorf("ForbiddenFlag(%q, %q) = %v, want %v", c.tool, c.arg, got, c.want)
			}
		})
	}

	// The lists of the loaded allowlist are walked here instead of being restated. Their contents
	// are pinned by TestLoadAllowlist_EmbeddedDataIsComplete.
	t.Run("every listed flag in both forms", func(t *testing.T) {
		for _, tool := range []struct {
			name              string
			forbidden, listed []string
		}{
			{"gcloud", a.ForbiddenGcloudFlags, a.GcloudFlags},
			{"kubectl", a.ForbiddenKubectlFlags, a.KubectlFlags},
		} {
			if len(tool.forbidden) == 0 || len(tool.listed) == 0 {
				t.Fatalf("%s: %d forbidden flags and %d listed flags, want both lists filled", tool.name, len(tool.forbidden), len(tool.listed))
			}
			for _, f := range tool.forbidden {
				for _, arg := range []string{f, f + "=x"} {
					if !a.ForbiddenFlag(tool.name, arg) {
						t.Errorf("ForbiddenFlag(%q, %q) = false, want true", tool.name, arg)
					}
				}
			}
			for _, f := range tool.listed {
				for _, arg := range []string{f, f + "=x"} {
					if a.ForbiddenFlag(tool.name, arg) {
						t.Errorf("ForbiddenFlag(%q, %q) = true, want false", tool.name, arg)
					}
				}
			}
		}
	})

	t.Run("a flag on the forbidden list stays forbidden when the positive list names it", func(t *testing.T) {
		a := mustParseAllowlist(t, `
gcloud_flags: ["--project", "--account"]
forbidden_gcloud_flags: ["--account"]
kubectl_flags: ["-o", "--server"]
forbidden_kubectl_flags: ["--server"]
`)
		for _, c := range []struct {
			tool, arg string
			want      bool
		}{
			{"gcloud", "--account", true},
			{"gcloud", "--account=x", true},
			{"gcloud", "--project=example-prod", false},
			{"kubectl", "--server=https://example.invalid", true},
			{"kubectl", "-o", false},
		} {
			if got := a.ForbiddenFlag(c.tool, c.arg); got != c.want {
				t.Errorf("ForbiddenFlag(%q, %q) = %v, want %v", c.tool, c.arg, got, c.want)
			}
		}
	})

	t.Run("a positive list that is left out forbids every flag", func(t *testing.T) {
		a := mustParseAllowlist(t, "gcloud: []\n")
		for _, c := range []struct {
			tool, arg string
			want      bool
		}{
			{"gcloud", "--project=example-prod", true},
			{"gcloud", "-q", true},
			{"kubectl", "-o", true},
			{"gcloud", "example-prod", false},
			{"kubectl", "pods", false},
		} {
			if got := a.ForbiddenFlag(c.tool, c.arg); got != c.want {
				t.Errorf("ForbiddenFlag(%q, %q) = %v, want %v", c.tool, c.arg, got, c.want)
			}
		}
	})
}

func TestRESTAllowed(t *testing.T) {
	a := mustLoadAllowlist(t)

	const (
		datasets = "https://bigquery.googleapis.com/bigquery/v2/projects/example-prod/datasets"
		table    = "https://bigquery.googleapis.com/bigquery/v2/projects/example-prod/datasets/d/tables/t"
	)
	cases := []struct {
		name, method, url string
		wantErr           string // "" when the call is allowed, else a part of the error
	}{
		{"GET on a listed host", "GET", datasets, ""},
		{"GET with a query string", "GET", "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=1", ""},
		{"GET on the third host", "GET", "https://dlp.googleapis.com/v2/projects/example-prod/inspectTemplates", ""},
		{"host in capitals", "GET", "https://BigQuery.GoogleAPIs.com/bigquery/v2/projects/example-prod/datasets", ""},
		{"scheme in capitals", "GET", "HTTPS://bigquery.googleapis.com/bigquery/v2/projects/example-prod/datasets", ""},

		{"POST with the getIamPolicy suffix", "POST", table + ":getIamPolicy", ""},
		{"POST with the search suffix", "POST", "https://bigquery.googleapis.com/v1/projects/example-prod/locations/us/datasets:search", ""},
		{"POST with the testIamPermissions suffix", "POST", table + ":testIamPermissions", ""},
		{"POST with the getEffectivePolicy suffix", "POST", "https://dlp.googleapis.com/v2/projects/example-prod:getEffectivePolicy", ""},
		{"POST with the getEffectiveIamPolicy suffix", "POST", "https://admin.googleapis.com/v1/projects/example-prod:getEffectiveIamPolicy", ""},
		{"POST suffix followed by a query string", "POST", table + ":getIamPolicy?alt=json", ""},

		{"DELETE has no suffix to rely on", "DELETE", datasets + "/d", "method"},
		{"PUT is not a read", "PUT", datasets + "/d", "method"},
		{"PATCH is not a read", "PATCH", datasets + "/d", "method"},
		{"POST without a suffix", "POST", datasets, "POST"},
		{"POST with a suffix that is not listed", "POST", table + ":setIamPolicy", "POST"},
		{"POST with the suffix only in the query", "POST", datasets + "?x=:getIamPolicy", "POST"},
		{"POST with the suffix only in the fragment", "POST", datasets + "#:getIamPolicy", "POST"},
		{"POST with an encoded colon", "POST", table + "%3AgetIamPolicy", "POST"},
		{"POST with the suffix inside the path", "POST", table + ":getIamPolicy/more", "POST"},
		{"POST with a suffix on a host that is not listed", "POST", "https://example.com/v1/projects/example-prod:getIamPolicy", "not in the allowlist"},
		{"method in lower case", "get", datasets, "method"},
		{"empty method", "", datasets, "method"},

		{"http scheme", "GET", "http://bigquery.googleapis.com/bigquery/v2/projects/example-prod/datasets", "scheme"},
		{"other scheme", "GET", "ftp://bigquery.googleapis.com/x", "scheme"},
		{"no scheme", "GET", "//bigquery.googleapis.com/x", "scheme"},
		{"empty url", "GET", "", "scheme"},
		{"userinfo", "GET", "https://user:secret@bigquery.googleapis.com/bigquery/v2/projects/example-prod/datasets", "userinfo"},
		{"user name only", "GET", "https://user@bigquery.googleapis.com/x", "userinfo"},
		{"empty userinfo", "GET", "https://@bigquery.googleapis.com/x", "userinfo"},
		// The listed host as the user part of a URL that goes to another host.
		{"listed host as userinfo", "GET", "https://bigquery.googleapis.com@example.com/x", "userinfo"},

		{"host that is not listed", "GET", "https://example.com/x", "not in the allowlist"},
		{"listed host as a prefix of another host", "GET", "https://bigquery.googleapis.com.example.com/x", "not in the allowlist"},
		{"listed host as a suffix of another host", "GET", "https://evilbigquery.googleapis.com/x", "not in the allowlist"},
		{"subdomain of a listed host", "GET", "https://eu.bigquery.googleapis.com/x", "not in the allowlist"},
		{"parent domain of a listed host", "GET", "https://googleapis.com/x", "not in the allowlist"},
		{"root label dot", "GET", "https://bigquery.googleapis.com./x", "not in the allowlist"},
		// strings.EqualFold equates a long s (U+017F) with "s". The token must not go to a host
		// that only looks like the listed one, and the error must show the difference.
		{"long s in place of s", "GET", "https://bigquery.googleapi\u017f.com/x", `googleapi\u017f.com" is not in the allowlist`},
		{"no host", "GET", "https:///bigquery/v2", "not in the allowlist"},
		{"opaque url", "GET", "https:bigquery.googleapis.com/x", "not in the allowlist"},
		{"ip address", "GET", "https://[::1]/x", "not in the allowlist"},

		{"explicit port", "GET", "https://bigquery.googleapis.com:8443/x", "port"},
		{"explicit default port", "GET", "https://bigquery.googleapis.com:443/x", "port"},
		{"empty port", "GET", "https://bigquery.googleapis.com:/x", "port"},

		{"control character", "GET", "https://bigquery.googleapis.com/x\x7f", "invalid URL"},
		{"escaped host", "GET", "https://bigquery%2Egoogleapis.com/x", "invalid URL"},
		{"leading space", "GET", " https://bigquery.googleapis.com/x", "invalid URL"},
		{"credentials stay out of a parse error", "GET", "https://user:secret@bigquery.googleapis.com/x\x7f", "invalid URL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := a.RESTAllowed(c.method, c.url)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("RESTAllowed(%q, %q) = %v, want nil", c.method, c.url, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("RESTAllowed(%q, %q) = nil, want an error that mentions %q", c.method, c.url, c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("RESTAllowed(%q, %q) = %q, want it to mention %q", c.method, c.url, err, c.wantErr)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Errorf("the error repeats credentials from the URL: %q", err)
			}
		})
	}

	t.Run("the Kelvin sign is not k", func(t *testing.T) {
		// strings.ToLower maps the Kelvin sign (U+212A) to "k". No embedded host has a "k", so
		// the case needs an allowlist of its own.
		a := mustParseAllowlist(t, "rest: [{host: kms.example.test, methods: [GET]}]\n")
		for _, c := range []struct {
			url string
			ok  bool
		}{
			{"https://kms.example.test/x", true},
			{"https://KMS.example.test/x", true},
			{"https://\u212Ams.example.test/x", false},
		} {
			if err := a.RESTAllowed("GET", c.url); (err == nil) != c.ok {
				t.Errorf("RESTAllowed(GET, %q) = %v, want allowed = %v", c.url, err, c.ok)
			}
		}
	})

	t.Run("methods come from the host entry", func(t *testing.T) {
		a := mustParseAllowlist(t, `
rest:
  - {host: read.example.test, methods: [GET]}
  - {host: write.example.test, methods: [GET, HEAD]}
  - {host: write.example.test, methods: [OPTIONS]}
rest_post_suffixes: [":check"]
`)
		for _, c := range []struct {
			method, url string
			ok          bool
		}{
			{"GET", "https://read.example.test/x", true},
			{"HEAD", "https://read.example.test/x", false},
			{"HEAD", "https://write.example.test/x", true},
			// A host listed twice admits the methods of both entries.
			{"OPTIONS", "https://write.example.test/x", true},
			{"POST", "https://write.example.test/x:check", true},
			{"POST", "https://write.example.test/x", false},
		} {
			if err := a.RESTAllowed(c.method, c.url); (err == nil) != c.ok {
				t.Errorf("RESTAllowed(%q, %q) = %v, want allowed = %v", c.method, c.url, err, c.ok)
			}
		}
	})
}

func TestParseAllowlist_RejectsUnknownKeys(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string // a part of the error
	}{
		{"unknown top-level key", "bogus_key: 1\n", "bogus_key"},
		{"unknown key in a gcloud entry", `gcloud: [{path: "a b", bind: [project], extra_key: 1}]`, "extra_key"},
		{"unknown key in an engine_gcloud entry", `engine_gcloud: [{path: "a b", bind: [none], extra_key: 1}]`, "extra_key"},
		{"unknown key in a rest entry", `rest: [{host: example.test, methods: [GET], extra_key: 1}]`, "extra_key"},
		{"misspelled list name", `gcloud_commands: []`, "gcloud_commands"},
		{"misspelled flag list name", `gcloud_flag: []`, "gcloud_flag"},

		{"empty path", `gcloud: [{path: "", bind: [project]}]`, "path is empty"},
		{"missing path", `gcloud: [{bind: [project]}]`, "path is empty"},
		{"blank path", `gcloud: [{path: "   ", bind: [project]}]`, "path is empty"},
		{"empty path in engine_gcloud", `engine_gcloud: [{path: "", bind: [none]}]`, "path is empty"},

		{"duplicate path", "gcloud:\n  - {path: \"a b\", bind: [project]}\n  - {path: \"a b\", bind: [organization]}\n", "duplicate path"},
		{"duplicate path in engine_gcloud", "engine_gcloud:\n  - {path: \"a b\", bind: [none]}\n  - {path: \"a b\", bind: [none]}\n", "duplicate path"},
		{"duplicate path that differs in spacing", `gcloud: [{path: "a b", bind: [project]}, {path: " a   b ", bind: [project]}]`, "duplicate path"},

		{"invalid bind value", `gcloud: [{path: "a b", bind: [bogus_kind]}]`, "bogus_kind"},
		{"bind value in another letter case", `gcloud: [{path: "a b", bind: [Project]}]`, "Project"},
		{"invalid bind value next to valid ones", `gcloud: [{path: "a b", bind: [project, bogus_kind]}]`, "bogus_kind"},
		{"invalid bind value in engine_gcloud", `engine_gcloud: [{path: "a b", bind: [bogus_kind]}]`, "bogus_kind"},
		{"bind is a scalar, not a list", `gcloud: [{path: "a b", bind: project}]`, "cannot unmarshal"},
		{"bind is an empty list", `gcloud: [{path: "a b", bind: []}]`, "bind is empty"},
		{"bind is missing", `gcloud: [{path: "a b"}]`, "bind is empty"},

		{"post suffix without a colon", `rest_post_suffixes: [getIamPolicy]`, "custom method suffix"},
		{"empty post suffix", `rest_post_suffixes: [""]`, "custom method suffix"},
		{"post suffix that is a bare colon", `rest_post_suffixes: [":"]`, "custom method suffix"},

		{"document is a list", "- gcloud\n", "cannot unmarshal"},
		{"list is a scalar", "gcloud: nope\n", "cannot unmarshal"},
		{"no document", "# only a comment\n", "empty"},
		{"no bytes", "", "empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := rule.ParseAllowlist([]byte(c.doc))
			if err == nil {
				t.Fatalf("ParseAllowlist accepted the document and returned %+v", a)
			}
			if a != nil {
				t.Errorf("an error must come with no allowlist, got %+v", a)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %q, want it to mention %q", err, c.want)
			}
		})
	}

	t.Run("the same path in both lists is not a duplicate", func(t *testing.T) {
		mustParseAllowlist(t, "gcloud: [{path: \"a b\", bind: [project]}]\nengine_gcloud: [{path: \"a b\", bind: [none]}]\n")
	})
}

func TestParseAllowlist_RejectsAliasesAndOversizedInput(t *testing.T) {
	const valid = "gcloud:\n  - {path: \"a b\", bind: [project]}\n"

	cases := []struct {
		name string
		data []byte
		want string // the prefix CheckYAMLShape gives its error
	}{
		{"alias", []byte("gcloud:\n  - &entry {path: \"a b\", bind: [project]}\n  - *entry\n"), "yaml-alias"},
		{"anchor without an alias", []byte("gcloud:\n  - &entry {path: \"a b\", bind: [project]}\n"), "yaml-alias"},
		{"more than 1 MiB", padTo([]byte(valid), 1<<20+1), "yaml-too-large"},
		{"mapping with too many keys", []byte("gcloud: [" + flowKeys(rule.MaxMappingKeys+1) + "]\n"), "yaml-too-large"},
		{"repeated key", []byte("gcloud: []\ngcloud: []\n"), "yaml-duplicate-key"},
		{"second document", []byte(valid + "---\n" + valid), "yaml-syntax"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The check is the one every rule and profile file goes through: ParseAllowlist must
			// report its error as it is.
			want := rule.CheckYAMLShape(c.data)
			if want == nil || !strings.HasPrefix(want.Error(), c.want) {
				t.Fatalf("CheckYAMLShape = %v, want an error that starts with %q", want, c.want)
			}
			a, err := rule.ParseAllowlist(c.data)
			if err == nil {
				t.Fatalf("ParseAllowlist accepted the input and returned %+v", a)
			}
			if a != nil {
				t.Errorf("an error must come with no allowlist, got %+v", a)
			}
			if err.Error() != want.Error() {
				t.Errorf("ParseAllowlist error = %q, want the error of CheckYAMLShape: %q", err, want)
			}
		})
	}
}

// The expected contents below are the policy as it was reviewed. A change to rules/allowlist.yaml
// has to change them too, which makes the change visible in review.
func TestLoadAllowlist_EmbeddedDataIsComplete(t *testing.T) {
	a := mustLoadAllowlist(t)

	project := []rule.Bind{rule.BindProject}
	org := []rule.Bind{rule.BindOrganization}
	derived := []rule.Bind{rule.BindDerived}
	none := []rule.Bind{rule.BindNone}

	type command struct {
		path string
		bind []rule.Bind
	}
	// compare checks one list of entries against the expected commands, ignoring order.
	compare := func(t *testing.T, name string, got []rule.GcloudEntry, want []command) {
		t.Helper()
		if len(got) != len(want) {
			t.Errorf("%s has %d entries, want %d", name, len(got), len(want))
		}
		gotBind := make(map[string][]rule.Bind, len(got))
		for _, e := range got {
			gotBind[strings.Join(e.Path, " ")] = e.Bind
		}
		for _, w := range want {
			b, ok := gotBind[w.path]
			if !ok {
				t.Errorf("%s has no entry %q", name, w.path)
				continue
			}
			if !slices.Equal(b, w.bind) {
				t.Errorf("%s %q: bind = %q, want %q", name, w.path, b, w.bind)
			}
			delete(gotBind, w.path)
		}
		for p := range gotBind {
			t.Errorf("%s has the unexpected entry %q", name, p)
		}
	}

	t.Run("gcloud", func(t *testing.T) {
		compare(t, "gcloud", a.Gcloud, []command{
			{"access-approval settings get", project},
			{"access-context-manager perimeters list", derived},
			{"access-context-manager policies list", org},
			{"app versions describe", project},
			{"app versions list", project},
			{"artifacts repositories get-iam-policy", project},
			{"artifacts repositories list", project},
			{"compute backend-services list", project},
			{"compute disks list", project},
			{"compute firewall-rules list", project},
			{"compute forwarding-rules list", project},
			{"compute instances list", project},
			{"compute networks get-effective-firewalls", project},
			{"compute networks list", project},
			{"compute networks subnets describe", project},
			{"compute networks subnets list", project},
			{"compute os-config inventories list", project},
			{"compute project-info describe", project},
			{"compute regions list", project},
			{"compute ssl-policies list", project},
			{"compute target-https-proxies list", project},
			{"compute target-ssl-proxies list", project},
			{"container binauthz policy export", project},
			{"dataproc clusters list", project},
			{"dns managed-zones list", project},
			{"dns policies list", project},
			{"essential-contacts list", org},
			{"functions list", project},
			{"iam service-accounts keys list", derived},
			{"iam service-accounts list", project},
			{"kms keyrings list", project},
			{"kms keys get-iam-policy", project},
			{"kms keys list", project},
			{"kms locations list", project},
			{"logging logs list", project},
			{"logging metrics list", project},
			{"logging read", org},
			{"logging sinks list", []rule.Bind{rule.BindProject, rule.BindOrganization}},
			{"monitoring policies list", project},
			{"org-policies describe", project},
			{"organizations get-iam-policy", org},
			{"projects get-iam-policy", project},
			{"projects list", org},
			{"resource-manager folders list", []rule.Bind{rule.BindOrganization, rule.BindDerived}},
			{"services api-keys list", project},
			{"services list", project},
			{"sql instances list", project},
			{"sql users list", project},
			{"storage buckets get-iam-policy", derived},
			{"storage buckets list", project},
		})
		if len(a.Gcloud) != 50 {
			t.Errorf("gcloud has %d entries, want 50", len(a.Gcloud))
		}

		// The file is kept in alphabetical order so that a change shows up as a small diff.
		paths := make([]string, len(a.Gcloud))
		for i, e := range a.Gcloud {
			paths[i] = strings.Join(e.Path, " ")
		}
		for i := 1; i < len(paths); i++ {
			if paths[i-1] >= paths[i] {
				t.Errorf("gcloud paths must be sorted and unique: %q is followed by %q", paths[i-1], paths[i])
			}
		}
	})

	t.Run("engine_gcloud", func(t *testing.T) {
		compare(t, "engine_gcloud", a.EngineGcloud, []command{
			{"--version", none},
			{"config get account", none},
			{"auth print-access-token", none},
			{"projects describe", project},
			{"projects get-ancestors", project},
			{"organizations describe", org},
			{"container clusters list", project},
		})
		if len(a.EngineGcloud) != 7 {
			t.Errorf("engine_gcloud has %d entries, want 7", len(a.EngineGcloud))
		}
	})

	t.Run("kubectl", func(t *testing.T) {
		resources := []string{
			"nodes", "clusterrolebindings", "rolebindings", "clusterroles", "roles", "serviceaccounts", "pods",
			"namespaces", "crd", "networkpolicies", "resourcequotas", "limitranges", "ingresses",
			"managedcertificates.networking.gke.io", "daemonsets", "storageclasses", "replicasets",
		}
		sameSet(t, "kubectl_verbs", a.KubectlVerbs, []string{"get", "api-resources", "version"})
		sameSet(t, "kubectl_resources", a.KubectlResources, resources)
		sameSet(t, "kubectl_flags", a.KubectlFlags, []string{"-o", "--all-namespaces", "--namespace"})
		sameSet(t, "forbidden_kubectl_flags", a.ForbiddenKubectlFlags, []string{
			"--kubeconfig", "--context", "--server", "--token", "--as", "--as-group",
			"--insecure-skip-tls-verify", "--certificate-authority", "--client-certificate", "--client-key",
			"--username", "--password", "--cluster", "--user", "--cache-dir", "--request-timeout",
		})

		for _, r := range resources {
			if !a.KubectlAllowed("get", r) {
				t.Errorf("KubectlAllowed(get, %q) = false, want true", r)
			}
		}
		for _, c := range []struct {
			verb, resource string
			want           bool
		}{
			{"get", "secrets", false},
			{"get", "configmaps", false},
			{"get", "", false},
			{"get", "pods,secrets", false},
			{"get", "Pods", false},
			{"get", "managedcertificates", false},
			// The resource of these two verbs is not looked at.
			{"api-resources", "", true},
			{"version", "", true},
			{"version", "anything", true},
			{"delete", "pods", false},
			{"describe", "pods", false},
			{"exec", "", false},
			{"", "pods", false},
			{"Get", "pods", false},
		} {
			if got := a.KubectlAllowed(c.verb, c.resource); got != c.want {
				t.Errorf("KubectlAllowed(%q, %q) = %v, want %v", c.verb, c.resource, got, c.want)
			}
		}

		// A verb that is added to the data and is not known to be free of a resource must still
		// name a listed resource.
		extended := mustParseAllowlist(t, `
kubectl_verbs: [get, describe, version]
kubectl_resources: [pods]
`)
		for _, c := range []struct {
			verb, resource string
			want           bool
		}{
			{"describe", "pods", true},
			{"describe", "secrets", false},
			{"describe", "", false},
			{"version", "", true},
		} {
			if got := extended.KubectlAllowed(c.verb, c.resource); got != c.want {
				t.Errorf("KubectlAllowed(%q, %q) = %v, want %v", c.verb, c.resource, got, c.want)
			}
		}
	})

	t.Run("rest", func(t *testing.T) {
		if len(a.REST) != 3 {
			t.Fatalf("rest has %d hosts, want 3: %+v", len(a.REST), a.REST)
		}
		for i, host := range []string{"bigquery.googleapis.com", "admin.googleapis.com", "dlp.googleapis.com"} {
			if got := a.REST[i]; got.Host != host || !slices.Equal(got.Methods, []string{"GET"}) {
				t.Errorf("rest[%d] = %+v, want %s with the method GET", i, got, host)
			}
		}
		sameSet(t, "rest_post_suffixes", a.RESTPostSuffixes, []string{
			":getIamPolicy", ":search", ":testIamPermissions", ":getEffectivePolicy", ":getEffectiveIamPolicy",
		})
	})

	t.Run("gcloud flags", func(t *testing.T) {
		sameSet(t, "gcloud_flags", a.GcloudFlags, []string{
			"--effective", "--enabled", "--filter", "--folder", "--format", "--freshness",
			"--iam-account", "--instance", "--keyring", "--limit", "--location", "--managed-by",
			"--organization", "--policy", "--project", "--region", "--service", "--view",
		})
		sameSet(t, "forbidden_gcloud_flags", a.ForbiddenGcloudFlags, []string{
			"--account", "--impersonate-service-account", "--access-token-file", "--configuration",
			"--log-http", "--flags-file", "--billing-project", "--verbosity", "--trace-token",
			"--authority-selector", "--authorization-token-file", "--credential-file-override",
			"--universe-domain",
		})

		// The positive list is kept in alphabetical order so that a change is a small diff.
		for i := 1; i < len(a.GcloudFlags); i++ {
			if a.GcloudFlags[i-1] >= a.GcloudFlags[i] {
				t.Errorf("gcloud_flags must be sorted and unique: %q is followed by %q", a.GcloudFlags[i-1], a.GcloudFlags[i])
			}
		}
	})

	t.Run("the allowlist is not loaded as a rule file", func(t *testing.T) {
		files, violations, err := rule.LoadFiles(rules.FS)
		if err != nil {
			t.Fatalf("LoadFiles: %v", err)
		}
		for _, f := range files {
			if f.Name == "allowlist.yaml" {
				t.Errorf("LoadFiles returned allowlist.yaml as a rule file")
			}
		}
		for _, v := range violations {
			if v.File == "allowlist.yaml" {
				t.Errorf("LoadFiles checked allowlist.yaml as a rule file: %+v", v)
			}
		}
	})
}
