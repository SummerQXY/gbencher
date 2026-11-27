// Package schemas embeds the JSON Schemas that define the rule, profile, report and
// catalog contracts, and validates documents against them.
package schemas

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// FS holds the schema documents. Each file is named <name>.schema.json and declares the
// $id urn:gbench:schema:<name>:<major>.
//
//go:embed *.schema.json
var FS embed.FS

const (
	fileSuffix = ".schema.json"
	idPrefix   = "urn:gbench:schema:"
)

var (
	compileMu sync.Mutex
	compiled  = map[string]*jsonschema.Schema{}
)

// Compile returns the schema called name: "rule", "profile", "report" or "catalog".
// Compiled schemas are cached, and the package is safe for concurrent use.
func Compile(name string) (*jsonschema.Schema, error) {
	compileMu.Lock()
	defer compileMu.Unlock()

	if sch, ok := compiled[name]; ok {
		return sch, nil
	}
	sch, err := compile(name)
	if err != nil {
		return nil, err
	}
	compiled[name] = sch
	return sch, nil
}

func compile(name string) (*jsonschema.Schema, error) {
	raw, err := FS.ReadFile(name + fileSuffix)
	if err != nil {
		return nil, fmt.Errorf("unknown schema %q (known: %s)", name, strings.Join(knownNames(), ", "))
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("schema %q: %w", name, err)
	}

	// The $id is the URN under which the schema is registered and compiled. Requiring the
	// name inside it keeps every file consistent with its file name.
	obj, _ := doc.(map[string]any)
	id, _ := obj["$id"].(string)
	if !strings.HasPrefix(id, idPrefix+name+":") {
		return nil, fmt.Errorf("schema %q: $id %q must start with %q", name, id, idPrefix+name+":")
	}

	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(noLoader{})
	if err := c.AddResource(id, doc); err != nil {
		return nil, fmt.Errorf("schema %q: %w", name, err)
	}
	sch, err := c.Compile(id)
	if err != nil {
		return nil, fmt.Errorf("schema %q: %w", name, err)
	}
	return sch, nil
}

func knownNames() []string {
	entries, _ := fs.ReadDir(FS, ".")
	var names []string
	for _, e := range entries {
		if n, ok := strings.CutSuffix(e.Name(), fileSuffix); ok {
			names = append(names, n)
		}
	}
	return names
}

// noLoader keeps compilation self-contained: a reference that leaves the embedded
// documents fails instead of reading the filesystem or the network.
type noLoader struct{}

func (noLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external schema reference %q is not allowed", url)
}
