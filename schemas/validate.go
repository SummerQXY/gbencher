package schemas

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"go.yaml.in/yaml/v3"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// ValidateJSON validates a JSON document against the named schema. A nil result means the
// document conforms; otherwise the error is a schema violation (see Issues) or says why the
// document could not be checked.
func ValidateJSON(name string, doc []byte) error {
	sch, err := Compile(name)
	if err != nil {
		return err
	}
	return validate(sch, doc)
}

// ValidateYAML validates a YAML document, or a JSON one, against the named schema.
//
// The document is converted to JSON first, so a YAML timestamp is validated as a string and
// a value JSON cannot hold (a non-string mapping key, NaN, infinity) is an error. It must
// contain exactly one YAML document.
func ValidateYAML(name string, doc []byte) error {
	sch, err := Compile(name)
	if err != nil {
		return err
	}
	j, err := yamlToJSON(doc)
	if err != nil {
		return err
	}
	return validate(sch, j)
}

func validate(sch *jsonschema.Schema, doc []byte) error {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	return sch.Validate(v)
}

func yamlToJSON(doc []byte) ([]byte, error) {
	dec := yaml.NewDecoder(bytes.NewReader(doc))

	// An empty document decodes to nil, which the schemas then report as a type violation.
	var v any
	if err := dec.Decode(&v); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode yaml: %w", err)
	}
	// A second document would be skipped silently by a single decode and never checked.
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return nil, errors.New("decode yaml: more than one document")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode yaml: %w", err)
	}

	j, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("convert yaml to json: %w", err)
	}
	return j, nil
}

// Issue is one schema violation.
type Issue struct {
	// Path is a JSON Pointer to the offending value, such as /rules/0/ref. It is empty for
	// the document root.
	Path    string
	Message string
}

var (
	printer    = message.NewPrinter(language.English)
	pointerEsc = strings.NewReplacer("~", "~0", "/", "~1")
)

// Issues flattens the leaf violations of an error returned by ValidateJSON or ValidateYAML,
// sorted by path and then message. It returns nil for a nil error and for errors that are
// not schema violations, such as a document that failed to parse.
func Issues(err error) []Issue {
	var verr *jsonschema.ValidationError
	if !errors.As(err, &verr) {
		return nil
	}
	var out []Issue
	collectIssues(verr, &out)
	slices.SortFunc(out, func(a, b Issue) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Message, b.Message))
	})
	return out
}

func collectIssues(e *jsonschema.ValidationError, out *[]Issue) {
	if len(e.Causes) > 0 {
		for _, c := range e.Causes {
			collectIssues(c, out)
		}
		return
	}
	var sb strings.Builder
	for _, tok := range e.InstanceLocation {
		sb.WriteByte('/')
		sb.WriteString(pointerEsc.Replace(tok))
	}
	*out = append(*out, Issue{Path: sb.String(), Message: issueMessage(e.ErrorKind)})
}

func issueMessage(k jsonschema.ErrorKind) string {
	// The schemas forbid a property with a false schema, whose library wording says nothing
	// useful to a rule author.
	if _, ok := k.(*kind.FalseSchema); ok {
		return "not allowed here"
	}
	return k.LocalizedString(printer)
}
