package rule

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/SummerQXY/gbencher/schemas"
)

// maxFileBytes is the largest rule file that is parsed. The real files are tens of kilobytes;
// the limit keeps an accidental or hostile file from being parsed at all.
const maxFileBytes = 1 << 20

// MaxMappingKeys is the most keys any single mapping in a rule or profile file may have. The
// YAML decoder compares the keys of a mapping pairwise before it decodes the mapping, so its
// time grows with the square of the key count: a mapping of about a hundred thousand keys fits
// in a file under the size limit and takes a minute or more to decode. Real files stay far
// below this limit.
const MaxMappingKeys = 1000

// fileDoc is the top-level shape of a rule file. The rules stay raw nodes so that each one is
// decoded, and hashed, from its own mapping.
type fileDoc struct {
	DSLVersion int         `yaml:"dsl_version"`
	Benchmark  Benchmark   `yaml:"benchmark"`
	Rules      []yaml.Node `yaml:"rules"`
}

// ParseFile parses one rule file. name is the path of the file relative to the loaded root,
// with forward slashes; it is recorded on the file, on its rules and on every violation.
//
// The two kinds of failure are kept apart. When the YAML itself is unusable ParseFile returns
// an error and nothing else; its message starts with one of
//
//	yaml-too-large       the file is larger than 1 MiB, or a mapping has more than
//	                     MaxMappingKeys keys
//	yaml-syntax          the parser rejected the text (a tab used for indentation, an
//	                     unterminated flow, a second document, ...)
//	yaml-alias           an anchor or an alias; rule files have no use for them, and expanding
//	                     them is how a small file becomes a huge one
//	yaml-duplicate-key   a mapping that repeats a key, so the file does not say which of the
//	                     values is meant
//
// Everything else is a violation. The document is checked against the rule schema as it is
// written, so a value such as an unquoted ref: 6.1 is reported at /rules/0/ref instead of
// being read as the string "6.1". Whenever the YAML parsed, the returned File is non-nil and
// holds as much of the file as could be decoded, even if there are violations, so that later
// checks can still look at it.
//
// Each rule gets its Benchmark, SourceFile and Hash. The hash is "sha256:" followed by 64
// lowercase hex digits over the canonical JSON (sorted keys) of the rule as written in the
// file and the benchmark id and version. It does not depend on key order, comments,
// formatting or the file name.
func ParseFile(name string, data []byte) (*File, []Violation, error) {
	doc, err := parseChecked(data)
	if err != nil {
		return nil, nil, err
	}

	violations := schemaViolations(name, data)

	f := &File{Name: name}
	if doc.Kind == 0 {
		return f, violations, nil // an empty file; the schema check has already said so
	}
	var top fileDoc
	// A value of the wrong type leaves its field empty. The schema check above is the
	// authority on what a valid file looks like, so the decoding error adds nothing to it.
	_ = doc.Decode(&top)
	f.DSLVersion, f.Benchmark = top.DSLVersion, top.Benchmark

	for i := range top.Rules {
		node := &top.Rules[i]
		if node.Kind != yaml.MappingNode {
			continue // not a rule; the schema check has reported /rules/<i>
		}
		r, err := decodeRule(name, top.Benchmark, node)
		if err != nil {
			violations = append(violations, Violation{
				File:    name,
				Path:    fmt.Sprintf("/rules/%d", i),
				Message: "cannot compute the rule hash: " + err.Error(),
			})
		}
		f.Rules = append(f.Rules, r)
	}
	return f, violations, nil
}

// decodeRule decodes the rule mapping at node and fills in the fields the loader owns. The
// returned error says why the content hash could not be computed; the rule is returned with
// an empty Hash in that case.
func decodeRule(name string, b Benchmark, node *yaml.Node) (*Rule, error) {
	r := &Rule{Benchmark: b, SourceFile: name}
	_ = node.Decode(r) // best effort, as for the file as a whole

	var mapping map[string]any
	if err := node.Decode(&mapping); err != nil {
		return r, err
	}
	hash, err := hashRule(b, mapping)
	if err != nil {
		return r, err
	}
	r.Hash = hash
	return r, nil
}

// CheckYAMLShape reports whether data holds at most one YAML document and whether that
// document stays within the limits every rule and profile file must meet: at most 1 MiB, no
// anchors or aliases, no repeated mapping keys and no mapping with more than MaxMappingKeys
// keys. Nothing is decoded into Go values, so the work is linear in the size of data. It is
// meant to run before the document is handed to a decoder or a schema check. The error
// message starts with one of the prefixes described on ParseFile.
func CheckYAMLShape(data []byte) error {
	_, err := parseChecked(data)
	return err
}

// parseChecked applies the limits of CheckYAMLShape and returns the parsed document. A file
// with no document at all yields a zero node.
func parseChecked(data []byte) (*yaml.Node, error) {
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("yaml-too-large: file is larger than %d bytes", maxFileBytes)
	}
	doc, err := parseDocument(data)
	if err != nil {
		return nil, err
	}
	if err := checkNodes(doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// parseDocument parses data, which may hold at most one YAML document, into a node tree. A
// file with no document at all yields a zero node.
func parseDocument(data []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return &doc, nil
		}
		return nil, syntaxError(err)
	}

	// Decoding reads one document and ignores the rest, which would then go unchecked.
	var next yaml.Node
	switch err := dec.Decode(&next); {
	case err == nil:
		return nil, errors.New("yaml-syntax: more than one document")
	case !errors.Is(err, io.EOF):
		return nil, syntaxError(err)
	}
	return &doc, nil
}

func syntaxError(err error) error {
	return fmt.Errorf("yaml-syntax: %s", strings.TrimPrefix(err.Error(), "yaml: "))
}

// checkNodes walks the node tree in document order and returns the first anchor, alias,
// oversized mapping or repeated mapping key. It works on the tree, before anything is
// decoded, so aliases are never expanded, an oversized mapping never reaches the decoder, and
// every error carries the line it was found on.
func checkNodes(n *yaml.Node) error {
	if n.Anchor != "" || n.Kind == yaml.AliasNode {
		return fmt.Errorf("yaml-alias: line %d: anchors and aliases are not allowed", n.Line)
	}

	if n.Kind == yaml.MappingNode {
		// Content alternates key, value.
		if keys := len(n.Content) / 2; keys > MaxMappingKeys {
			return fmt.Errorf("yaml-too-large: line %d: mapping has %d keys, limit is %d", n.Line, keys, MaxMappingKeys)
		}

		// Same notion of "the same key" as the YAML decoder: equal scalar text, however it
		// is quoted.
		firstLine := make(map[string]int, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode {
				continue
			}
			if first, seen := firstLine[key.Value]; seen {
				return fmt.Errorf("yaml-duplicate-key: line %d: mapping key %q already defined at line %d", key.Line, key.Value, first)
			}
			firstLine[key.Value] = key.Line
		}
	}

	for _, child := range n.Content {
		if err := checkNodes(child); err != nil {
			return err
		}
	}
	return nil
}

// schemaViolations checks the document, as written, against the rule schema.
func schemaViolations(name string, data []byte) []Violation {
	err := schemas.ValidateYAML("rule", data)
	if err == nil {
		return nil
	}
	issues := schemas.Issues(err)
	if len(issues) == 0 {
		// Not a schema violation: the document could not be checked at all, for instance
		// because a mapping key is not a string and so has no JSON form.
		return []Violation{{File: name, Message: err.Error()}}
	}
	out := make([]Violation, len(issues))
	for i, is := range issues {
		out[i] = Violation{File: name, Path: is.Path, Message: is.Message}
	}
	return out
}
