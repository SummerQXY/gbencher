package rule

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const hashPrefix = "sha256:"

// hashRule returns the content hash of one rule: the digest of the canonical JSON of the
// benchmark id and version together with the rule mapping as decoded from the file.
//
// Hashing the decoded mapping, and not the file text or the typed Rule, makes the hash
// independent of key order, comments, quoting and layout, and still sensitive to every value
// the file sets. The path of the file is left out on purpose: moving a rule to another file
// does not change the rule. Benchmark section and title are left out too, since they describe
// the file and not the check.
func hashRule(b Benchmark, mapping map[string]any) (string, error) {
	canonical, err := canonicalJSON(map[string]any{
		"benchmark": map[string]string{"id": b.ID, "version": b.Version},
		"rule":      mapping,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hashPrefix + hex.EncodeToString(sum[:]), nil
}

// hashSet returns the hash of a set: the digest of one "<id>\t<rule hash>\n" line per rule.
// The rules must already be in the order of Set.Rules, which is what makes the result
// independent of how the rules were spread over files.
func hashSet(rules []*Rule) string {
	h := sha256.New()
	for _, r := range rules {
		fmt.Fprintf(h, "%s\t%s\n", r.ID, r.Hash)
	}
	return hashPrefix + hex.EncodeToString(h.Sum(nil))
}

// canonicalJSON encodes v as JSON with object keys in sorted order (encoding/json sorts map
// keys), no insignificant whitespace and no HTML escaping, so the bytes do not depend on
// anything but the data.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
