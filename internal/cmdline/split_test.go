package cmdline_test

import (
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/SummerQXY/gbencher/internal/cmdline"
)

// lit and act build the parts a word is expected to have.
func lit(s string) cmdline.Part { return cmdline.Part{Text: s} }
func act(s string) cmdline.Part { return cmdline.Part{Text: s, Action: true} }

// wordParts returns the parts of every word, which is all the cases below care about.
func wordParts(words []cmdline.Word) [][]cmdline.Part {
	out := make([][]cmdline.Part, len(words))
	for i, w := range words {
		out[i] = w.Parts
	}
	return out
}

func TestSplit_WordsQuotesAndActions(t *testing.T) {
	type words = [][]cmdline.Part
	cases := []struct {
		name     string
		template string
		want     words
	}{
		{"plain words with runs of spaces", "compute  instances   list",
			words{{lit("compute")}, {lit("instances")}, {lit("list")}}},
		{"tab, carriage return and newline separate words", "a\tb\nc\r\nd",
			words{{lit("a")}, {lit("b")}, {lit("c")}, {lit("d")}}},
		{"leading and trailing white space", "  \t a b \n ",
			words{{lit("a")}, {lit("b")}}},
		{"blank template has no words", "", nil},
		{"white space only has no words", " \t\r\n ", nil},

		{"single quotes group", "'a b' c", words{{lit("a b")}, {lit("c")}}},
		{"double quotes group", `"a b" c`, words{{lit("a b")}, {lit("c")}}},
		{"each kind of quote keeps the other", `"it's" 'say "x"'`, words{{lit("it's")}, {lit(`say "x"`)}}},
		{"quotes in the middle of a word", `a"b c"d`, words{{lit("ab cd")}}},
		{"text after a closing quote joins the word", `'a'b'c d'`, words{{lit("abc d")}}},
		{"quoted white space is kept", "'a\tb\nc'", words{{lit("a\tb\nc")}}},

		{"a pair of empty quotes is an empty word", `a '' b`, words{{lit("a")}, {}, {lit("b")}}},
		{"a pair of double quotes alone", `""`, words{{}}},
		{"an empty word at the end", `a ""`, words{{lit("a")}, {}}},
		{"empty quotes inside a word add nothing", `x''y`, words{{lit("xy")}}},
		{"empty quotes before a flag leave the flag", `''-x`, words{{lit("-x")}}},

		{"a flag with an action is one word of two parts", "--policy={{ .policy }}",
			words{{lit("--policy="), act("{{ .policy }}")}}},
		{"a whole word that is one action", "get {{ .x }}", words{{lit("get")}, {act("{{ .x }}")}}},
		{"white space and quotes inside an action do not split", `{{ "x y" }}`, words{{act(`{{ "x y" }}`)}}},
		{"single quotes inside an action", `{{ 'a b' }}`, words{{act(`{{ 'a b' }}`)}}},
		{"an action inside quotes is an action part", `--filter="parent.id={{ .organization }}"`,
			words{{lit("--filter=parent.id="), act("{{ .organization }}")}}},
		{"quoted text with white space around an action", `--filter="name:x parent.id={{ .organization }}"`,
			words{{lit("--filter=name:x parent.id="), act("{{ .organization }}")}}},
		{"an action inside single quotes", `'{{ .x }}'`, words{{act("{{ .x }}")}}},
		{"an action that holds the quote of its own text", `"a {{ "x" }} b"`,
			words{{lit("a "), act(`{{ "x" }}`), lit(" b")}}},
		{"adjacent actions", "{{ .a }}{{ .b }}", words{{act("{{ .a }}"), act("{{ .b }}")}}},
		{"literal, action, literal", "pre-{{ .x }}-post", words{{lit("pre-"), act("{{ .x }}"), lit("-post")}}},
		{"trim markers stay in the action", "{{- .x -}}", words{{act("{{- .x -}}")}}},
		{"a comment is an action part too", "a{{/* c */}}b", words{{lit("a"), act("{{/* c */}}"), lit("b")}}},
		{"an action may be empty", "{{}}", words{{act("{{}}")}}},
		{"an action ends at the first closing braces", "{{ .a }}}", words{{act("{{ .a }}"), lit("}")}}},
		{"an action holds new lines", "a {{ .x\n   | printf \"%s\" }} c",
			words{{lit("a")}, {act("{{ .x\n   | printf \"%s\" }}")}, {lit("c")}}},
		{"two actions of one construct are two parts", "a {{ if .x }}\nb{{ end }} c",
			words{{lit("a")}, {act("{{ if .x }}")}, {lit("b"), act("{{ end }}")}, {lit("c")}}},

		{"logging read with a quoted filter",
			`logging read 'protoPayload.serviceName="a.example" OR protoPayload.serviceName="b.example"' --limit=1`,
			words{{lit("logging")}, {lit("read")},
				{lit(`protoPayload.serviceName="a.example" OR protoPayload.serviceName="b.example"`)}, {lit("--limit=1")}}},

		{"single braces and closing braces are text", "{a} b}} {", words{{lit("{a}")}, {lit("b}}")}, {lit("{")}}},
		{"multi-byte text and non-ASCII spaces are ordinary", "\u540d\u524d a\u00a0b",
			words{{lit("\u540d\u524d")}, {lit("a\u00a0b")}}},
		{"a vertical tab and a form feed are ordinary", "a\vb\fc", words{{lit("a\vb\fc")}}},
		{"a byte that is not UTF-8 passes through", "a\xffb", words{{lit("a\xffb")}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := cmdline.Split(c.template)
			if err != nil {
				t.Fatalf("Split(%q): %v", c.template, err)
			}
			if !slices.EqualFunc(wordParts(got), c.want, slices.Equal) {
				t.Errorf("Split(%q)\n got  %+v\n want %+v", c.template, wordParts(got), c.want)
			}
		})
	}
}

func TestSplit_UnterminatedQuoteAndActionAreErrors(t *testing.T) {
	cases := []struct {
		template string
		reason   string // what the message names as not closed
	}{
		{`'abc`, "quote"},
		{`"abc`, "quote"},
		{`{{ .x`, "action"},
		{`a {{ .x b`, "action"},
		{`'`, "quote"},
		{`"`, "quote"},
		{`{{`, "action"},
		{`{{}`, "action"},
		{`a "b {{ .x }}`, "quote"},
		{`"a {{ .x"`, "action"}, // the action swallows the closing quote
		{`a 'b' 'c`, "quote"},
		{`x '' "`, "quote"},
		{`{{ .a }} {{ .b`, "action"},
	}
	for _, c := range cases {
		t.Run(c.template, func(t *testing.T) {
			got, err := cmdline.Split(c.template)
			if err == nil {
				t.Fatalf("Split(%q) = %+v, want an error", c.template, got)
			}
			if got != nil {
				t.Errorf("Split(%q) returned words %+v with its error", c.template, got)
			}
			msg := err.Error()
			if !strings.Contains(msg, c.reason) {
				t.Errorf("error %q does not name the %s that is not closed", msg, c.reason)
			}
			// The message is shown to people next to rule text: one line, and it never repeats the template.
			if strings.IndexFunc(msg, unicode.IsControl) >= 0 || strings.Contains(msg, "abc") {
				t.Errorf("error %q has a control character or repeats the template", msg)
			}
		})
	}
}

func TestSplit_BackslashIsOrdinary(t *testing.T) {
	cases := []struct {
		name     string
		template string
		want     []string
	}{
		{"a backslash does not keep a space in the word", `a\ b`, []string{`a\`, "b"}},
		{"a backslash inside a word", `C:\dir\x`, []string{`C:\dir\x`}},
		{"a backslash and a letter are two characters", `\n`, []string{`\n`}},
		{"a backslash before a closing double quote", `"a\"`, []string{`a\`}},
		{"a backslash before a closing single quote", `'a\'`, []string{`a\`}},
		{"a backslash before a quote does not escape it", `a\"b c"`, []string{`a\b c`}},
		{"a backslash in front of braces", `\{{ .x }}`, []string{`\{{ .x }}`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := cmdline.Split(c.template)
			if err != nil {
				t.Fatalf("Split(%q): %v", c.template, err)
			}
			var texts []string
			for _, w := range got {
				texts = append(texts, w.String())
			}
			if !slices.Equal(texts, c.want) {
				t.Errorf("Split(%q) = %q, want %q", c.template, texts, c.want)
			}
		})
	}

	// The quote after a backslash still opens a quote, so this one never closes.
	if got, err := cmdline.Split(`a\"b`); err == nil || got != nil {
		t.Errorf("Split(%q) = %+v, %v; want an error for the quote that is never closed", `a\"b`, got, err)
	}
}

func TestSplit_StringJoinsPartsWithoutQuotes(t *testing.T) {
	cases := []struct {
		template string
		want     []string
	}{
		{`a"b c"d`, []string{"ab cd"}},
		{`--filter="x {{ .organization }}"`, []string{"--filter=x {{ .organization }}"}},
		{`'{{ .x }}'`, []string{"{{ .x }}"}},
		{`{{ .a }}{{ .b }}`, []string{"{{ .a }}{{ .b }}"}},
		{`--policy={{ .policy }} 'p q' ""`, []string{"--policy={{ .policy }}", "p q", ""}},
		{`'' ""`, []string{"", ""}},
		{`--for"mat"=json`, []string{"--format=json"}},
	}
	for _, c := range cases {
		t.Run(c.template, func(t *testing.T) {
			got, err := cmdline.Split(c.template)
			if err != nil {
				t.Fatalf("Split(%q): %v", c.template, err)
			}
			var texts []string
			for _, w := range got {
				texts = append(texts, w.String())
			}
			if !slices.Equal(texts, c.want) {
				t.Errorf("Split(%q).String() = %q, want %q", c.template, texts, c.want)
			}
		})
	}

	if got := (cmdline.Word{}).String(); got != "" {
		t.Errorf("the zero Word has String() = %q, want an empty string", got)
	}
	if got := (cmdline.Word{Parts: []cmdline.Part{{Text: "a"}, {Text: "{{ .x }}", Action: true}, {Text: "b"}}}).String(); got != "a{{ .x }}b" {
		t.Errorf("String() joins the parts in order, got %q", got)
	}
}
