// Package cmdline splits the text of a command step of a rule into words. A command is written as
// words separated by white space, with quotes to group text and {{ ... }} actions that stand for
// values when the command is rendered.
//
// The lint of rules and the rendering of commands use this one splitter, so the words the lint
// checks are the words that are run. The package imports nothing from this repository.
package cmdline

import (
	"fmt"
	"strings"
)

// Part is a piece of a word: literal text, or one template action.
type Part struct {
	// Text is the literal text with its quotes removed, or, for an action, the action as it was
	// written, from "{{" to the closing "}}".
	Text   string
	Action bool
}

// Word is one word of a command. Literal text that is next to other literal text is one part,
// whatever the quotes around it, and no literal part is empty, so a word that is made of an empty
// pair of quotes has no parts.
type Word struct{ Parts []Part }

// String returns the word as the text of its parts, one after the other: the quotes are gone and
// an action is as it was written.
func (w Word) String() string {
	var b strings.Builder
	for _, p := range w.Parts {
		b.WriteString(p.Text)
	}
	return b.String()
}

// Split splits template into words.
//
//   - White space (a space, a tab, a carriage return or a new line) separates words, except inside
//     quotes and actions.
//   - Single and double quotes group the text between them and are removed. A quote can start and
//     end in the middle of a word, so a"b c"d is one word, and a pair of empty quotes is an empty
//     word, as in a shell.
//   - "{{" up to the next "}}" is an action. It is kept as it was written and white space and
//     quotes in it do not split. Inside quotes an action is still an action.
//   - A backslash is an ordinary character.
//
// A quote or an action that is not closed is an error, and no words are returned.
func Split(template string) ([]Word, error) {
	var (
		words   []Word
		parts   []Part
		literal strings.Builder
		inWord  bool // a word has started: it has text, an action, or a pair of quotes
		quote   byte // the quote that is open, or 0
		quoteAt int  // where it was opened
	)
	endLiteral := func() {
		if literal.Len() > 0 {
			parts = append(parts, Part{Text: literal.String()})
			literal.Reset()
		}
	}
	endWord := func() {
		if inWord {
			endLiteral()
			words = append(words, Word{Parts: parts})
			parts, inWord = nil, false
		}
	}

	// Every character that matters is ASCII, so the text is read by bytes: a character that is
	// longer, or that is not valid UTF-8, is copied as it is.
	for i := 0; i < len(template); {
		c := template[i]
		switch {
		case c == '{' && strings.HasPrefix(template[i:], "{{"):
			n := strings.Index(template[i+2:], "}}")
			if n < 0 {
				return nil, fmt.Errorf("unterminated action that starts at byte %d", i)
			}
			end := i + 2 + n + 2
			endLiteral()
			parts = append(parts, Part{Text: template[i:end], Action: true})
			inWord = true
			i = end
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				literal.WriteByte(c)
			}
			i++
		case c == '\'' || c == '"':
			quote, quoteAt, inWord = c, i, true
			i++
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			endWord()
			i++
		default:
			literal.WriteByte(c)
			inWord = true
			i++
		}
	}
	if quote != 0 {
		kind := "double"
		if quote == '\'' {
			kind = "single"
		}
		return nil, fmt.Errorf("unterminated %s quote that starts at byte %d", kind, quoteAt)
	}
	endWord()
	return words, nil
}
