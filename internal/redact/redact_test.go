package redact

import "testing"

func TestString_KnownPatternsAreRedacted(t *testing.T) {
	input := "token ya29.access-token key AIzaExampleKey bearer Bearer abc.def_123.pem -----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"
	got := String(input)
	for _, secret := range []string{"ya29.access-token", "AIzaExampleKey", "Bearer abc.def_123", "secret"} {
		if contains(got, secret) {
			t.Errorf("String() retained %q in %q", secret, got)
		}
	}
}

func TestString_PreservesOrdinaryText(t *testing.T) {
	const input = "ordinary diagnostic text"
	if got := String(input); got != input {
		t.Fatalf("String() = %q, want %q", got, input)
	}
}

func TestStripControl_RemovesEscapeSequences(t *testing.T) {
	if got, want := StripControl("\x1b[31mred\x1b[0m\nnext\tline\x00"), "red\nnext\tline"; got != want {
		t.Fatalf("StripControl() = %q, want %q", got, want)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
