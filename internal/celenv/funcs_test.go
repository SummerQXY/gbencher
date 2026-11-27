package celenv_test

import (
	"fmt"
	"strings"
	"testing"

	"cel.dev/cel-go/cel"

	"github.com/SummerQXY/gbencher/internal/celenv"
)

// celBool calls the CEL function fn with args and returns its bool result. Every argument
// travels through params, so it reaches the overload as a dyn value, as it does in rules.
func celBool(t *testing.T, env *cel.Env, fn string, args ...any) bool {
	t.Helper()
	names := make([]string, len(args))
	params := make(map[string]any, len(args))
	for i, a := range args {
		key := fmt.Sprintf("a%d", i)
		names[i] = "params." + key
		params[key] = a
	}
	expr := fn + "(" + strings.Join(names, ", ") + ")"
	out, err := eval(t, env, expr, map[string]any{"params": params})
	if err != nil {
		t.Fatalf("%s with %v: %v", expr, args, err)
	}
	got, ok := out.Value().(bool)
	if !ok {
		t.Fatalf("%s with %v returned %T, want bool", expr, args, out.Value())
	}
	return got
}

func TestModeAtMost(t *testing.T) {
	env := newEnv(t, false)
	for _, c := range []struct {
		mode, max string
		want      bool
	}{
		{"644", "644", true},
		{"600", "644", true},
		{"700", "644", false},
		{"abc", "644", false},
		{"0644", "0644", true},
		{"640", "644", true},
		{"400", "644", true},
		{"000", "644", true},
		{"0", "0", true},
		{"755", "644", false},
		{"645", "644", false},
		{"1644", "7777", true},
		{"1644", "0777", false},
		{"7777", "7777", true},
		{"", "644", false},
		{"644", "", false},
		{"8", "777", false},
		{"-1", "777", false},
		{"+6", "777", false},
		{"0o644", "777", false},
		{" 644", "777", false},
		{"644\n", "777", false},
		{"1000000", "777", false},
	} {
		if got := celenv.ModeAtMost(c.mode, c.max); got != c.want {
			t.Errorf("ModeAtMost(%q, %q) = %v, want %v", c.mode, c.max, got, c.want)
		}
		if got := celBool(t, env, "modeAtMost", c.mode, c.max); got != c.want {
			t.Errorf("CEL modeAtMost(%q, %q) = %v, want %v", c.mode, c.max, got, c.want)
		}
	}
}

func TestPortRangeContains(t *testing.T) {
	env := newEnv(t, false)
	for _, c := range []struct {
		rng  string
		port int64
		want bool
	}{
		{"22", 22, true},
		{"20-30", 25, true},
		{"", 8080, true}, // the empty range stands for every port
		{"20-30", 31, false},
		{"x", 1, false},

		{"22", 23, false},
		{"20-30", 20, true},
		{"20-30", 30, true},
		{"20-30", 19, false},
		{"22-22", 22, true},
		{"0", 0, true},
		{"65535", 65535, true},
		{"0-65535", 12345, true},
		{"", 0, true},
		{"", 65535, true},

		// Malformed ranges contain no port.
		{"1-2-3", 1, false},
		{"1-2-3", 2, false},
		{"5-1", 3, false},
		{"-3", 3, false},
		{"a-b", 1, false},
		{"22-", 22, false},
		{"-", 0, false},
		{" 22", 22, false},
		{"22 ", 22, false},
		{"+22", 22, false},
		{"0x16", 22, false},
		{"1e3", 1000, false},
		{"65536", 65535, false},
		{"0-65536", 1, false},

		// A value that is not a port is contained in no range, not even the empty one.
		{"", -1, false},
		{"", 65536, false},
		{"0-65535", 70000, false},
	} {
		if got := celenv.PortRangeContains(c.rng, c.port); got != c.want {
			t.Errorf("PortRangeContains(%q, %d) = %v, want %v", c.rng, c.port, got, c.want)
		}
		if got := celBool(t, env, "portRangeContains", c.rng, c.port); got != c.want {
			t.Errorf("CEL portRangeContains(%q, %d) = %v, want %v", c.rng, c.port, got, c.want)
		}
	}

	// A dyn argument of the wrong runtime type is an evaluation error, not a panic or a false.
	_, err := eval(t, env, "portRangeContains(params.a, params.b)",
		map[string]any{"params": map[string]any{"a": int64(22), "b": int64(22)}})
	if err == nil {
		t.Error("portRangeContains with an int range did not fail")
	}
}

func TestCidrIsPublic(t *testing.T) {
	env := newEnv(t, false)
	for _, c := range []struct {
		cidr string
		want bool
	}{
		{"0.0.0.0/0", true},
		{"::/0", true},
		{"1.2.3.4/0", true}, // any spelling with a zero-length prefix
		{"10.0.0.0/8", false},

		{"0.0.0.0/1", false},
		{"0.0.0.0", false}, // a single address is a /32
		{"::", false},      // a single address is a /128
		{"8.8.8.8/32", false},
		{"not-an-ip", false},
		{"", false},
		{"0.0.0.0/33", false},
		{"::/129", false},
		{"0.0.0.0/", false},
		{"/0", false},
	} {
		if got := celenv.CidrIsPublic(c.cidr); got != c.want {
			t.Errorf("CidrIsPublic(%q) = %v, want %v", c.cidr, got, c.want)
		}
		if got := celBool(t, env, "cidrIsPublic", c.cidr); got != c.want {
			t.Errorf("CEL cidrIsPublic(%q) = %v, want %v", c.cidr, got, c.want)
		}
	}
}

func TestCidrIsPrivate(t *testing.T) {
	env := newEnv(t, false)
	for _, c := range []struct {
		cidr string
		want bool
	}{
		{"10.1.2.3", true},
		{"172.16.0.0/12", true},
		{"100.64.0.0/10", true},
		{"169.254.1.1", true},
		{"fc00::/7", true},
		{"fe80::1", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"172.32.0.1", false},
		{"8.8.8.8", false},
		{"not-an-ip", false},

		{"10.0.0.0/8", true},
		{"10.1.2.3/8", true}, // host bits do not matter
		{"192.168.1.0/24", true},
		{"172.31.255.255", true},
		{"100.127.255.255", true},
		{"127.0.0.0/8", true},
		{"169.254.0.0/16", true},
		{"fd12:3456::/32", true},
		{"fe80::/10", true},
		{"::1/128", true},

		// A block is private only when every address in it is.
		{"10.0.0.0/7", false},
		{"172.16.0.0/11", false},
		{"0.0.0.0/0", false},
		{"::/0", false},
		{"fc00::/6", false},

		{"172.15.255.255", false},
		{"100.128.0.1", false},
		{"192.169.0.1", false},
		{"2001:db8::1", false},
		{"::2", false},
		{"", false},
		{"10.0.0.0/33", false},
		{"10.0.0.256", false},
		{"fe80::1%eth0", false}, // a zone is not part of a CIDR block
	} {
		if got := celenv.CidrIsPrivate(c.cidr); got != c.want {
			t.Errorf("CidrIsPrivate(%q) = %v, want %v", c.cidr, got, c.want)
		}
		if got := celBool(t, env, "cidrIsPrivate", c.cidr); got != c.want {
			t.Errorf("CEL cidrIsPrivate(%q) = %v, want %v", c.cidr, got, c.want)
		}
	}
}

func TestCidrContains(t *testing.T) {
	env := newEnv(t, false)
	for _, c := range []struct {
		outer, inner string
		want         bool
	}{
		{"10.0.0.0/8", "10.1.0.0/16", true},
		{"10.1.0.0/16", "10.0.0.0/8", false},
		{"10.0.0.0/8", "10.2.3.4", true},
		{"10.0.0.0/8", "::1", false},

		{"10.0.0.0/8", "10.0.0.0/8", true},
		{"10.0.0.0/8", "11.0.0.0/8", false},
		{"10.0.0.0/9", "10.0.0.0/8", false},
		{"10.1.2.3/8", "10.9.9.9", true},         // host bits of outer do not matter
		{"10.0.0.0/16", "10.0.255.255/16", true}, // host bits of inner do not matter
		{"10.0.0.1", "10.0.0.1", true},           // a single address is a /32
		{"10.0.0.1", "10.0.0.2", false},
		{"10.0.0.0/8", "10.0.0.0/7", false},
		{"0.0.0.0/0", "10.0.0.0/8", true},
		{"::/0", "2001:db8::/32", true},
		{"2001:db8::/32", "::/0", false},
		{"2001:db8::1", "2001:db8::1", true}, // a single address is a /128

		// Blocks of different address families never contain each other.
		{"::/0", "10.0.0.0/8", false},
		{"0.0.0.0/0", "::1", false},
		{"0.0.0.0/0", "::/0", false},
		{"::/0", "0.0.0.0/0", false},

		{"not-a-cidr", "10.0.0.0/8", false},
		{"10.0.0.0/8", "not-a-cidr", false},
		{"10.0.0.0/8", "10.0.0.0/33", false},
		{"10.0.0.0/33", "10.0.0.1", false},
		{"", "", false},
	} {
		if got := celenv.CidrContains(c.outer, c.inner); got != c.want {
			t.Errorf("CidrContains(%q, %q) = %v, want %v", c.outer, c.inner, got, c.want)
		}
		if got := celBool(t, env, "cidrContains", c.outer, c.inner); got != c.want {
			t.Errorf("CEL cidrContains(%q, %q) = %v, want %v", c.outer, c.inner, got, c.want)
		}
	}
}
