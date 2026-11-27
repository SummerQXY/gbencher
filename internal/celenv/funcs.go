package celenv

import (
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
)

const (
	maxPort     = 65535
	nanosPerDay = int64(24 * time.Hour)
)

// privateRanges holds the blocks that the CidrIsPrivate documentation lists.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"),
}

// PortRangeContains reports whether port lies in the range rng: a single port ("22"), an
// inclusive range ("20-30"), or the empty string, which stands for every port. Port numbers
// are decimal and within 0-65535. It yields false for a port outside that span, for an rng
// that is not one of those forms (such as "1-2-3" or "a-b"), and for a range that ends
// before it starts.
func PortRangeContains(rng string, port int64) bool {
	if port < 0 || port > maxPort {
		return false
	}
	if rng == "" {
		return true
	}
	loText, hiText, isRange := strings.Cut(rng, "-")
	lo, ok := parsePort(loText)
	if !ok {
		return false
	}
	hi := lo
	if isRange {
		if hi, ok = parsePort(hiText); !ok {
			return false
		}
	}
	// A range whose end precedes its start is empty, so it contains no port.
	return port >= lo && port <= hi
}

// parsePort accepts only decimal digits that make a value in 0-65535: no sign, no spaces.
func parsePort(s string) (int64, bool) {
	n, err := strconv.ParseUint(s, 10, 16)
	return int64(n), err == nil
}

// ModeAtMost reports whether every permission bit set in mode is also set in limit, that is
// mode &^ limit == 0. Both are octal strings such as "644"; anything else yields false. The
// parse is bounded to 16 bits, far above the 12 permission bits, so real modes always fit.
func ModeAtMost(mode, limit string) bool {
	m, err := strconv.ParseUint(mode, 8, 16)
	if err != nil {
		return false
	}
	l, err := strconv.ParseUint(limit, 8, 16)
	return err == nil && m&^l == 0
}

// CidrIsPublic reports whether s has a zero-length prefix, such as 0.0.0.0/0 or ::/0, and so
// matches every address of its family. s is a CIDR block or a single address, which counts as
// a /32 or /128 block; anything that does not parse yields false.
func CidrIsPublic(s string) bool {
	p, ok := parseCIDR(s)
	return ok && p.Bits() == 0
}

// CidrIsPrivate reports whether s lies entirely within one of the private, link-local or
// loopback ranges 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16,
// 127.0.0.0/8, fc00::/7, fe80::/10 and ::1/128. s is a CIDR block or a single address, which
// counts as a /32 or /128 block; anything that does not parse yields false.
func CidrIsPrivate(s string) bool {
	p, ok := parseCIDR(s)
	return ok && slices.ContainsFunc(privateRanges, func(r netip.Prefix) bool { return covers(r, p) })
}

// CidrContains reports whether inner lies entirely within outer. Each is a CIDR block or a
// single address, which counts as a /32 or /128 block; anything that does not parse yields
// false, and so does a pair from different address families.
func CidrContains(outer, inner string) bool {
	o, ok := parseCIDR(outer)
	if !ok {
		return false
	}
	i, ok := parseCIDR(inner)
	return ok && covers(o, i)
}

// parseCIDR parses a CIDR block, or a single address as the /32 or /128 block that holds only
// that address. An address with an IPv6 zone is rejected, as it is in the block form.
func parseCIDR(s string) (netip.Prefix, bool) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p, err == nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// covers reports whether every address of inner is also in outer. Host bits set in either block
// are ignored. Blocks of different address families never cover each other, because
// netip.Prefix.Contains is false for an address of the other family.
func covers(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// daysToDuration converts a whole number of days to a duration. It reports false when the
// result does not fit in a time.Duration, which spans about 292 years either way.
func daysToDuration(n int64) (time.Duration, bool) {
	if n > math.MaxInt64/nanosPerDay || n < math.MinInt64/nanosPerDay {
		return 0, false
	}
	return time.Duration(n * nanosPerDay), true
}

// functionOptions declares the custom functions rule expressions can call. There are exactly
// six, and each overload only converts its arguments and calls the Go function that holds
// the behavior.
//
// cel-go checks the runtime type of every argument before it calls a binding and turns a
// mismatch into an evaluation error, so the type assertions below cannot fail.
func functionOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("portRangeContains",
			cel.Overload("portRangeContains_string_int", []*cel.Type{cel.StringType, cel.IntType}, cel.BoolType,
				cel.BinaryBinding(func(rng, port ref.Val) ref.Val {
					return types.Bool(PortRangeContains(string(rng.(types.String)), int64(port.(types.Int))))
				}))),
		cel.Function("modeAtMost",
			cel.Overload("modeAtMost_string_string", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(mode, limit ref.Val) ref.Val {
					return types.Bool(ModeAtMost(string(mode.(types.String)), string(limit.(types.String))))
				}))),
		cel.Function("days",
			cel.Overload("days_int", []*cel.Type{cel.IntType}, cel.DurationType,
				cel.UnaryBinding(func(n ref.Val) ref.Val {
					count := int64(n.(types.Int))
					d, ok := daysToDuration(count)
					if !ok {
						return types.NewErr("days(%d): integer overflow", count)
					}
					return types.Duration{Duration: d}
				}))),
		cel.Function("cidrIsPublic",
			cel.Overload("cidrIsPublic_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(func(s ref.Val) ref.Val {
					return types.Bool(CidrIsPublic(string(s.(types.String))))
				}))),
		cel.Function("cidrIsPrivate",
			cel.Overload("cidrIsPrivate_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(func(s ref.Val) ref.Val {
					return types.Bool(CidrIsPrivate(string(s.(types.String))))
				}))),
		cel.Function("cidrContains",
			cel.Overload("cidrContains_string_string", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(outer, inner ref.Val) ref.Val {
					return types.Bool(CidrContains(string(outer.(types.String)), string(inner.(types.String))))
				}))),
	}
}
