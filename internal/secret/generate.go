// Package secret generates cryptographically secure random secrets for
// splitting. Every byte of entropy comes from a caller-supplied io.Reader
// (crypto/rand.Reader in production); selection from the alphabet uses
// rejection sampling so there is zero modulo bias. The whole point of the tool
// is that these secrets are unguessable — there are no shortcuts here.
package secret

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Charset presets, selectable by name. Anything that isn't a known name is
// treated as a literal set of allowed characters.
const (
	charsetAlphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	charsetAlpha        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	charsetDigits       = "0123456789"
	charsetHex          = "0123456789abcdef"
	// safe adds shell-friendly symbols that won't trip up copy/paste or quoting.
	charsetSafe = charsetAlphanumeric + "!@#$%^&*()-_=+[]{}"
	// ascii is every printable ASCII character except space — maximum entropy
	// per character, at the cost of symbols some systems dislike.
	charsetASCII = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
)

// presets maps preset names to their character sets.
var presets = map[string]string{
	"alphanumeric": charsetAlphanumeric,
	"alpha":        charsetAlpha,
	"digits":       charsetDigits,
	"hex":          charsetHex,
	"safe":         charsetSafe,
	"ascii":        charsetASCII,
}

// PresetNames returns the available preset names, sorted, for help text.
func PresetNames() []string {
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ResolveCharset turns a --charset value into the literal alphabet to draw
// from. A known preset name expands to its set; anything else is taken as the
// literal allowed characters (deduplicated, order preserved). The result must
// contain at least two distinct characters.
func ResolveCharset(spec string) (string, error) {
	set := spec
	if preset, ok := presets[spec]; ok {
		set = preset
	}
	set = dedupe(set)
	if len(set) < 2 {
		return "", fmt.Errorf("charset must contain at least 2 distinct characters (got %q)", spec)
	}
	return set, nil
}

// dedupe removes duplicate bytes, preserving first-seen order, so a custom
// alphabet with repeats doesn't bias the distribution.
func dedupe(s string) string {
	seen := make(map[byte]struct{}, len(s))
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if _, ok := seen[s[i]]; ok {
			continue
		}
		seen[s[i]] = struct{}{}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Generate returns a random secret of the given length drawn uniformly from
// charset, using rand for entropy. charset is resolved via ResolveCharset, so
// it may be a preset name or a literal alphabet.
func Generate(length int, charset string, rand io.Reader) (string, error) {
	if length < 1 {
		return "", fmt.Errorf("length must be at least 1 (an empty secret protects nothing)")
	}
	set, err := ResolveCharset(charset)
	if err != nil {
		return "", err
	}

	out := make([]byte, length)
	for i := 0; i < length; i++ {
		idx, err := uniformIndex(rand, len(set))
		if err != nil {
			return "", err
		}
		out[i] = set[idx]
	}
	return string(out), nil
}

// uniformIndex returns a uniformly random integer in [0, n) using rejection
// sampling to eliminate modulo bias. n must be in [1, 256]; outside that range
// it errors rather than (for n>256) looping forever draining the RNG.
func uniformIndex(rand io.Reader, n int) (int, error) {
	if n < 1 || n > 256 {
		return 0, fmt.Errorf("uniformIndex: n must be in [1,256], got %d", n)
	}
	// Largest multiple of n that fits in a byte; values at or above it are
	// rejected so every index is equally likely.
	limit := 256 - (256 % n)
	buf := make([]byte, 1)
	for {
		if _, err := io.ReadFull(rand, buf); err != nil {
			return 0, fmt.Errorf("reading randomness: %w", err)
		}
		if int(buf[0]) < limit {
			return int(buf[0]) % n, nil
		}
	}
}
