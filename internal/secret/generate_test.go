package secret

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// errReader always fails — used to cover randomness-failure branches.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestGenerateLengthAndAlphabet(t *testing.T) {
	const length = 40
	got, err := Generate(length, "alphanumeric", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != length {
		t.Fatalf("expected length %d, got %d", length, len(got))
	}
	for _, c := range got {
		if !strings.ContainsRune(charsetAlphanumeric, c) {
			t.Fatalf("character %q not in alphabet", c)
		}
	}
}

func TestGenerateAllPresets(t *testing.T) {
	for _, name := range PresetNames() {
		set, err := ResolveCharset(name)
		if err != nil {
			t.Fatalf("preset %s: %v", name, err)
		}
		got, err := Generate(50, name, rand.Reader)
		if err != nil {
			t.Fatalf("preset %s: %v", name, err)
		}
		for _, c := range got {
			if !strings.ContainsRune(set, c) {
				t.Fatalf("preset %s produced out-of-set char %q", name, c)
			}
		}
	}
}

func TestGenerateCustomLiteralCharset(t *testing.T) {
	got, err := Generate(100, "AB", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got {
		if c != 'A' && c != 'B' {
			t.Fatalf("unexpected char %q", c)
		}
	}
}

func TestResolveCharsetDedupesAndValidates(t *testing.T) {
	set, err := ResolveCharset("aabbbc")
	if err != nil {
		t.Fatal(err)
	}
	if set != "abc" {
		t.Fatalf("expected deduped 'abc', got %q", set)
	}
	if _, err := ResolveCharset("xxxx"); err == nil {
		t.Fatal("expected error: single distinct character")
	}
	if _, err := ResolveCharset(""); err == nil {
		t.Fatal("expected error: empty charset")
	}
}

func TestGenerateErrors(t *testing.T) {
	if _, err := Generate(0, "alphanumeric", rand.Reader); err == nil {
		t.Fatal("expected length error")
	}
	if _, err := Generate(10, "z", rand.Reader); err == nil {
		t.Fatal("expected charset error")
	}
	if _, err := Generate(10, "alphanumeric", errReader{}); err == nil {
		t.Fatal("expected RNG error")
	}
}

func TestUniformIndexRejectionSampling(t *testing.T) {
	// n=62 → limit=248. Byte 0xFF (255) is rejected; the next byte (0x00) is used.
	r := bytes.NewReader([]byte{0xFF, 0x00})
	idx, err := uniformIndex(r, 62)
	if err != nil {
		t.Fatal(err)
	}
	if idx != 0 {
		t.Fatalf("expected index 0 after rejection, got %d", idx)
	}
}

func TestUniformIndexFullByteRange(t *testing.T) {
	// n=256 → limit=256, no rejection ever; index equals the byte.
	r := bytes.NewReader([]byte{200})
	idx, err := uniformIndex(r, 256)
	if err != nil {
		t.Fatal(err)
	}
	if idx != 200 {
		t.Fatalf("expected 200, got %d", idx)
	}
}

func TestUniformIndexOutOfRange(t *testing.T) {
	// n outside [1,256] must error, not loop forever (audit finding #3).
	for _, n := range []int{0, -1, 257, 512} {
		if _, err := uniformIndex(rand.Reader, n); err == nil {
			t.Fatalf("expected error for n=%d", n)
		}
	}
}

// TestUniformIndexRejectionMidRange exercises a mid-range n where a subtle
// off-by-one in `limit` would bias the result: n=10 → limit=250, so bytes
// 250–255 must be rejected and 0–249 must map across all ten indices.
func TestUniformIndexRejectionMidRange(t *testing.T) {
	// A rejected byte (250) followed by an accepted one (7) → index 7.
	r := bytes.NewReader([]byte{250, 7})
	idx, err := uniformIndex(r, 10)
	if err != nil {
		t.Fatal(err)
	}
	if idx != 7 {
		t.Fatalf("expected 7 after rejecting 250, got %d", idx)
	}
	// Every accepted byte 0..249 maps to byte%10, covering all 10 indices.
	seen := make(map[int]bool)
	for b := 0; b < 250; b++ {
		i, err := uniformIndex(bytes.NewReader([]byte{byte(b)}), 10)
		if err != nil {
			t.Fatal(err)
		}
		if i != b%10 {
			t.Fatalf("byte %d → index %d, want %d", b, i, b%10)
		}
		seen[i] = true
	}
	if len(seen) != 10 {
		t.Fatalf("expected all 10 indices covered, got %d", len(seen))
	}
}

// TestGenerateDistribution draws many symbols from a small alphabet and checks
// the empirical distribution is roughly uniform (a loose chi-square-style
// tolerance). Catches gross bias regressions that membership/length tests miss.
func TestGenerateDistribution(t *testing.T) {
	const draws = 60000
	const n = 10 // "digits"
	got, err := Generate(draws, "digits", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var counts [n]int
	for _, c := range got {
		counts[c-'0']++
	}
	expected := float64(draws) / n
	for d, c := range counts {
		// Allow ±15% per bucket — wide enough to never flake on real CSPRNG
		// output, tight enough to catch a missing/biased index.
		if float64(c) < expected*0.85 || float64(c) > expected*1.15 {
			t.Fatalf("digit %d appeared %d times, expected ~%.0f (out of tolerance)", d, c, expected)
		}
	}
}
