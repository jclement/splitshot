package taglines

import (
	"bytes"
	"strings"
	"testing"
)

func TestAllAreReasonable(t *testing.T) {
	all := All()
	if len(all) < 150 {
		t.Fatalf("expected ~200 taglines, got %d", len(all))
	}
	seen := make(map[string]bool, len(all))
	for i, tl := range all {
		if strings.TrimSpace(tl) == "" {
			t.Fatalf("tagline %d is empty", i)
		}
		if seen[tl] {
			t.Fatalf("duplicate tagline: %q", tl)
		}
		seen[tl] = true
	}
}

func TestPickWrapsAndHandlesNegatives(t *testing.T) {
	n := len(All())
	if Pick(0) != Pick(n) {
		t.Fatal("Pick should wrap modulo length")
	}
	if Pick(-1) != Pick(n-1) {
		t.Fatal("Pick should handle negative indices")
	}
}

func TestRandom(t *testing.T) {
	// Deterministic byte source → deterministic pick.
	got := Random(bytes.NewReader([]byte{0x00, 0x05}))
	if got != Pick(5) {
		t.Fatalf("Random mismatch: got %q", got)
	}
	// Short read falls back to the first tagline rather than panicking.
	if Random(bytes.NewReader(nil)) != All()[0] {
		t.Fatal("Random should fall back on read error")
	}
}
