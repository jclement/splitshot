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
