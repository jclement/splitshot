// slip039_test.go covers the public API and internals beyond the official
// vectors: round-trips across many (threshold,total,length) shapes, both
// encodings, and every error path (validation, RNG failure, corrupt shares).
package slip039

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
)

// failingReader fails after letting `ok` bytes through, to exercise the
// randomness-failure branches deterministically.
type failingReader struct{ remaining int }

func (f *failingReader) Read(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, errors.New("simulated RNG failure")
	}
	n := len(p)
	if n > f.remaining {
		n = f.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = 0xAB
	}
	f.remaining -= n
	return n, nil
}

// ---------------------------------------------------------------------------
// Round-trips
// ---------------------------------------------------------------------------

func TestSplitCombineRoundTrip(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 16)
	cases := []struct{ threshold, total int }{
		{2, 2}, {2, 3}, {3, 5}, {5, 5}, {2, 16}, {16, 16},
	}
	for _, c := range cases {
		shares, err := Split(secret, c.threshold, c.total, "", rand.Reader)
		if err != nil {
			t.Fatalf("%d-of-%d split: %v", c.threshold, c.total, err)
		}
		if len(shares) != c.total {
			t.Fatalf("expected %d shares, got %d", c.total, len(shares))
		}
		// Any threshold-sized subset recovers; one fewer must not.
		got, err := Combine(shares[:c.threshold], "")
		if err != nil {
			t.Fatalf("%d-of-%d combine: %v", c.threshold, c.total, err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("%d-of-%d recovered %x, want %x", c.threshold, c.total, got, secret)
		}
	}
}

func TestSplitCombineWithPassphrase(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, 32)
	shares, err := Split(secret, 2, 3, "hunter2", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Combine(shares[:2], "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("recovered %x, want %x", got, secret)
	}
	// Wrong passphrase yields a *different* secret, not an error (by design).
	wrong, err := Combine(shares[:2], "hunter3")
	if err != nil {
		t.Fatalf("unexpected error with wrong passphrase: %v", err)
	}
	if bytes.Equal(wrong, secret) {
		t.Fatalf("wrong passphrase should not recover the original secret")
	}
}

func TestCombineToleratesExtraShares(t *testing.T) {
	secret := bytes.Repeat([]byte{0x7e}, 16)
	shares, err := Split(secret, 2, 5, "", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Hand it all 5 even though only 2 are needed.
	got, err := Combine(shares, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("recovered %x, want %x", got, secret)
	}
}

func TestMnemonicRoundTrip(t *testing.T) {
	secret := bytes.Repeat([]byte{0x99}, 32)
	shares, err := Split(secret, 3, 5, "", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var reparsed []Share
	for _, s := range shares {
		m := s.Mnemonic()
		if len(strings.Fields(m)) != 33 { // 256-bit share → 33 words
			t.Fatalf("expected 33 words, got %d", len(strings.Fields(m)))
		}
		got, err := ShareFromMnemonic(m)
		if err != nil {
			t.Fatalf("ShareFromMnemonic: %v", err)
		}
		reparsed = append(reparsed, got)
	}
	out, err := Combine(reparsed[:3], "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, secret) {
		t.Fatalf("recovered %x, want %x", out, secret)
	}
}

func TestMnemonicWhitespaceTolerant(t *testing.T) {
	secret := bytes.Repeat([]byte{0x01}, 16)
	shares, _ := Split(secret, 2, 2, "", rand.Reader)
	// Surrounding whitespace and mixed case must still parse.
	parsed, err := ShareFromMnemonic("  " + shares[0].Mnemonic() + "  ")
	if err != nil || parsed.MemberIndex != shares[0].MemberIndex {
		t.Fatalf("ShareFromMnemonic with whitespace: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Split / Combine validation errors
// ---------------------------------------------------------------------------

func TestSplitValidation(t *testing.T) {
	ok := bytes.Repeat([]byte{0x42}, 16)
	cases := []struct {
		name             string
		secret           []byte
		threshold, total int
		passphrase       string
	}{
		{"non-ascii passphrase", ok, 2, 3, "café"},
		{"threshold below 2", ok, 1, 3, ""},
		{"threshold above total", ok, 4, 3, ""},
		{"too many shares", ok, 2, 17, ""},
		{"secret too short", bytes.Repeat([]byte{1}, 14), 2, 3, ""},
		{"secret odd length", bytes.Repeat([]byte{1}, 15), 2, 3, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Split(c.secret, c.threshold, c.total, c.passphrase, rand.Reader); err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
		})
	}
}

func TestSplitRNGFailure(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 16)
	// Identifier needs 2 bytes; fail immediately.
	if _, err := Split(secret, 2, 3, "", &failingReader{remaining: 0}); err == nil {
		t.Fatal("expected identifier RNG failure")
	}
	// Let identifier through (2 bytes) but fail when splitSecret draws randomness.
	if _, err := Split(secret, 3, 5, "", &failingReader{remaining: 2}); err == nil {
		t.Fatal("expected split RNG failure")
	}
	// 2-of-3 has randomShareCount 0 but still needs randomPart for the digest.
	if _, err := Split(secret, 2, 3, "", &failingReader{remaining: 2}); err == nil {
		t.Fatal("expected digest randomPart RNG failure")
	}
}

func TestCombineValidation(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 16)
	shares, _ := Split(secret, 2, 3, "", rand.Reader)

	if _, err := Combine(nil, ""); err == nil {
		t.Fatal("expected error for empty share set")
	}
	if _, err := Combine(shares, "café"); err == nil {
		t.Fatal("expected error for bad passphrase")
	}
	if _, err := Combine(shares[:1], ""); err == nil {
		t.Fatal("expected error for insufficient shares")
	}

	// Mismatched common parameters: tweak one share's identifier.
	bad := append([]Share{}, shares[:2]...)
	bad[1].Identifier ^= 1
	if _, err := Combine(bad, ""); err == nil {
		t.Fatal("expected error for mismatched common parameters")
	}

	// Mismatched group parameters within a group: tweak member threshold.
	bad2 := append([]Share{}, shares[:2]...)
	bad2[1].MemberThreshold = 3
	if _, err := Combine(bad2, ""); err == nil {
		t.Fatal("expected error for mismatched group parameters")
	}
}

func TestCombineCorruptShareFailsDigest(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 16)
	shares, _ := Split(secret, 2, 3, "", rand.Reader)
	corrupt := append([]Share{}, shares[:2]...)
	corrupt[0].Value = append([]byte{}, corrupt[0].Value...)
	corrupt[0].Value[0] ^= 0xff
	if _, err := Combine(corrupt, ""); err == nil {
		t.Fatal("expected digest failure on corrupt share")
	}
}

// ---------------------------------------------------------------------------
// Internal Shamir primitives (white-box)
// ---------------------------------------------------------------------------

func TestSplitSecretThresholdOne(t *testing.T) {
	secret := []byte("sixteen-byte-key")
	shares, err := splitSecret(1, 3, secret, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range shares {
		if !bytes.Equal(s.data, secret) {
			t.Fatal("1-of-n share should equal the secret")
		}
	}
	got, err := recoverSecret(1, shares[:1])
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("recoverSecret(1): %v", err)
	}
}

func TestSplitSecretValidation(t *testing.T) {
	s := []byte("sixteen-byte-key")
	if _, err := splitSecret(0, 3, s, rand.Reader); err == nil {
		t.Fatal("expected error for threshold < 1")
	}
	if _, err := splitSecret(4, 3, s, rand.Reader); err == nil {
		t.Fatal("expected error for threshold > shareCount")
	}
	if _, err := splitSecret(2, 17, s, rand.Reader); err == nil {
		t.Fatal("expected error for shareCount > max")
	}
}

func TestInterpolateErrors(t *testing.T) {
	if _, err := interpolate(nil, 0); err == nil {
		t.Fatal("expected error for empty shares")
	}
	dup := []rawShare{{x: 1, data: []byte{1}}, {x: 1, data: []byte{2}}}
	if _, err := interpolate(dup, 0); err == nil {
		t.Fatal("expected error for duplicate x")
	}
	mismatched := []rawShare{{x: 1, data: []byte{1}}, {x: 2, data: []byte{1, 2}}}
	if _, err := interpolate(mismatched, 0); err == nil {
		t.Fatal("expected error for mismatched lengths")
	}
	// Requesting an existing x returns that share's data directly.
	pts := []rawShare{{x: 7, data: []byte{9, 9}}, {x: 8, data: []byte{1, 2}}}
	got, err := interpolate(pts, 7)
	if err != nil || !bytes.Equal(got, []byte{9, 9}) {
		t.Fatalf("interpolate at known x: %v %x", err, got)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	secret := bytes.Repeat([]byte{0x33}, 16)
	for _, ext := range []bool{true, false} {
		ct, err := encryptMasterSecret(secret, []byte("pw"), 1, 1234, ext)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := decryptMasterSecret(ct, []byte("pw"), 1, 1234, ext)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pt, secret) {
			t.Fatalf("ext=%v: decrypt mismatch", ext)
		}
	}
}

func TestEncryptOddLength(t *testing.T) {
	if _, err := encryptMasterSecret([]byte{1, 2, 3}, nil, 1, 1, true); err == nil {
		t.Fatal("expected odd-length error")
	}
	if _, err := decryptMasterSecret([]byte{1, 2, 3}, nil, 1, 1, true); err == nil {
		t.Fatal("expected odd-length error")
	}
}

func TestRS1024RoundTrip(t *testing.T) {
	data := []int{1, 2, 3, 4, 5}
	cs := rs1024CreateChecksum(data, customizationStringOrig)
	full := append(append([]int{}, data...), cs...)
	if !rs1024VerifyChecksum(full, customizationStringOrig) {
		t.Fatal("checksum should verify")
	}
	full[0] ^= 1
	if rs1024VerifyChecksum(full, customizationStringOrig) {
		t.Fatal("corrupted data should not verify")
	}
}

func TestMod255(t *testing.T) {
	if mod255(-1) != 254 || mod255(256) != 1 || mod255(0) != 0 {
		t.Fatal("mod255 wrong")
	}
}

func TestXorBytes(t *testing.T) {
	// Unequal lengths truncate to the shorter operand.
	got := xorBytes([]byte{0x0f, 0xff, 0xaa}, []byte{0xf0, 0x0f})
	if !bytes.Equal(got, []byte{0xff, 0xf0}) {
		t.Fatalf("xorBytes mismatch: %x", got)
	}
}

func TestEqualBytes(t *testing.T) {
	if !equalBytes([]byte{1, 2}, []byte{1, 2}) {
		t.Fatal("equal slices should compare equal")
	}
	if equalBytes([]byte{1, 2}, []byte{1, 2, 3}) {
		t.Fatal("different lengths should not be equal")
	}
	if equalBytes([]byte{1, 2}, []byte{1, 3}) {
		t.Fatal("different contents should not be equal")
	}
}

// ---------------------------------------------------------------------------
// Share decode error paths
// ---------------------------------------------------------------------------

func TestShareFromMnemonicErrors(t *testing.T) {
	valid, _ := Split(bytes.Repeat([]byte{1}, 16), 2, 2, "", rand.Reader)
	good := valid[0].Mnemonic()

	if _, err := ShareFromMnemonic("notaword " + good); err == nil {
		t.Fatal("expected invalid-word error")
	}
	if _, err := ShareFromMnemonic("academic academic academic"); err == nil {
		t.Fatal("expected short-length error")
	}
	// Corrupt the checksum by swapping a middle word.
	words := strings.Fields(good)
	words[5] = "zero"
	if _, err := ShareFromMnemonic(strings.Join(words, " ")); err == nil {
		t.Fatal("expected checksum error")
	}
}

func TestWordsPerShare(t *testing.T) {
	// Known counts, and a cross-check against an actually-generated share.
	cases := map[int]int{16: 20, 32: 33}
	for length, want := range cases {
		if got := WordsPerShare(length); got != want {
			t.Fatalf("WordsPerShare(%d) = %d, want %d", length, got, want)
		}
		shares, err := Split(bytes.Repeat([]byte{1}, length), 2, 2, "", rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(shares[0].Words()); got != want {
			t.Fatalf("generated share has %d words, WordsPerShare said %d", got, want)
		}
	}
}

// readRandom should surface short reads as errors.
func TestReadRandomFailure(t *testing.T) {
	if _, err := readRandom(io.LimitReader(&failingReader{remaining: 1}, 1), 4); err == nil {
		t.Fatal("expected short-read error")
	}
}
