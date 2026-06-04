// vectors_test.go runs the official SLIP-0039 test vectors. This is the
// authoritative correctness check: if these pass, our port matches the spec.
//
// Each vector is [description, mnemonics, secretHex, xprv]. A non-empty
// secretHex means the mnemonics are valid and must combine to that secret
// (passphrase "TREZOR"); an empty secretHex means the set is invalid and
// Combine must reject it.
package slip039

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

const vectorPassphrase = "TREZOR"

type vector struct {
	description string
	mnemonics   []string
	secretHex   string
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/slip39-vectors.json")
	if err != nil {
		t.Fatalf("reading vectors: %v", err)
	}
	var entries [][]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("parsing vectors: %v", err)
	}
	vectors := make([]vector, 0, len(entries))
	for _, e := range entries {
		v := vector{description: e[0].(string), secretHex: e[2].(string)}
		for _, m := range e[1].([]any) {
			v.mnemonics = append(v.mnemonics, m.(string))
		}
		vectors = append(vectors, v)
	}
	return vectors
}

func TestOfficialVectors(t *testing.T) {
	vectors := loadVectors(t)
	if len(vectors) < 40 {
		t.Fatalf("expected the full official vector set, got %d", len(vectors))
	}

	var valid, invalid int
	for _, v := range vectors {
		t.Run(v.description, func(t *testing.T) {
			shares := make([]Share, 0, len(v.mnemonics))
			parseOK := true
			for _, m := range v.mnemonics {
				s, err := ShareFromMnemonic(m)
				if err != nil {
					parseOK = false
					break
				}
				shares = append(shares, s)
			}

			if v.secretHex == "" {
				// Invalid vector: either a share fails to parse, or Combine rejects it.
				if !parseOK {
					return
				}
				if _, err := Combine(shares, vectorPassphrase); err == nil {
					t.Fatalf("expected invalid vector to be rejected, but it combined")
				}
				return
			}

			// Valid vector: must parse and combine to the expected secret.
			if !parseOK {
				t.Fatalf("valid vector failed to parse")
			}
			got, err := Combine(shares, vectorPassphrase)
			if err != nil {
				t.Fatalf("Combine failed: %v", err)
			}
			want, _ := hex.DecodeString(v.secretHex)
			if !equalBytes(got, want) {
				t.Fatalf("recovered %x, want %x", got, want)
			}
		})
		if v.secretHex == "" {
			invalid++
		} else {
			valid++
		}
	}
	t.Logf("ran %d valid and %d invalid official vectors", valid, invalid)
}
