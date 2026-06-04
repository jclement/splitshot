// encrypt.go implements the SLIP-0039 Feistel cipher that wraps the master
// secret before it is split. The round function is PBKDF2-HMAC-SHA256. This
// layer is what makes the optional passphrase a real second factor: without
// the right passphrase, recovered shares decrypt to a different (plausible)
// secret rather than failing outright — the basis for plausible-deniability
// "decoy" wallets.
package slip039

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"fmt"
)

// roundFunction is the Feistel round function: PBKDF2-HMAC-SHA256 keyed by the
// round index prepended to the passphrase, salted by salt||r, producing len(r)
// bytes. Iterations are (baseIterationCount << e) / roundCount.
func roundFunction(i int, passphrase []byte, e int, salt, r []byte) ([]byte, error) {
	password := append([]byte{byte(i)}, passphrase...)
	saltR := append(append([]byte{}, salt...), r...)
	iterations := (baseIterationCount << uint(e)) / roundCount
	out, err := pbkdf2.Key(sha256.New, string(password), saltR, iterations, len(r))
	if err != nil {
		return nil, fmt.Errorf("pbkdf2: %w", err)
	}
	return out, nil
}

// getSalt returns the cipher salt. Extendable shares use an empty salt so that
// the same secret can be re-split with a fresh identifier; legacy shares bind
// the salt to the identifier.
func getSalt(identifier int, extendable bool) []byte {
	if extendable {
		return []byte{}
	}
	idLen := bitsToBytes(idLengthBits)
	salt := append([]byte{}, customizationStringOrig...)
	idBytes := make([]byte, idLen)
	for i := idLen - 1; i >= 0; i-- {
		idBytes[i] = byte(identifier & 0xff)
		identifier >>= 8
	}
	return append(salt, idBytes...)
}

// xorBytes returns the byte-wise XOR of a and b (truncated to the shorter).
func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// encryptMasterSecret runs the 4-round Feistel network forward, turning the
// master secret into the ciphertext that actually gets shared.
func encryptMasterSecret(masterSecret, passphrase []byte, iterationExponent, identifier int, extendable bool) ([]byte, error) {
	if len(masterSecret)%2 != 0 {
		return nil, fmt.Errorf("the length of the master secret in bytes must be an even number")
	}
	half := len(masterSecret) / 2
	l := append([]byte{}, masterSecret[:half]...)
	r := append([]byte{}, masterSecret[half:]...)
	salt := getSalt(identifier, extendable)
	for i := 0; i < roundCount; i++ {
		f, err := roundFunction(i, passphrase, iterationExponent, salt, r)
		if err != nil {
			return nil, err
		}
		l, r = r, xorBytes(l, f)
	}
	return append(r, l...), nil
}

// decryptMasterSecret reverses encryptMasterSecret, running the Feistel rounds
// in reverse to recover the master secret from the shared ciphertext.
func decryptMasterSecret(ciphertext, passphrase []byte, iterationExponent, identifier int, extendable bool) ([]byte, error) {
	if len(ciphertext)%2 != 0 {
		return nil, fmt.Errorf("the length of the encrypted master secret in bytes must be an even number")
	}
	half := len(ciphertext) / 2
	l := append([]byte{}, ciphertext[:half]...)
	r := append([]byte{}, ciphertext[half:]...)
	salt := getSalt(identifier, extendable)
	for i := roundCount - 1; i >= 0; i-- {
		f, err := roundFunction(i, passphrase, iterationExponent, salt, r)
		if err != nil {
			return nil, err
		}
		l, r = r, xorBytes(l, f)
	}
	return append(r, l...), nil
}
