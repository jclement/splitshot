// slip039.go is the public surface of the package: Split turns a secret into a
// set of mnemonic shares; Combine turns a sufficient subset back into the
// secret. Both use single-group sharing for production (Split), while Combine
// understands the full SLIP-0039 group model so it can also recover shares
// produced by other conforming tools.
package slip039

import (
	"crypto/subtle"
	"fmt"
	"io"
)

// defaultIterationExponent matches the reference default. 10000<<1 = 20000
// PBKDF2 iterations TOTAL (≈5000 per round over the 4 Feistel rounds) — plenty
// for a passphrase that is a second factor, not the sole secret, and keeps the
// CLI snappy.
const defaultIterationExponent = 1

// WordsPerShare reports how many mnemonic words each share will have when a
// secret of secretLenBytes is split. The count depends only on the byte length
// (the share value is the same length as the secret), not on the threshold or
// share count — so callers such as blank PDF templates can size their word
// boxes without generating anything. Example: 16→20, 32→33.
func WordsPerShare(secretLenBytes int) int {
	return metadataLengthWords + bitsToWords(secretLenBytes*8)
}

// Split encrypts secret under passphrase and splits it into `total` shares of
// which any `threshold` reconstruct it. Randomness (identifier + Shamir
// coefficients) is drawn from rand; pass crypto/rand.Reader in production.
//
// Constraints: 2 ≤ threshold ≤ total ≤ 16, and secret must be at least 16
// bytes and an even number of bytes (a SLIP-0039 requirement).
func Split(secret []byte, threshold, total int, passphrase string, rand io.Reader) ([]Share, error) {
	if err := validatePassphrase(passphrase); err != nil {
		return nil, err
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2 (a 1-of-m split protects nothing)")
	}
	if threshold > total {
		return nil, fmt.Errorf("threshold (%d) must not exceed the number of shares (%d)", threshold, total)
	}
	if total > maxShareCount {
		return nil, fmt.Errorf("number of shares must not exceed %d", maxShareCount)
	}
	if len(secret) < bitsToBytes(minStrengthBits) {
		return nil, fmt.Errorf("secret must be at least %d bytes (got %d)", bitsToBytes(minStrengthBits), len(secret))
	}
	if len(secret)%2 != 0 {
		return nil, fmt.Errorf("secret length in bytes must be even (got %d)", len(secret))
	}

	identifier, err := randomIdentifier(rand)
	if err != nil {
		return nil, err
	}
	ciphertext, err := encryptMasterSecret(secret, []byte(passphrase), defaultIterationExponent, identifier, true)
	if err != nil {
		return nil, err
	}

	rawShares, err := splitSecret(threshold, total, ciphertext, rand)
	if err != nil {
		return nil, err
	}

	shares := make([]Share, len(rawShares))
	for i, rs := range rawShares {
		shares[i] = Share{
			Identifier:        identifier,
			Extendable:        true,
			IterationExponent: defaultIterationExponent,
			GroupIndex:        0,
			GroupThreshold:    1,
			GroupCount:        1,
			MemberIndex:       rs.x,
			MemberThreshold:   threshold,
			Value:             rs.data,
		}
	}
	return shares, nil
}

// Combine recovers the secret from a set of shares (which may include more than
// the minimum; extras of a matching set are tolerated). The passphrase must be
// the one used at Split time — a wrong passphrase yields a different secret,
// not an error, by SLIP-0039 design.
//
// Recovery does not validate the passphrase charset: the reference
// combine_mnemonics passes the passphrase straight to the cipher, so we do too
// (maximally permissive recovery, including shares from other conforming tools).
func Combine(shares []Share, passphrase string) ([]byte, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}

	ems, err := recoverEMS(shares)
	if err != nil {
		return nil, err
	}
	return decryptMasterSecret(ems.ciphertext, []byte(passphrase), ems.iterationExponent, ems.identifier, ems.extendable)
}

// encryptedMasterSecret bundles the ciphertext with the metadata needed to
// decrypt it.
type encryptedMasterSecret struct {
	identifier        int
	extendable        bool
	iterationExponent int
	ciphertext        []byte
}

// recoverEMS validates a share set, recovers each group's secret, then the
// encrypted master secret. It mirrors the reference recover_ems but tolerates
// extra shares by using a minimal subset per group.
func recoverEMS(shares []Share) (encryptedMasterSecret, error) {
	common := shares[0].common()
	groups := make(map[int][]Share)
	for _, s := range shares {
		if s.common() != common {
			return encryptedMasterSecret{}, fmt.Errorf("invalid set of shares: all shares must share the same identifier, group threshold and group count")
		}
		groups[s.GroupIndex] = append(groups[s.GroupIndex], s)
	}

	// Collect groups that have reached their member threshold.
	complete := make(map[int][]Share)
	for idx, g := range groups {
		gp := g[0].group()
		for _, s := range g {
			if s.group() != gp {
				return encryptedMasterSecret{}, fmt.Errorf("invalid set of shares: group %d parameters don't match", idx)
			}
		}
		if len(g) >= gp.memberThreshold {
			complete[idx] = g[:gp.memberThreshold]
		}
	}

	if len(complete) < common.groupThreshold {
		// Give the common single-group case a message in the units the user
		// actually thinks in: shares, not "complete groups".
		if common.groupCount == 1 {
			have := 0
			if g, ok := groups[0]; ok {
				have = len(g)
			}
			need := shares[0].MemberThreshold
			return encryptedMasterSecret{}, fmt.Errorf("insufficient shares: need %d, have %d", need, have)
		}
		return encryptedMasterSecret{}, fmt.Errorf("insufficient shares: need %d complete group(s), have %d", common.groupThreshold, len(complete))
	}

	// Recover one group-secret per group, up to the group threshold.
	var groupShares []rawShare
	for idx, g := range complete {
		if len(groupShares) >= common.groupThreshold {
			break
		}
		raws := make([]rawShare, len(g))
		for i, s := range g {
			raws[i] = rawShare{x: s.MemberIndex, data: s.Value}
		}
		secret, err := recoverSecret(g[0].MemberThreshold, raws)
		if err != nil {
			return encryptedMasterSecret{}, err
		}
		groupShares = append(groupShares, rawShare{x: idx, data: secret})
	}

	ciphertext, err := recoverSecret(common.groupThreshold, groupShares)
	if err != nil {
		return encryptedMasterSecret{}, err
	}
	return encryptedMasterSecret{common.identifier, common.extendable, common.iterationExponent, ciphertext}, nil
}

// ---------------------------------------------------------------------------
// Raw Shamir over GF(256)
// ---------------------------------------------------------------------------

// splitSecret splits sharedSecret into shareCount raw shares, threshold of
// which reconstruct it. Indices 254/255 are reserved for the digest and the
// secret, so the public polynomial passes through them.
func splitSecret(threshold, shareCount int, sharedSecret []byte, rand io.Reader) ([]rawShare, error) {
	if threshold < 1 {
		return nil, fmt.Errorf("threshold must be a positive integer")
	}
	if threshold > shareCount {
		return nil, fmt.Errorf("threshold must not exceed the number of shares")
	}
	if shareCount > maxShareCount {
		return nil, fmt.Errorf("number of shares must not exceed %d", maxShareCount)
	}

	// A 1-of-n split is just the secret copied n times; no digest involved.
	if threshold == 1 {
		shares := make([]rawShare, shareCount)
		for i := range shares {
			shares[i] = rawShare{x: i, data: append([]byte{}, sharedSecret...)}
		}
		return shares, nil
	}

	randomShareCount := threshold - 2
	shares := make([]rawShare, 0, shareCount)
	for i := 0; i < randomShareCount; i++ {
		data, err := readRandom(rand, len(sharedSecret))
		if err != nil {
			return nil, err
		}
		shares = append(shares, rawShare{x: i, data: data})
	}

	randomPart, err := readRandom(rand, len(sharedSecret)-digestLengthBytes)
	if err != nil {
		return nil, err
	}
	digest := createDigest(randomPart, sharedSecret)

	baseShares := append([]rawShare{}, shares...)
	baseShares = append(baseShares,
		rawShare{x: digestIndex, data: append(append([]byte{}, digest...), randomPart...)},
		rawShare{x: secretIndex, data: append([]byte{}, sharedSecret...)},
	)

	for i := randomShareCount; i < shareCount; i++ {
		data, err := interpolate(baseShares, i)
		if err != nil {
			return nil, err
		}
		shares = append(shares, rawShare{x: i, data: data})
	}
	return shares, nil
}

// recoverSecret reconstructs the secret from threshold raw shares and verifies
// the integrity digest. A bad digest means the shares don't belong together or
// one is corrupt.
func recoverSecret(threshold int, shares []rawShare) ([]byte, error) {
	if threshold == 1 {
		return append([]byte{}, shares[0].data...), nil
	}
	sharedSecret, err := interpolate(shares, secretIndex)
	if err != nil {
		return nil, err
	}
	digestShare, err := interpolate(shares, digestIndex)
	if err != nil {
		return nil, err
	}
	digest := digestShare[:digestLengthBytes]
	randomPart := digestShare[digestLengthBytes:]
	// Constant-time compare as defense-in-depth (the reference compares plainly;
	// there is no remote timing oracle here, but intent-signaling is cheap).
	if subtle.ConstantTimeCompare(digest, createDigest(randomPart, sharedSecret)) != 1 {
		return nil, fmt.Errorf("invalid digest of the shared secret (wrong or corrupt shares)")
	}
	return sharedSecret, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// validatePassphrase enforces SLIP-0039's printable-ASCII passphrase rule.
func validatePassphrase(passphrase string) error {
	for _, c := range []byte(passphrase) {
		if c < 32 || c > 126 {
			return fmt.Errorf("passphrase must contain only printable ASCII characters (code points 32-126)")
		}
	}
	return nil
}

// randomIdentifier draws a 15-bit identifier from rand.
func randomIdentifier(rand io.Reader) (int, error) {
	b, err := readRandom(rand, bitsToBytes(idLengthBits))
	if err != nil {
		return 0, err
	}
	id := 0
	for _, by := range b {
		id = id<<8 | int(by)
	}
	return id & ((1 << idLengthBits) - 1), nil
}

// readRandom reads exactly n bytes from rand, wrapping read failures.
func readRandom(rand io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand, buf); err != nil {
		return nil, fmt.Errorf("reading randomness: %w", err)
	}
	return buf, nil
}

// equalBytes reports whether two byte slices are identical.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
