// Package slip039 is a from-scratch, dependency-free implementation of
// SLIP-0039 (Shamir's Secret-Sharing for Mnemonic Codes).
//
// It is a faithful port of the canonical Trezor reference implementation
// (github.com/trezor/python-shamir-mnemonic) and is verified against the
// official SLIP-0039 test vectors — see vectors_test.go. We implement it
// locally rather than pulling a library because correctness here is the whole
// point of the tool, and the reference is small enough to mirror exactly.
//
// The public surface most callers want is Split and Combine plus the Share
// type with its Mnemonic() encoder. The lower-level GF(256), RS1024,
// Feistel-cipher and Shamir-interpolation pieces live in sibling files.
package slip039

// These constants are copied verbatim from the SLIP-0039 specification. Do not
// "tidy" them — every value is load-bearing and is exercised by the official
// test vectors.
const (
	radixBits = 10   // bits encoded per mnemonic word (1024-word list)
	radix     = 1024 // number of words in the wordlist

	idLengthBits             = 15 // random identifier, shared across a set
	extendableFlagLengthBits = 1  // "extendable backup" flag
	iterationExpLengthBits   = 4  // PBKDF2 iteration exponent

	maxShareCount       = 16 // most shares SLIP-0039 will produce per group
	checksumLengthWords = 3  // RS1024 checksum, 30 bits
	digestLengthBytes   = 4  // truncated HMAC digest used for share integrity

	minStrengthBits = 128 // master secret must be at least this strong

	baseIterationCount = 10000 // PBKDF2 base iteration count (×2^e)
	roundCount         = 4     // Feistel rounds in the cipher

	secretIndex = 255 // x-coordinate at which the shared secret sits: f(255)
	digestIndex = 254 // x-coordinate at which the digest sits: f(254)
)

// Customization strings feed both the RS1024 checksum and (for non-extendable
// shares) the PBKDF2 salt. They differ so an extendable share can never be
// mistaken for a legacy one.
var (
	customizationStringOrig       = []byte("shamir")
	customizationStringExtendable = []byte("shamir_extendable")
)

// idExpLengthWords is the number of words holding the identifier, extendable
// flag, and iteration exponent (15+1+4 = 20 bits → 2 words).
const idExpLengthWords = (idLengthBits + extendableFlagLengthBits + iterationExpLengthBits + radixBits - 1) / radixBits

// metadataLengthWords is the mnemonic length excluding the share value:
// id/exp words + 2 words of group/member params + checksum words.
const metadataLengthWords = idExpLengthWords + 2 + checksumLengthWords

// minMnemonicLengthWords is the shortest a valid mnemonic can be.
const minMnemonicLengthWords = metadataLengthWords + (minStrengthBits+radixBits-1)/radixBits

// bitsToBytes rounds a bit count up to whole bytes.
func bitsToBytes(n int) int { return (n + 7) / 8 }

// bitsToWords rounds a bit count up to a whole number of mnemonic words.
func bitsToWords(n int) int { return (n + radixBits - 1) / radixBits }
