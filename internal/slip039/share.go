// share.go defines the Share type and its canonical SLIP-0039 mnemonic
// serialization (Mnemonic / ShareFromMnemonic): an RS1024-checksummed word
// encoding that is interoperable with other SLIP-0039 tools. The mnemonic
// carries the full metadata, so a Share is self-describing — the combine path
// never needs the threshold told to it out of band.
package slip039

import (
	"fmt"
	"math/big"
	"strings"
)

// Share is one mnemonic share and everything needed to place it back on the
// Shamir polynomial during recovery.
type Share struct {
	Identifier        int    // 15-bit random id, identical across a share set
	Extendable        bool   // extendable-backup flag
	IterationExponent int    // PBKDF2 iteration exponent (0–15)
	GroupIndex        int    // which group this share belongs to (0-based)
	GroupThreshold    int    // groups required to recover (1-based)
	GroupCount        int    // total groups (1-based)
	MemberIndex       int    // x-coordinate of this share within its group
	MemberThreshold   int    // shares required within the group (1-based)
	Value             []byte // the share value (Shamir y-bytes)
}

// commonParameters are the fields that must match across every share in a set.
type commonParameters struct {
	identifier        int
	extendable        bool
	iterationExponent int
	groupThreshold    int
	groupCount        int
}

func (s Share) common() commonParameters {
	return commonParameters{s.Identifier, s.Extendable, s.IterationExponent, s.GroupThreshold, s.GroupCount}
}

// groupParameters are the fields shared by members of one group.
type groupParameters struct {
	commonParameters
	groupIndex      int
	memberThreshold int
}

func (s Share) group() groupParameters {
	return groupParameters{s.common(), s.GroupIndex, s.MemberThreshold}
}

// ---------------------------------------------------------------------------
// Mnemonic encoding (canonical SLIP-0039)
// ---------------------------------------------------------------------------

// Mnemonic returns the share as a space-separated SLIP-0039 mnemonic.
func (s Share) Mnemonic() string {
	return strings.Join(s.Words(), " ")
}

// Words returns the share's mnemonic as a slice of words.
func (s Share) Words() []string {
	shareData := append(s.encodeIDExp(), s.encodeShareParams()...)
	shareData = append(shareData, s.encodeValue()...)
	checksum := rs1024CreateChecksum(shareData, customizationString(s.Extendable))
	return wordsFromIndices(append(shareData, checksum...))
}

// encodeIDExp packs identifier, extendable flag and iteration exponent into the
// leading words (20 bits → 2 words).
func (s Share) encodeIDExp() []int {
	v := s.Identifier << (iterationExpLengthBits + extendableFlagLengthBits)
	if s.Extendable {
		v += 1 << iterationExpLengthBits
	}
	v += s.IterationExponent
	return intToIndices(v, idExpLengthWords)
}

// encodeShareParams packs the five 4-bit group/member fields (20 bits → 2 words).
func (s Share) encodeShareParams() []int {
	v := s.GroupIndex
	v = v<<4 + (s.GroupThreshold - 1)
	v = v<<4 + (s.GroupCount - 1)
	v = v<<4 + s.MemberIndex
	v = v<<4 + (s.MemberThreshold - 1)
	return intToIndices(v, 2)
}

// encodeValue packs the share value bytes into 10-bit words (big-endian).
func (s Share) encodeValue() []int {
	wordCount := bitsToWords(len(s.Value) * 8)
	value := new(big.Int).SetBytes(s.Value)
	return bigToIndices(value, wordCount)
}

// ShareFromMnemonic parses a SLIP-0039 mnemonic into a Share, validating its
// length, checksum, group/member parameters and padding.
func ShareFromMnemonic(mnemonic string) (Share, error) {
	data, err := mnemonicToIndices(mnemonic)
	if err != nil {
		return Share{}, err
	}
	if len(data) < minMnemonicLengthWords {
		return Share{}, fmt.Errorf("invalid mnemonic length: must be at least %d words", minMnemonicLengthWords)
	}

	// Padding bits between the value and a word boundary; more than a byte
	// of padding means the length is structurally impossible.
	paddingLen := (radixBits * (len(data) - metadataLengthWords)) % 16
	if paddingLen > 8 {
		return Share{}, fmt.Errorf("invalid mnemonic length")
	}

	idExpInt := intFromIndices(data[:idExpLengthWords])
	identifier := idExpInt >> (extendableFlagLengthBits + iterationExpLengthBits)
	extendable := (idExpInt>>iterationExpLengthBits)&1 == 1
	iterationExponent := idExpInt & ((1 << iterationExpLengthBits) - 1)

	if !rs1024VerifyChecksum(data, customizationString(extendable)) {
		return Share{}, fmt.Errorf("invalid mnemonic checksum")
	}

	paramsInt := intFromIndices(data[idExpLengthWords : idExpLengthWords+2])
	params := intToIndicesRadix(paramsInt, 5, 4)
	groupIndex, groupThreshold, groupCount, memberIndex, memberThreshold := params[0], params[1], params[2], params[3], params[4]

	if groupCount < groupThreshold {
		return Share{}, fmt.Errorf("invalid mnemonic: group threshold cannot exceed group count")
	}

	valueData := data[idExpLengthWords+2 : len(data)-checksumLengthWords]
	valueByteCount := bitsToBytes(radixBits*len(valueData) - paddingLen)
	valueInt := bigFromIndices(valueData)
	value, err := bigIntToFixedBytes(valueInt, valueByteCount)
	if err != nil {
		return Share{}, fmt.Errorf("invalid mnemonic padding")
	}

	return Share{
		Identifier:        identifier,
		Extendable:        extendable,
		IterationExponent: iterationExponent,
		GroupIndex:        groupIndex,
		GroupThreshold:    groupThreshold + 1,
		GroupCount:        groupCount + 1,
		MemberIndex:       memberIndex,
		MemberThreshold:   memberThreshold + 1,
		Value:             value,
	}, nil
}

// ---------------------------------------------------------------------------
// Small integer ↔ index helpers
// ---------------------------------------------------------------------------

// customizationString returns the RS1024/PBKDF2 customization for the flag.
func customizationString(extendable bool) []byte {
	if extendable {
		return customizationStringExtendable
	}
	return customizationStringOrig
}

// intToIndices converts a small integer to `length` big-endian 10-bit indices.
func intToIndices(value, length int) []int {
	return intToIndicesRadix(value, length, radixBits)
}

// intToIndicesRadix converts a small integer to `length` big-endian digits of
// the given bit width.
func intToIndicesRadix(value, length, bits int) []int {
	mask := (1 << bits) - 1
	out := make([]int, length)
	for i := 0; i < length; i++ {
		shift := bits * (length - 1 - i)
		out[i] = (value >> shift) & mask
	}
	return out
}

// intFromIndices converts big-endian 10-bit indices to a small integer.
func intFromIndices(indices []int) int {
	value := 0
	for _, idx := range indices {
		value = value*radix + idx
	}
	return value
}

// bigToIndices converts a big integer to `length` big-endian 10-bit indices.
func bigToIndices(value *big.Int, length int) []int {
	out := make([]int, length)
	mask := big.NewInt(radix - 1)
	tmp := new(big.Int)
	for i := 0; i < length; i++ {
		shift := uint(radixBits * (length - 1 - i))
		tmp.Rsh(value, shift)
		tmp.And(tmp, mask)
		out[i] = int(tmp.Int64())
	}
	return out
}

// bigFromIndices converts big-endian 10-bit indices to a big integer.
func bigFromIndices(indices []int) *big.Int {
	value := new(big.Int)
	for _, idx := range indices {
		value.Mul(value, big.NewInt(radix))
		value.Add(value, big.NewInt(int64(idx)))
	}
	return value
}

// bigIntToFixedBytes renders value as exactly n big-endian bytes, erroring if
// it does not fit (which signals non-zero padding bits — a corrupt mnemonic).
func bigIntToFixedBytes(value *big.Int, n int) ([]byte, error) {
	raw := value.Bytes()
	if len(raw) > n {
		return nil, fmt.Errorf("value overflows %d bytes", n)
	}
	out := make([]byte, n)
	copy(out[n-len(raw):], raw)
	return out, nil
}
