// rs1024.go implements the RS1024 Reed-Solomon checksum that protects each
// SLIP-0039 mnemonic against transcription errors. It is a direct port of the
// reference; the GEN table values are copied verbatim and must not be altered.
package slip039

// rs1024GEN is the generator table for the RS1024 checksum polynomial.
var rs1024GEN = [10]int{
	0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009,
	0x1C0C2412, 0x38086C24, 0x3090FC48, 0x21B1F890, 0x3F3F120,
}

// rs1024Polymod computes the RS1024 polynomial residue over the given 10-bit
// values. A correctly-checksummed value list yields 1.
func rs1024Polymod(values []int) int {
	chk := 1
	for _, v := range values {
		b := chk >> 20
		chk = (chk&0xFFFFF)<<10 ^ v
		for i := 0; i < 10; i++ {
			if (b>>i)&1 != 0 {
				chk ^= rs1024GEN[i]
			}
		}
	}
	return chk
}

// rs1024CreateChecksum returns the 3-word checksum for the given data words,
// customized by the customization string (which differs for extendable shares).
func rs1024CreateChecksum(data []int, customization []byte) []int {
	values := make([]int, 0, len(customization)+len(data)+checksumLengthWords)
	for _, c := range customization {
		values = append(values, int(c))
	}
	values = append(values, data...)
	values = append(values, make([]int, checksumLengthWords)...)

	polymod := rs1024Polymod(values) ^ 1
	checksum := make([]int, checksumLengthWords)
	for i := 0; i < checksumLengthWords; i++ {
		// Words are emitted most-significant first.
		shift := 10 * (checksumLengthWords - 1 - i)
		checksum[i] = (polymod >> shift) & 1023
	}
	return checksum
}

// rs1024VerifyChecksum reports whether the data words (which must already
// include the trailing checksum words) carry a valid RS1024 checksum.
func rs1024VerifyChecksum(data []int, customization []byte) bool {
	values := make([]int, 0, len(customization)+len(data))
	for _, c := range customization {
		values = append(values, int(c))
	}
	values = append(values, data...)
	return rs1024Polymod(values) == 1
}
