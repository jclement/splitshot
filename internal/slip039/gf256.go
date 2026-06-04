// gf256.go implements arithmetic over GF(2^8) and Lagrange interpolation of
// Shamir shares — the mathematical core of the secret sharing. The field is
// the Rijndael (AES) field, reduced modulo x^8 + x^4 + x^3 + x + 1 (0x11b).
//
// Shares are points (x, f(x)) on a polynomial whose constant terms encode the
// secret and a digest; interpolation recovers f at a chosen x. This mirrors
// the reference _interpolate exactly, including its log-domain arithmetic.
package slip039

import "fmt"

// expTable and logTable are the exponential/logarithm tables for the field's
// generator. They turn multiplication/division into table lookups and adds.
var (
	expTable [255]int
	logTable [256]int
)

// init builds the GF(256) log/exp tables from the field generator, exactly as
// the reference does. expTable[i] = g^i; logTable[g^i] = i.
func init() {
	poly := 1
	for i := 0; i < 255; i++ {
		expTable[i] = poly
		logTable[poly] = i

		// Multiply poly by (x + 1) = 3 in this representation.
		poly = (poly << 1) ^ poly
		// Reduce modulo x^8 + x^4 + x^3 + x + 1.
		if poly&0x100 != 0 {
			poly ^= 0x11b
		}
	}
}

// rawShare is a Shamir point: an x-coordinate and the per-byte evaluations of
// the polynomials at that x.
type rawShare struct {
	x    int
	data []byte
}

// interpolate returns f(x) given a set of Shamir shares (x_i, f(x_i)).
//
// All shares must have the same data length and unique x-coordinates. If the
// requested x is one of the given points, its data is returned directly. The
// computation is done in the log domain to keep field multiplications cheap,
// matching the reference implementation byte-for-byte.
func interpolate(shares []rawShare, x int) ([]byte, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares to interpolate")
	}

	dataLen := len(shares[0].data)
	seenX := make(map[int]struct{}, len(shares))
	for _, s := range shares {
		if _, dup := seenX[s.x]; dup {
			return nil, fmt.Errorf("invalid set of shares: share indices must be unique")
		}
		seenX[s.x] = struct{}{}
		if len(s.data) != dataLen {
			return nil, fmt.Errorf("invalid set of shares: all share values must have the same length")
		}
	}

	for _, s := range shares {
		if s.x == x {
			out := make([]byte, dataLen)
			copy(out, s.data)
			return out, nil
		}
	}

	// logProd = sum of log(x_i XOR x) over all shares.
	logProd := 0
	for _, s := range shares {
		logProd += logTable[s.x^x]
	}

	result := make([]byte, dataLen)
	for _, s := range shares {
		// Logarithm of the Lagrange basis polynomial for this share at x.
		sumOther := 0
		for _, other := range shares {
			sumOther += logTable[s.x^other.x]
		}
		logBasisEval := mod255(logProd - logTable[s.x^x] - sumOther)

		for j, shareVal := range s.data {
			if shareVal != 0 {
				result[j] ^= byte(expTable[(logTable[shareVal]+logBasisEval)%255])
			}
		}
	}
	return result, nil
}

// mod255 returns a non-negative residue modulo 255 (Go's % can be negative).
func mod255(n int) int {
	m := n % 255
	if m < 0 {
		m += 255
	}
	return m
}
