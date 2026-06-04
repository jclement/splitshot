// digest.go computes the share-integrity digest. SLIP-0039 reserves one share
// point (f(254)) for a truncated HMAC of the secret. On recovery, recomputing
// it detects wrong or corrupted shares before the (otherwise garbage) secret
// is ever returned.
package slip039

import (
	"crypto/hmac"
	"crypto/sha256"
)

// createDigest returns the first 4 bytes of HMAC-SHA256(key=randomData, msg=sharedSecret).
func createDigest(randomData, sharedSecret []byte) []byte {
	mac := hmac.New(sha256.New, randomData)
	mac.Write(sharedSecret)
	return mac.Sum(nil)[:digestLengthBytes]
}
