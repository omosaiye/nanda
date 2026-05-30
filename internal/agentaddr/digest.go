package agentaddr

import "crypto/sha256"

// Hash128 returns the first 128 bits of a SHA-256 digest.
func Hash128(data []byte) [16]byte {
	sum := sha256.Sum256(data)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}
