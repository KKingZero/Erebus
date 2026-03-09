package crypto

import (
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// DeriveKey derives a 32-byte AES key from a passphrase and salt using scrypt.
func DeriveKey(passphrase string, salt []byte) ([]byte, error) {
	if len(salt) < 16 {
		return nil, fmt.Errorf("salt must be at least 16 bytes")
	}
	// N=2^15, r=8, p=1, keyLen=32
	return scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
}
