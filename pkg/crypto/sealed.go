package crypto

import "fmt"

// Seal encrypts plaintext with AES-256-GCM using a 32-byte master key.
// Output is nonce||ciphertext||tag (same layout as AESEncrypt).
func Seal(masterKey, plaintext []byte) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}
	return AESEncrypt(masterKey, plaintext)
}

// Open decrypts a Seal blob with the 32-byte master key.
func Open(masterKey, sealed []byte) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}
	return AESDecrypt(masterKey, sealed)
}
