package crypto

import (
	"encoding/hex"
	"fmt"
)

// HexDecode decodes a hex string to bytes.
func HexDecode(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	return b, nil
}

// HexEncode encodes bytes to a hex string.
func HexEncode(b []byte) string {
	return hex.EncodeToString(b)
}
