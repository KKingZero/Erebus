//go:build windows

package creds

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestDecryptChromiumPasswordV10RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plain := "hunter2"

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	sealed := gcm.Seal(nil, nonce, []byte(plain), nil)

	blob := append([]byte("v10"), nonce...)
	blob = append(blob, sealed...)

	got, err := decryptChromiumPassword(blob, key)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Fatalf("got %q want %q", got, plain)
	}
}