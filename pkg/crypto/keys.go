package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// GenerateEd25519KeyPair generates a new Ed25519 key pair.
func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// ComputeHMAC computes HMAC-SHA256 over implantID and timestamp using the given secret.
func ComputeHMAC(secret []byte, implantID string, timestamp int64) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(implantID))
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(timestamp))
	mac.Write(ts)
	return mac.Sum(nil)
}

// VerifyHMAC verifies an HMAC with a replay window.
//
// Timestamps may be Unix seconds (legacy) or Unix milliseconds (current implants).
// Values < 1e12 are treated as seconds; otherwise milliseconds. replayWindowSec is
// always expressed in seconds and converted for millisecond timestamps.
func VerifyHMAC(secret []byte, implantID string, timestamp int64, providedMAC []byte, replayWindowSec int64) error {
	var now, window, diff int64
	if timestamp < 1_000_000_000_000 { // ~2001-09-09 in ms → treat as seconds
		now = time.Now().Unix()
		window = replayWindowSec
	} else {
		now = time.Now().UnixMilli()
		window = replayWindowSec * 1000
	}
	diff = now - timestamp
	if diff < 0 {
		diff = -diff
	}
	if diff > window {
		unit := "ms"
		if timestamp < 1_000_000_000_000 {
			unit = "s"
		}
		return fmt.Errorf("timestamp outside replay window: drift=%d%s", diff, unit)
	}

	expected := ComputeHMAC(secret, implantID, timestamp)
	if !hmac.Equal(expected, providedMAC) {
		return fmt.Errorf("HMAC verification failed")
	}
	return nil
}

// RandomBytes generates n random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// RandomID generates a random hex ID of the given byte length.
func RandomID(byteLen int) (string, error) {
	b, err := RandomBytes(byteLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// JitterDuration applies jitter to a base duration.
func JitterDuration(base time.Duration, jitterPct int) time.Duration {
	if jitterPct <= 0 {
		return base
	}
	b, _ := RandomBytes(4)
	r := float64(binary.BigEndian.Uint32(b)) / float64(math.MaxUint32)
	jitter := float64(base) * (float64(jitterPct) / 100.0) * (r*2 - 1)
	d := time.Duration(float64(base) + jitter)
	if d < 0 {
		d = base
	}
	return d
}
