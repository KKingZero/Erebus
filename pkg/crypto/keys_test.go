package crypto

import (
	"testing"
	"time"
)

func TestVerifyHMAC_AcceptsUnixSecondsAndMillis(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	id := "implant-test"

	sec := time.Now().Unix()
	macSec := ComputeHMAC(secret, id, sec)
	if err := VerifyHMAC(secret, id, sec, macSec, 30); err != nil {
		t.Fatalf("seconds: %v", err)
	}

	ms := time.Now().UnixMilli()
	macMs := ComputeHMAC(secret, id, ms)
	if err := VerifyHMAC(secret, id, ms, macMs, 30); err != nil {
		t.Fatalf("millis: %v", err)
	}
}

func TestVerifyHMAC_RejectsStale(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	id := "implant-test"
	ts := time.Now().Unix() - 120
	mac := ComputeHMAC(secret, id, ts)
	if err := VerifyHMAC(secret, id, ts, mac, 30); err == nil {
		t.Fatal("expected stale timestamp error")
	}
}
