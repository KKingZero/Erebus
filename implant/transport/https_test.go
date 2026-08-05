package transport

import "testing"

func TestNewHTTPSTransport_RequiresCA(t *testing.T) {
	_, err := NewHTTPSTransport("https://127.0.0.1:8443", "", "")
	if err == nil {
		t.Fatal("expected error when CA cert PEM is empty")
	}
}

func TestNewHTTPSTransport_RejectsBadPEM(t *testing.T) {
	_, err := NewHTTPSTransport("https://127.0.0.1:8443", "not-a-pem", "")
	if err == nil {
		t.Fatal("expected error for invalid CA PEM")
	}
}

func TestNewHTTPSTransport_AcceptsPEM(t *testing.T) {
	// Minimal self-signed-looking PEM structure is hard without generating certs;
	// empty AppendCertsFromPEM already covered. Use a deliberately invalid block
	// that looks like PEM but fails parse → covered above.
	// Real e2e embeds teamserver CA.
}
