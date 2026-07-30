package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestAuthorizeContextRoles(t *testing.T) {
	ts := &Teamserver{Config: &Config{
		OperatorCNs: []string{"operator-a"},
		ApproverCNs: []string{"approver-a"},
	}}

	if err := ts.authorizeContext(testTLSContext("operator-a"), "/erebus.api.ErebusC2/ListSessions"); err != nil {
		t.Fatalf("operator should be authorized: %v", err)
	}
	if err := ts.authorizeContext(testTLSContext("operator-a"), "/erebus.api.ErebusC2/Approve"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator should not approve, got %v", err)
	}
	if err := ts.authorizeContext(testTLSContext("approver-a"), "/erebus.api.ErebusC2/Approve"); err != nil {
		t.Fatalf("approver should approve: %v", err)
	}
	if err := ts.authorizeContext(testTLSContext("unknown"), "/erebus.api.ErebusC2/ListSessions"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unknown CN should be rejected, got %v", err)
	}
}

func testTLSContext(cn string) context.Context {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
	p := &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}}
	return peer.NewContext(context.Background(), p)
}
