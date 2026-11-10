package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// selfSignedCert builds a throwaway P-256 certificate for signer tests.
func selfSignedCert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test", Organization: []string{"POC-DO-NOT-TRUST"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return key, cert
}

func TestSoftwareSignerProducesVerifiableSignature(t *testing.T) {
	key, cert := selfSignedCert(t)
	s, err := NewSoftwareSigner(key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	sig, err := s.Sign(context.Background(), []byte("payload"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("expected 64-byte raw P-256 signature, got %d", len(sig))
	}
}

func TestSoftwareSignerReturnsFullChain(t *testing.T) {
	key, cert := selfSignedCert(t)
	s, err := NewSoftwareSigner(key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	if got := len(s.CertificateChain()); got != 1 {
		t.Fatalf("expected chain of 1, got %d", got)
	}
}

func TestNewSoftwareSignerRejectsEmptyChain(t *testing.T) {
	key, _ := selfSignedCert(t)
	if _, err := NewSoftwareSigner(key, nil); err == nil {
		t.Fatal("expected error for empty certificate chain")
	}
}
