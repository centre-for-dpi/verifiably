package mdl

import (
	"context"
	"testing"
)

func TestNewServerSignerProducesAUsableSigner(t *testing.T) {
	s, err := NewServerSigner()
	if err != nil {
		t.Fatalf("new server signer: %v", err)
	}
	sig, err := s.Sign(context.Background(), []byte("payload"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("expected 64-byte raw signature, got %d", len(sig))
	}
	chain := s.CertificateChain()
	if len(chain) != 2 {
		t.Fatalf("expected DSC+IACA chain of 2, got %d", len(chain))
	}
	if chain[0].IsCA {
		t.Error("chain[0] (leaf, the DSC) must not be a CA")
	}
	if !chain[1].IsCA {
		t.Error("chain[1] (the IACA) must be a CA")
	}
}

func TestNewServerSignerIsMarkedAsPOC(t *testing.T) {
	s, err := NewServerSigner()
	if err != nil {
		t.Fatalf("new server signer: %v", err)
	}
	for _, c := range s.CertificateChain() {
		found := false
		for _, o := range c.Subject.Organization {
			if o == "POC-DO-NOT-TRUST" {
				found = true
			}
		}
		if !found {
			t.Errorf("certificate %s must carry O=POC-DO-NOT-TRUST", c.Subject.CommonName)
		}
	}
}
