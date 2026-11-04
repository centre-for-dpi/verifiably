package pki

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestGenerateIACAIsSelfSignedAndMarkedPOC(t *testing.T) {
	_, iaca, err := GenerateIACA("Test IACA", "DO", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	if !iaca.IsCA {
		t.Error("IACA must have IsCA set")
	}
	if err := iaca.CheckSignatureFrom(iaca); err != nil {
		t.Errorf("IACA must be self-signed: %v", err)
	}
	// The POC marker is what stops this material from silently reaching production.
	found := false
	for _, o := range iaca.Subject.Organization {
		if o == POCOrganization {
			found = true
		}
	}
	if !found {
		t.Errorf("IACA subject must carry O=%s, got %v", POCOrganization, iaca.Subject.Organization)
	}
	if len(iaca.Subject.Country) == 0 || iaca.Subject.Country[0] != "DO" {
		t.Errorf("expected country DO, got %v", iaca.Subject.Country)
	}
}

func TestGenerateDSCChainsToIACAAndCarriesEKU(t *testing.T) {
	iacaKey, iaca, err := GenerateIACA("Test IACA", "DO", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	_, dsc, err := GenerateDSC(iacaKey, iaca, "Test DSC", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("generate DSC: %v", err)
	}
	if err := dsc.CheckSignatureFrom(iaca); err != nil {
		t.Errorf("DSC must be signed by the IACA: %v", err)
	}
	if dsc.IsCA {
		t.Error("DSC must not be a CA")
	}
	// EKU 1.0.18013.5.1.2 is what marks this as an mDL document signer.
	found := false
	for _, oid := range dsc.UnknownExtKeyUsage {
		if oid.String() == EKUDocumentSigner {
			found = true
		}
	}
	if !found {
		t.Errorf("DSC must carry EKU %s, got %v", EKUDocumentSigner, dsc.UnknownExtKeyUsage)
	}
}

func TestGenerateDSCRejectsValidityBeyond457Days(t *testing.T) {
	iacaKey, iaca, err := GenerateIACA("Test IACA", "DO", 500*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	if _, _, err := GenerateDSC(iacaKey, iaca, "Test DSC", 458*24*time.Hour); err == nil {
		t.Fatal("expected error: Annex B caps DSC validity at 457 days")
	}
}

func TestGenerateDSCRejectsValidityBeyondIACA(t *testing.T) {
	// A DSC outliving its issuer produces a chain that breaks mid-demo.
	iacaKey, iaca, err := GenerateIACA("Test IACA", "DO", 10*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	if _, _, err := GenerateDSC(iacaKey, iaca, "Test DSC", 30*24*time.Hour); err == nil {
		t.Fatal("expected error: DSC validity must not exceed the IACA's")
	}
}

func TestGeneratedCertificatesVerifyAsAChain(t *testing.T) {
	iacaKey, iaca, err := GenerateIACA("Test IACA", "DO", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	_, dsc, err := GenerateDSC(iacaKey, iaca, "Test DSC", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("generate DSC: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(iaca)
	if _, err := dsc.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("DSC must chain to the IACA: %v", err)
	}
}
