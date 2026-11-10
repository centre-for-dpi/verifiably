package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

// TestIACAWithProvinceCarriesStateOrProvinceName guards a cross-check that
// fails at accept time, in the wallet, with no error on our side.
//
// @animo-id/mdoc (the verification stack in the wallets this project targets)
// cross-checks the mdoc's own data elements against the DSC subject:
//
//	issuing_country      vs  countryName          (C)
//	issuing_jurisdiction vs  stateOrProvinceName  (ST)
//
// A certificate with no ST at all, or an ST that disagrees with the
// issuing_jurisdiction we put in the credential, is rejected by the wallet.
// The issuance side reports nothing.
func TestIACAWithProvinceCarriesStateOrProvinceName(t *testing.T) {
	_, iaca, err := GenerateIACAWithSubject("Test IACA", "DO", "DO-01", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	if len(iaca.Subject.Country) == 0 || iaca.Subject.Country[0] != "DO" {
		t.Errorf("countryName = %v, want [DO]", iaca.Subject.Country)
	}
	if len(iaca.Subject.Province) == 0 || iaca.Subject.Province[0] != "DO-01" {
		t.Errorf("stateOrProvinceName = %v, want [DO-01] — @animo-id/mdoc "+
			"cross-checks issuing_jurisdiction against this", iaca.Subject.Province)
	}
}

// TestDSCInheritsCountryAndProvinceFromIACA pins that the DSC — the
// certificate a verifier actually reads, as the x5chain leaf — carries the
// cross-checked fields too. Inheriting them from the IACA is what keeps the
// two ends of the chain from disagreeing.
func TestDSCInheritsCountryAndProvinceFromIACA(t *testing.T) {
	iacaKey, iaca, err := GenerateIACAWithSubject("Test IACA", "DO", "DO-01", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	_, dsc, err := GenerateDSC(iacaKey, iaca, "Test DSC", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("generate DSC: %v", err)
	}
	if len(dsc.Subject.Country) == 0 || dsc.Subject.Country[0] != "DO" {
		t.Errorf("DSC countryName = %v, want [DO]", dsc.Subject.Country)
	}
	if len(dsc.Subject.Province) == 0 || dsc.Subject.Province[0] != "DO-01" {
		t.Errorf("DSC stateOrProvinceName = %v, want [DO-01] — the DSC is the "+
			"x5chain leaf, so this is the subject a verifier cross-checks", dsc.Subject.Province)
	}
}

// TestGenerateDSCForKeyBindsTheSuppliedKey is the guard for the failure that
// has already bitten this deployment once: a signing key that does not match
// the certificate in the x5chain.
//
// ISO 18013-5 gives a verifier no source for the signing public key other than
// the x5chain leaf. If the key issuer-api2 signs with is not the key inside
// that leaf, every credential fails signature verification everywhere real,
// and nothing logs an error at issue time. GenerateDSC generates its own key,
// which makes it impossible to bind a key the caller already holds — so the
// caller must be able to hand the key in and get a certificate over exactly
// that key.
func TestGenerateDSCForKeyBindsTheSuppliedKey(t *testing.T) {
	iacaKey, iaca, err := GenerateIACAWithSubject("Test IACA", "DO", "DO-01", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	dsc, err := GenerateDSCForKey(iacaKey, iaca, &key.PublicKey, "Test DSC", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("generate DSC: %v", err)
	}
	pub, ok := dsc.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("DSC public key is %T, want *ecdsa.PublicKey", dsc.PublicKey)
	}
	if !pub.Equal(&key.PublicKey) {
		t.Error("DSC does not certify the supplied key — the x5chain leaf would " +
			"advertise a different public key than the one signing the mdoc, and " +
			"every credential would fail verification with no error at issue time")
	}
	if err := dsc.CheckSignatureFrom(iaca); err != nil {
		t.Errorf("DSC must still chain to the IACA: %v", err)
	}
}

// TestGenerateDSCForKeyEnforcesTheAnnexBCap makes sure routing around
// GenerateDSC does not route around the 457-day limit with it.
func TestGenerateDSCForKeyEnforcesTheAnnexBCap(t *testing.T) {
	iacaKey, iaca, err := GenerateIACAWithSubject("Test IACA", "DO", "DO-01", 500*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := GenerateDSCForKey(iacaKey, iaca, &key.PublicKey, "Test DSC", 458*24*time.Hour); err == nil {
		t.Fatal("expected error: Annex B caps DSC validity at 457 days")
	}
}

// TestGenerateDSCForKeyMarksPOCMaterial keeps generated certificates
// identifiable as test material.
func TestGenerateDSCForKeyMarksPOCMaterial(t *testing.T) {
	iacaKey, iaca, err := GenerateIACAWithSubject("Test IACA", "DO", "DO-01", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("generate IACA: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	dsc, err := GenerateDSCForKey(iacaKey, iaca, &key.PublicKey, "Test DSC", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("generate DSC: %v", err)
	}
	found := false
	for _, o := range dsc.Subject.Organization {
		if o == POCOrganization {
			found = true
		}
	}
	if !found {
		t.Errorf("DSC subject must carry O=%s, got %v", POCOrganization, dsc.Subject.Organization)
	}
}
