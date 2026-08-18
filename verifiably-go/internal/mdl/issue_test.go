package mdl

import (
	"context"
	"testing"
	"time"
)

func sampleLicence() LicenceData {
	return LicenceData{
		FamilyName:           "Pérez",
		GivenName:            "Ana María",
		BirthDate:            time.Date(1990, 3, 15, 0, 0, 0, 0, time.UTC),
		IssueDate:            time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
		ExpiryDate:           time.Date(2032, 1, 10, 0, 0, 0, 0, time.UTC),
		IssuingCountry:       "DO",
		IssuingAuthority:     "INTRANT",
		DocumentNumber:       "001-1234567-8",
		UNDistinguishingSign: "DOM",
		DrivingPrivileges: []DrivingPrivilege{
			{VehicleCategoryCode: "B"},
		},
	}
}

func TestElementsComputesAgeAttestationsFromValidFrom(t *testing.T) {
	d := sampleLicence()
	// Born 1990-03-15. On this validFrom the holder is 36: over both bounds.
	els, err := d.Elements(time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("elements: %v", err)
	}
	if els["age_over_18"] != true {
		t.Errorf("age_over_18 should be true, got %v", els["age_over_18"])
	}
	if els["age_over_21"] != true {
		t.Errorf("age_over_21 should be true, got %v", els["age_over_21"])
	}
}

func TestElementsAgeAttestationsUseValidFromNotToday(t *testing.T) {
	d := sampleLicence()
	d.BirthDate = time.Date(2010, 6, 1, 0, 0, 0, 0, time.UTC)
	// At this validFrom the holder is 15 — under both bounds — even though
	// they may be older by the time anyone runs this test.
	els, err := d.Elements(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("elements: %v", err)
	}
	if els["age_over_18"] != false {
		t.Errorf("age_over_18 should be false at that validFrom, got %v", els["age_over_18"])
	}
	if els["age_over_21"] != false {
		t.Errorf("age_over_21 should be false at that validFrom, got %v", els["age_over_21"])
	}
}

func TestElementsProducesTheFullDataset(t *testing.T) {
	els, err := sampleLicence().Elements(time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("elements: %v", err)
	}
	if len(els) != len(DatasetElements) {
		t.Fatalf("expected %d elements, got %d", len(DatasetElements), len(els))
	}
	for _, name := range DatasetElements {
		if _, ok := els[name]; !ok {
			t.Errorf("missing element %q", name)
		}
	}
}

func TestIssueProducesIssuerSignedWithAllItems(t *testing.T) {
	s := testSigner(t)
	deviceKey, err := LoadTestDeviceKey()
	if err != nil {
		t.Fatalf("load test device key: %v", err)
	}
	d := sampleLicence()

	is, err := Issue(context.Background(), s, d, deviceKey, d.ExpiryDate)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	items, ok := is.NameSpaces[Namespace]
	if !ok {
		t.Fatalf("expected namespace %q in nameSpaces", Namespace)
	}
	if len(items) != len(DatasetElements) {
		t.Errorf("expected %d disclosable items, got %d", len(DatasetElements), len(items))
	}
	if len(is.IssuerAuth) == 0 {
		t.Error("IssuerAuth must not be empty")
	}
}

func TestIssueRejectsValidUntilBeyondExpiry(t *testing.T) {
	s := testSigner(t)
	deviceKey, err := LoadTestDeviceKey()
	if err != nil {
		t.Fatalf("load test device key: %v", err)
	}
	d := sampleLicence()
	if _, err := Issue(context.Background(), s, d, deviceKey, d.ExpiryDate.Add(24*time.Hour)); err == nil {
		t.Fatal("expected error: validUntil must not exceed expiry_date")
	}
}
