package mdl

import (
	"context"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// samplePortraitJPEG is a minimal but structurally valid JPEG: SOI, an APP0
// JFIF segment, and EOI. Real enough to exercise the JPEG magic-byte check
// without shipping a real photo in the test tree.
var samplePortraitJPEG = []byte{
	0xFF, 0xD8, // SOI
	0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // APP0
	0xFF, 0xD9, // EOI
}

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
		Portrait:             samplePortraitJPEG,
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

// C.7.5: portrait is mandatory element #11 of Table 3. Its absence must be a
// build-time error now, the same way missing family_name already is — an
// mdoc issued without it is a test mdoc, not a conformant mDL, and the type
// system should not let that happen silently.
func TestElementsRejectsMissingPortrait(t *testing.T) {
	d := sampleLicence()
	d.Portrait = nil
	if _, err := d.Elements(time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected error: portrait is mandatory")
	}
}

// TestElementsRejectsNonJPEGPortrait guards against the exact failure mode
// this session spent hours chasing on the walt.id path: a portrait that
// isn't real image bytes reaching the signer at all. ISO/IEC 18013-5 §7.2.1
// requires portrait to be a JPEG or JPEG2000 byte string; catching a
// non-image payload here is cheaper than discovering it on a reader screen.
func TestElementsRejectsNonJPEGPortrait(t *testing.T) {
	d := sampleLicence()
	d.Portrait = []byte("not a jpeg")
	if _, err := d.Elements(time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected error: portrait must be JPEG-magic-byte-prefixed")
	}
}

// TestDatasetElementsNowHasElevenMandatory is the C.7.5 acceptance line in
// the plan made concrete: the dataset must carry all 11 Table 3 mandatory
// elements (the prior 10 plus portrait), not just the 12-including-portrait
// count checked elsewhere — this asserts portrait specifically is present,
// so a future refactor that silently drops it fails loudly here.
func TestDatasetElementsNowHasElevenMandatory(t *testing.T) {
	if !containsElement(DatasetElements, "portrait") {
		t.Fatal("portrait must be part of the emitted dataset as of C.7.5 — the credential is not a conformant mDL without it")
	}
}

// TestIssuePortraitEncodesAsRealByteString is the test that matters most in
// this file: it proves the same CBOR-typing bug this session spent a full
// walt.id investigation chasing (portrait landing as a text string or an
// array of ints instead of a genuine bstr) cannot happen on this native
// path, by decoding the actual signed CBOR and checking the wire type —
// not by trusting that []byte "should" round-trip correctly.
func TestIssuePortraitEncodesAsRealByteString(t *testing.T) {
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

	found := false
	for _, raw := range items {
		// Each entry is tag-24-wrapped IssuerSignedItemBytes; unwrap it the
		// same way a verifier would before inspecting elementValue.
		var tagged cbor.Tag
		if err := cbor.Unmarshal(raw, &tagged); err != nil {
			t.Fatalf("unwrap tag 24: %v", err)
		}
		inner, ok := tagged.Content.([]byte)
		if !ok {
			t.Fatalf("tag 24 content must be a byte string, got %T", tagged.Content)
		}
		var item struct {
			ElementIdentifier string          `cbor:"elementIdentifier"`
			ElementValue      cbor.RawMessage `cbor:"elementValue"`
		}
		if err := cbor.Unmarshal(inner, &item); err != nil {
			t.Fatalf("unmarshal item: %v", err)
		}
		if item.ElementIdentifier != "portrait" {
			continue
		}
		found = true

		// Major type 2 (byte string) with a short-form length header for a
		// payload this size encodes with the top 3 bits of the first byte
		// as 010 — i.e. the byte is in [0x40, 0x57] for lengths 0-23. This
		// is the exact distinction that failed against walt.id's legacy
		// issuer-api, which produced 0x6x (text string) or 0x8x (array).
		majorType := item.ElementValue[0] >> 5
		if majorType != 2 {
			t.Fatalf("portrait elementValue must be CBOR major type 2 (byte string), got major type %d (raw: %x)",
				majorType, item.ElementValue)
		}

		var decoded []byte
		if err := cbor.Unmarshal(item.ElementValue, &decoded); err != nil {
			t.Fatalf("portrait elementValue did not decode as bytes: %v", err)
		}
		if len(decoded) != len(samplePortraitJPEG) {
			t.Errorf("decoded portrait length = %d, want %d", len(decoded), len(samplePortraitJPEG))
		}
		if decoded[0] != 0xFF || decoded[1] != 0xD8 {
			t.Errorf("decoded portrait lost its JPEG SOI marker: %x", decoded[:2])
		}
	}
	if !found {
		t.Fatal("no portrait element found in issued IssuerSigned items")
	}
}
