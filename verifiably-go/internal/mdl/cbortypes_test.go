package mdl

import (
	"bytes"
	"testing"
	"time"
)

// CBOR tag numbers the standard mandates. Getting these wrong is the most
// common way an mdoc fails against a conformant verifier.
const (
	tagTDate    = 0
	tagFullDate = 1004
)

func TestFullDateEncodesWithTag1004(t *testing.T) {
	em, err := EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	d := FullDate(time.Date(1990, 3, 15, 0, 0, 0, 0, time.UTC))
	got, err := em.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Tag 1004 encodes as major type 6 with a two-byte argument: d9 03ec.
	want := []byte{0xd9, 0x03, 0xec}
	if !bytes.HasPrefix(got, want) {
		t.Errorf("expected tag %d prefix %x, got %x", tagFullDate, want, got)
	}
	// The value must be a full-date string, not a date-time.
	if !bytes.Contains(got, []byte("1990-03-15")) {
		t.Errorf("expected full-date text 1990-03-15, got %x", got)
	}
	if bytes.Contains(got, []byte("T00:00:00")) {
		t.Error("full-date must not carry a time component")
	}
}

func TestTDateEncodesWithTag0(t *testing.T) {
	em, err := EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	d := TDate(time.Date(2026, 8, 17, 12, 30, 0, 0, time.UTC))
	got, err := em.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Tag 0 encodes as a single byte: c0.
	if len(got) == 0 || got[0] != 0xc0 {
		t.Errorf("expected tag %d prefix c0, got %x", tagTDate, got)
	}
	if !bytes.Contains(got, []byte("2026-08-17T12:30:00Z")) {
		t.Errorf("expected RFC3339 date-time, got %x", got)
	}
}

func TestMandatoryElementsListMatchesSpec(t *testing.T) {
	// All 11 Table 3 mandatory elements, including portrait as of C.7.5
	// (docs/superpowers/plans/2026-08-17-mdl-issuer-go.md), plus the two
	// optional age attestations = 13. Before C.7.5 this asserted 12 with
	// portrait explicitly absent — that assertion was C.7.1/C.7.2's
	// acceptance criterion for THAT phase, not a permanent constraint; C.7.5
	// deliberately supersedes it.
	if got := len(DatasetElements); got != 13 {
		t.Fatalf("expected 13 dataset elements, got %d", got)
	}
	for _, name := range []string{
		"family_name", "given_name", "birth_date", "issue_date", "expiry_date",
		"issuing_country", "issuing_authority", "document_number", "portrait",
		"driving_privileges", "un_distinguishing_sign",
		"age_over_18", "age_over_21",
	} {
		if !containsElement(DatasetElements, name) {
			t.Errorf("dataset must contain %q", name)
		}
	}
}
