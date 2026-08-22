package mdoc

import (
	"testing"

	"github.com/verifiably/verifiably-go/internal/mdl"
)

func TestMandatoryFieldsMDL(t *testing.T) {
	fields := MandatoryFields("org.iso.18013.5.1.mDL")

	// ISO/IEC 18013-5 Table 3 defines exactly 11 mandatory elements.
	if len(fields) != 11 {
		t.Fatalf("mDL: got %d mandatory fields, want 11", len(fields))
	}

	byName := map[string]bool{}
	for _, f := range fields {
		byName[f.Name] = true
		if !f.Required {
			t.Errorf("%s: mandatory field not marked Required", f.Name)
		}
		if f.Labels["en"] == "" {
			t.Errorf("%s: missing English label", f.Name)
		}
	}
	for _, want := range []string{
		"family_name", "given_name", "birth_date", "issue_date", "expiry_date",
		"issuing_country", "issuing_authority", "document_number", "portrait",
		"driving_privileges", "un_distinguishing_sign",
	} {
		if !byName[want] {
			t.Errorf("mDL missing mandatory element %q", want)
		}
	}
}

func TestMandatoryFieldsPhotoID(t *testing.T) {
	fields := MandatoryFields("org.iso.23220.photoid.1")

	// ISO/IEC 23220 defines 9 mandatory elements in org.iso.23220.1.
	if len(fields) != 9 {
		t.Fatalf("photoID: got %d mandatory fields, want 9", len(fields))
	}
	byName := map[string]bool{}
	for _, f := range fields {
		byName[f.Name] = true
	}
	// age_over_18 is mandatory here but optional in mDL — the clearest
	// evidence that the mandatory set belongs to the docType, not the format.
	if !byName["age_over_18"] {
		t.Error("photoID must include age_over_18 as mandatory")
	}
	if !byName["issuing_authority_unicode"] {
		t.Error("photoID uses issuing_authority_unicode, not issuing_authority")
	}
}

func TestMandatoryFieldsUnknownDocType(t *testing.T) {
	if got := MandatoryFields("org.iso.7367.1.mVRC"); got != nil {
		t.Errorf("unknown docType should return nil, got %v", got)
	}
}

func TestKnownDocTypes(t *testing.T) {
	known := KnownDocTypes()
	if len(known) != 2 {
		t.Fatalf("got %d known docTypes, want 2 (mDL, photoID)", len(known))
	}
	for _, d := range known {
		if d.DocType == "" || d.Name == "" {
			t.Errorf("incomplete entry: %+v", d)
		}
	}
}

// The mandatory list here and internal/mdl's emitted dataset describe the
// same standard. If one gains an element the other must too, so pin them.
func TestMDLMandatorySubsetOfIssuerDataset(t *testing.T) {
	issued := map[string]bool{}
	for _, e := range mdl.DatasetElements {
		issued[e] = true
	}
	for _, f := range MandatoryFields("org.iso.18013.5.1.mDL") {
		if !issued[f.Name] {
			t.Errorf("%q is mandatory but internal/mdl does not emit it", f.Name)
		}
	}
}
