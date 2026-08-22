package mdoc

import (
	"testing"

	"github.com/verifiably/verifiably-go/internal/mdl"
)

func TestMandatoryFieldsMDL(t *testing.T) {
	fields := MandatoryFields("org.iso.18013.5.1.mDL")

	// ISO/IEC 18013-5 Table 3 defines exactly 11 mandatory elements. We offer
	// one more — portrait_capture_date — because walt.id's isoMdl profile
	// ships it as "" under a stringToFullDate mapping and deep-merges our data
	// over the profile, so a field we never offer keeps that blank and fails
	// issuance on the citizen's phone. The ISO count is asserted separately so
	// this stays honest about which requirement is whose.
	if len(fields) != 12 {
		t.Fatalf("mDL: got %d fields, want 12 (11 ISO-mandatory + portrait_capture_date)", len(fields))
	}
	isoMandatory := 0
	for _, f := range fields {
		if f.Name != "portrait_capture_date" {
			isoMandatory++
		}
	}
	if isoMandatory != 11 {
		t.Errorf("ISO-mandatory count = %d, want 11", isoMandatory)
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

	// ISO/IEC 23220 defines 9 mandatory elements in org.iso.23220.1. We offer
	// one more — portrait_capture_date — because walt.id's isoPhotoId profile
	// ships it as "" under a stringToFullDate mapping and deep-merges our data
	// over the profile, so a field we never offer keeps that blank and fails
	// issuance on the citizen's phone. The ISO count is asserted separately
	// below so this stays honest about which is which.
	if len(fields) != 10 {
		t.Fatalf("photoID: got %d fields, want 10 (9 ISO-mandatory + portrait_capture_date)", len(fields))
	}
	isoMandatory := 0
	for _, f := range fields {
		if f.Name != "portrait_capture_date" {
			isoMandatory++
		}
	}
	if isoMandatory != 9 {
		t.Errorf("ISO-mandatory count = %d, want 9", isoMandatory)
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
//
// vendorProfileOnly holds fields this list carries that ISO does NOT make
// mandatory, and which internal/mdl therefore has no reason to emit. They are
// here because walt.id's issuer profile ships them as "" under a date
// mapping, and issuer-api2 deep-merges our data over that profile — so a
// field the builder never offers keeps the blank and kills issuance at wallet
// redemption. Offering them is a walt.id requirement, not an ISO one, so
// widening internal/mdl (the independent CONFORMANCE verifier, whose emitted
// set is pinned by its own vectors) to match would be the wrong direction.
func TestMDLMandatorySubsetOfIssuerDataset(t *testing.T) {
	vendorProfileOnly := map[string]bool{
		"portrait_capture_date": true,
	}
	issued := map[string]bool{}
	for _, e := range mdl.DatasetElements {
		issued[e] = true
	}
	for _, f := range MandatoryFields("org.iso.18013.5.1.mDL") {
		if vendorProfileOnly[f.Name] {
			continue
		}
		if !issued[f.Name] {
			t.Errorf("%q is mandatory but internal/mdl does not emit it", f.Name)
		}
	}
}

// MandatoryFields must hand back a DEEP copy. A plain copy() duplicates the
// slice but leaves every FieldSpec.Labels aliasing the package-level
// mdlMandatory/photoIDMandatory maps, so a caller writing a label would
// poison the package defaults for the entire process — one operator's label
// leaking into every later request. The schema builder DOES write into these
// maps (it overlays the operator's labels onto the curated ones), so this is
// a live hazard, not a theoretical one.
func TestMandatoryFieldsLabelsAreNotAliased(t *testing.T) {
	for _, docType := range []string{"org.iso.18013.5.1.mDL", "org.iso.23220.photoid.1"} {
		first := MandatoryFields(docType)
		if len(first) == 0 {
			t.Fatalf("%s: no mandatory fields", docType)
		}
		originalEN := first[0].Labels["en"]
		if originalEN == "" {
			t.Fatalf("%s: first field has no English label to test with", docType)
		}

		// Mutate the first result exactly as the schema builder does.
		first[0].Labels["en"] = "MUTATED BY CALLER"
		first[0].Labels["es"] = "Apellido"

		second := MandatoryFields(docType)
		if got := second[0].Labels["en"]; got != originalEN {
			t.Errorf("%s: mutating the first result's Labels changed the second: en = %q, want %q "+
				"(MandatoryFields is aliasing the package-level Labels map)", docType, got, originalEN)
		}
		if _, leaked := second[0].Labels["es"]; leaked {
			t.Errorf("%s: a locale written into the first result leaked into the second — "+
				"package-level state was mutated", docType)
		}
	}
}
