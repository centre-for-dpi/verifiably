package handlers

import (
	"context"
	"testing"
)

// F(1): auth-code schemas live in the Certify DB (SubjectStore), not the
// registry's custom-schema list, so ListAllSchemas surfaces them only as
// non-custom entries that verifierPresentableSchemas drops. verifierAuthcodeSchemas
// must rebuild them as Custom schemas stamped with the auth-code vendor DPG so
// they survive both gates and appear in the verifier grid.
func TestVerifierAuthcodeSchemas(t *testing.T) {
	h := apiTestH(&testAdapter{})
	h.Subjects = &fakeSubjects{
		listCreds: []map[string]string{
			{"key": "testaauthinjiw3cv5_vc_ldp", "displayName": "TestaAuthInjiW3CV5"},
		},
		fieldsByKey: map[string][]string{
			"testaauthinjiw3cv5_vc_ldp": {"last_name", "testa_id"},
		},
	}

	got := h.verifierAuthcodeSchemas(context.Background())
	if len(got) != 1 {
		t.Fatalf("verifierAuthcodeSchemas returned %d schemas, want 1", len(got))
	}
	s := got[0]
	if s.ID != "testaauthinjiw3cv5_vc_ldp" || s.Name != "TestaAuthInjiW3CV5" {
		t.Errorf("ID/Name = %q/%q", s.ID, s.Name)
	}
	if !s.Custom {
		t.Error("schema must be Custom=true to survive verifierPresentableSchemas")
	}
	if !dpgsIntersect(s.DPGs, []string{authcodeVendor}) {
		t.Errorf("DPGs = %v, want to include %q", s.DPGs, authcodeVendor)
	}
	if s.Std != "w3c_vcdm_2" { // CredentialClaimSpec returns "" in the fake → W3C default
		t.Errorf("Std = %q, want w3c_vcdm_2 default", s.Std)
	}
	if len(s.FieldsSpec) != 2 || s.FieldsSpec[0].Name != "last_name" || s.FieldsSpec[1].Name != "testa_id" {
		t.Errorf("FieldsSpec = %+v", s.FieldsSpec)
	}

	// It must survive the verifier grid filter for the Inji Verify DPG.
	kept := verifierPresentableSchemas(got, "Inji Verify")
	if len(kept) != 1 {
		t.Fatalf("verifierPresentableSchemas dropped the auth-code schema (%d kept)", len(kept))
	}
}

// No SubjectStore → no auth-code schemas (and no panic).
func TestVerifierAuthcodeSchemas_NoSubjects(t *testing.T) {
	h := apiTestH(&testAdapter{})
	if got := h.verifierAuthcodeSchemas(context.Background()); got != nil {
		t.Errorf("want nil without a SubjectStore, got %v", got)
	}
}
