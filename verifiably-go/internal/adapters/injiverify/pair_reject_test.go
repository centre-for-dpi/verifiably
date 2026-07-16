package injiverify

import (
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// F25: a delegated-access PAIR is now honoured — Inji Verify 0.16 accepts a
// multi-input_descriptor presentation_definition (PROVEN: it returns a
// per-credential vcResults array). presentationDefinitionForN must build one
// descriptor per template, each with a stable unique id + its own name/format.
func TestPresentationDefinitionForN_Pair(t *testing.T) {
	pd := presentationDefinitionForN([]vctypes.OID4VPTemplate{
		{Title: "W3CSubjectF23", Format: "w3c_vcdm_2", Fields: []string{"subjectRef"}},
		{Title: "DelegatedAccessCredential", Format: "sd_jwt_vc (IETF)", Vct: "https://x/deleg", Fields: []string{"onBehalfOf"}},
	})
	descs, ok := pd["input_descriptors"].([]map[string]any)
	if !ok || len(descs) != 2 {
		t.Fatalf("input_descriptors = %v, want 2", pd["input_descriptors"])
	}
	if descs[0]["id"] != "vc-1" || descs[1]["id"] != "vc-2" {
		t.Errorf("descriptor ids = %v, %v; want vc-1, vc-2", descs[0]["id"], descs[1]["id"])
	}
	if descs[0]["name"] != "W3CSubjectF23" || descs[1]["name"] != "DelegatedAccessCredential" {
		t.Errorf("descriptor names = %v, %v", descs[0]["name"], descs[1]["name"])
	}
	// each descriptor carries its own format (ldp_vp for W3C, vc+sd-jwt for SD-JWT)
	f0, _ := descs[0]["format"].(map[string]any)
	f1, _ := descs[1]["format"].(map[string]any)
	if _, hasLdp := f0["ldp_vp"]; !hasLdp {
		t.Errorf("subject descriptor format = %v, want ldp_vp", f0)
	}
	if _, hasSd := f1["vc+sd-jwt"]; !hasSd {
		t.Errorf("delegation descriptor format = %v, want vc+sd-jwt", f1)
	}
}

// A single-template request still produces exactly one descriptor keyed vc-1.
func TestPresentationDefinitionForN_Single(t *testing.T) {
	pd := presentationDefinitionForN([]vctypes.OID4VPTemplate{{Title: "Solo", Format: "w3c_vcdm_2"}})
	descs, _ := pd["input_descriptors"].([]map[string]any)
	if len(descs) != 1 || descs[0]["id"] != "vc-1" {
		t.Fatalf("single descriptor = %v", pd["input_descriptors"])
	}
}
