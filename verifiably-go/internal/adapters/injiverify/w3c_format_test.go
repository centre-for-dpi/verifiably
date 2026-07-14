package injiverify

import (
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// TestFormatKeyW3CLdpVp covers the F23 mapping: Inji-issued W3C credentials
// present as an ldp_vp (JSON-LD VerifiablePresentation), not jwt_vc_json.
func TestFormatKeyW3CLdpVp(t *testing.T) {
	cases := map[string]string{
		"w3c_vcdm_2":            "ldp_vp",
		"w3c_vcdm_2 (VCDM 2.0)": "ldp_vp",
		"w3c_vcdm_1.1":          "ldp_vp",
		"sd_jwt_vc (IETF)":      "vc+sd-jwt",
		"mso_mdoc":              "mso_mdoc",
		"":                      "jwt_vc_json",
	}
	for std, want := range cases {
		if got := formatKey(std); got != want {
			t.Errorf("formatKey(%q) = %q, want %q", std, got, want)
		}
	}
	// ldp_vp alg clause advertises Data-Integrity proof suites, not "alg".
	alg := formatAlgClause("w3c_vcdm_2")
	if _, ok := alg["proof_type"]; !ok {
		t.Errorf("ldp_vp formatAlgClause missing proof_type: %v", alg)
	}
	if _, ok := alg["alg"]; ok {
		t.Errorf("ldp_vp formatAlgClause must not carry alg: %v", alg)
	}
}

// TestPresentationDefinitionForW3C verifies the PD advertises ldp_vp for a W3C
// template (and still vc+sd-jwt for SD-JWT — no regression).
func TestPresentationDefinitionForW3C(t *testing.T) {
	pd := presentationDefinitionFor(vctypes.OID4VPTemplate{
		Title:  "TestaAuthInjiW3CV3",
		Fields: []string{"last_name", "testa_id"},
		Format: "w3c_vcdm_2",
	})
	descs, _ := pd["input_descriptors"].([]map[string]any)
	if len(descs) != 1 {
		t.Fatalf("input_descriptors = %v", pd["input_descriptors"])
	}
	format, _ := descs[0]["format"].(map[string]any)
	if _, ok := format["ldp_vp"]; !ok {
		t.Errorf("W3C descriptor format = %v, want ldp_vp key", format)
	}

	sdPd := presentationDefinitionFor(vctypes.OID4VPTemplate{
		Title:  "SD",
		Fields: []string{"last_name"},
		Format: "sd_jwt_vc (IETF)",
	})
	sdDescs, _ := sdPd["input_descriptors"].([]map[string]any)
	sdFormat, _ := sdDescs[0]["format"].(map[string]any)
	if _, ok := sdFormat["vc+sd-jwt"]; !ok {
		t.Errorf("SD-JWT descriptor format = %v, want vc+sd-jwt key", sdFormat)
	}
}
