package injicertify

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// decodeTemplate base64-decodes buildVCTemplate's output into a map.
func decodeTemplate(t *testing.T, schema vctypes.Schema) map[string]any {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(buildVCTemplate(schema))
	if err != nil {
		t.Fatalf("decode template: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal template: %v", err)
	}
	return m
}

func ctx0(t *testing.T, m map[string]any) string {
	t.Helper()
	ctx, ok := m["@context"].([]any)
	if !ok || len(ctx) == 0 {
		t.Fatalf("@context not a non-empty array: %v", m["@context"])
	}
	s, _ := ctx[0].(string)
	return s
}

// A VCDM 2.0 (w3c_vcdm_2) schema must produce a credentials/v2 credential with
// validFrom/validUntil — not the v1 context + issuanceDate it used to emit.
func TestBuildVCTemplateVCDM2(t *testing.T) {
	schema := vctypes.Schema{
		ID: "custom-v2", Name: "Testa Card V2", Std: "w3c_vcdm_2",
		AdditionalTypes: []string{"TestaCardV2"},
		FieldsSpec:      []vctypes.FieldSpec{{Name: "testa_id"}, {Name: "last_name"}},
	}
	m := decodeTemplate(t, schema)
	if got := ctx0(t, m); got != "https://www.w3.org/ns/credentials/v2" {
		t.Errorf("VCDM2 base @context = %q, want credentials/v2", got)
	}
	if _, ok := m["validFrom"]; !ok {
		t.Error("VCDM2 template missing validFrom")
	}
	if _, ok := m["validUntil"]; !ok {
		t.Error("VCDM2 template missing validUntil")
	}
	if _, ok := m["issuanceDate"]; ok {
		t.Error("VCDM2 template must not carry issuanceDate (v1 field)")
	}
	if _, ok := m["expirationDate"]; ok {
		t.Error("VCDM2 template must not carry expirationDate (v1 field)")
	}
}

// A VCDM 1.1 (w3c_vcdm_1) schema keeps credentials/v1 + issuanceDate/expirationDate.
func TestBuildVCTemplateVCDM1(t *testing.T) {
	schema := vctypes.Schema{
		ID: "custom-v1", Name: "Testa Card V3", Std: "w3c_vcdm_1",
		AdditionalTypes: []string{"TestaCardV3"},
		FieldsSpec:      []vctypes.FieldSpec{{Name: "testa_id"}},
	}
	m := decodeTemplate(t, schema)
	if got := ctx0(t, m); got != "https://www.w3.org/2018/credentials/v1" {
		t.Errorf("VCDM1 base @context = %q, want credentials/v1", got)
	}
	if _, ok := m["issuanceDate"]; !ok {
		t.Error("VCDM1 template missing issuanceDate")
	}
	if _, ok := m["validFrom"]; ok {
		t.Error("VCDM1 template must not carry validFrom (v2 field)")
	}
}

// Both data models must include the Ed25519Signature2020 suite context (Inji
// does not inject it; a strict wallet needs it to verify the proof).
func TestBuildVCTemplateAlwaysHasSuiteContext(t *testing.T) {
	for _, std := range []string{"w3c_vcdm_1", "w3c_vcdm_2"} {
		m := decodeTemplate(t, vctypes.Schema{ID: "x", Name: "X", Std: std, AdditionalTypes: []string{"XCard"}})
		ctx, _ := m["@context"].([]any)
		found := false
		for _, c := range ctx {
			if c == "https://w3id.org/security/suites/ed25519-2020/v1" {
				found = true
			}
		}
		if !found {
			t.Errorf("std %q: @context missing ed25519-2020 suite context: %v", std, ctx)
		}
	}
}
