package injicertify

import (
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// A custom field whose name collides with a VCDM-2.0 @protected term (e.g.
// "name"/"description") must NOT be redefined in the inline @context — doing so
// triggers PROTECTED_TERM_REDEFINITION during inji-certify's JSON-LD
// canonicalization at signing time (ERROR_SIGNING_QR_DATA), which blocked
// claiming such credentials. The inline context must therefore carry ONLY
// @vocab: standard terms keep their protected base definition, custom terms
// resolve via @vocab. (decodeTemplate lives in db_vcdm_test.go.)
func TestBuildVCTemplate_NoProtectedTermRedefinition(t *testing.T) {
	schema := vctypes.Schema{
		ID: "custom-waka", Name: "Waka", Std: "w3c_vcdm_2",
		AdditionalTypes: []string{"Waka"},
		FieldsSpec:      []vctypes.FieldSpec{{Name: "holder_id"}, {Name: "name"}},
	}
	m := decodeTemplate(t, schema)

	ctx, _ := m["@context"].([]any)
	if len(ctx) < 3 {
		t.Fatalf("@context should be [base, suite, inline], got %v", ctx)
	}
	inline, ok := ctx[2].(map[string]any)
	if !ok {
		t.Fatalf("third @context entry is not an inline object: %T", ctx[2])
	}
	if inline["@vocab"] != "https://vocab.verifiably.local/" {
		t.Errorf("@vocab = %v, want the verifiably vocab base", inline["@vocab"])
	}
	// Only @vocab is permitted — any explicit term entry could redefine a
	// VCDM-2.0 protected term (name/description/id/type/...).
	for k := range inline {
		if k != "@vocab" {
			t.Errorf("inline @context redefines term %q; only @vocab is allowed (it collides with VCDM-2.0 @protected terms)", k)
		}
	}
	// The custom field still rides in credentialSubject (resolved via @vocab),
	// and the custom type is still on the type array.
	if sub, _ := m["credentialSubject"].(map[string]any); sub["name"] == nil {
		t.Error("credentialSubject lost the 'name' field")
	}
	types, _ := m["type"].([]any)
	found := false
	for _, ty := range types {
		if ty == "Waka" {
			found = true
		}
	}
	if !found {
		t.Errorf("type array missing the custom type 'Waka': %v", types)
	}
}
