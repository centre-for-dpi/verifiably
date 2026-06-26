package handlers

import (
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// wireFormatOf drives the two-step picker's single-format constraint (walt.id
// can't mix formats in one presentation request).
func TestWireFormatOf(t *testing.T) {
	cases := map[string]string{
		"sd_jwt_vc (IETF)": "vc+sd-jwt",
		"sd_jwt_vc":        "vc+sd-jwt",
		"w3c_vcdm_2":       "jwt_vc_json",
		"w3c_vcdm_1":       "jwt_vc_json",
		"mso_mdoc":         "mso_mdoc",
		"":                 "jwt_vc_json",
	}
	for std, want := range cases {
		if got := wireFormatOf(std); got != want {
			t.Errorf("wireFormatOf(%q) = %q, want %q", std, got, want)
		}
	}
}

// schemaHasField distinguishes a delegation credential (has onBehalfOf) from an
// identity one — the step-1/step-2 grid filter.
func TestSchemaHasField(t *testing.T) {
	deleg := vctypes.Schema{FieldsSpec: []vctypes.FieldSpec{{Name: "onBehalfOf"}, {Name: "role"}}}
	identity := vctypes.Schema{FieldsSpec: []vctypes.FieldSpec{{Name: "last_name"}, {Name: "testa_id"}}}
	if !schemaHasField(deleg, "onBehalfOf") {
		t.Error("delegation schema should have onBehalfOf")
	}
	if schemaHasField(identity, "onBehalfOf") {
		t.Error("identity schema should not have onBehalfOf")
	}
}

func TestSchemaNameByID(t *testing.T) {
	schemas := []vctypes.Schema{{ID: "da-petcard", Name: "Pet Card"}}
	if got := schemaNameByID(schemas, "da-petcard"); got != "Pet Card" {
		t.Errorf("schemaNameByID = %q, want %q", got, "Pet Card")
	}
	if got := schemaNameByID(schemas, "nope"); got != "" {
		t.Errorf("schemaNameByID(unknown) = %q, want empty", got)
	}
	if got := schemaNameByID(schemas, ""); got != "" {
		t.Errorf("schemaNameByID(empty) = %q, want empty", got)
	}
}
