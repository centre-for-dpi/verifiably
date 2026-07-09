package handlers

import (
	"context"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// TestBuildTemplateForSchemaVctPin covers the F19 fix: an Inji-certify SD-JWT
// schema surfaces through ListAllSchemas WITHOUT Custom set and WITHOUT
// Variants, so neither the Custom branch nor the Variants branch pins the vct.
// The fallback must derive it (explicit Vct preferred, host-derived otherwise)
// so the verifier's PD carries a $.vct filter — without which the wallet's
// matchesVct reports "No credential found for: vc-1".
func TestBuildTemplateForSchemaVctPin(t *testing.T) {
	t.Setenv("VERIFIABLY_PUBLIC_URL", "https://verify.example.test")

	cases := []struct {
		name           string
		schema         vctypes.Schema
		wantVct        string
		wantWireFormat string
	}{
		{
			name: "inji sd-jwt with explicit metadata vct (Custom=false, no Variants)",
			schema: vctypes.Schema{
				ID:         "custom-x",
				Name:       "Testa SD",
				Std:        "sd_jwt_vc (IETF)",
				Vct:        "https://verify.example.test/credentials/custom-x",
				FieldsSpec: []vctypes.FieldSpec{{Name: "last_name", Datatype: "string"}},
			},
			wantVct:        "https://verify.example.test/credentials/custom-x",
			wantWireFormat: "vc+sd-jwt",
		},
		{
			name: "inji sd-jwt WITHOUT explicit vct falls back to host-derived",
			schema: vctypes.Schema{
				ID:         "custom-y",
				Name:       "Testa SD 2",
				Std:        "sd_jwt_vc (IETF)",
				FieldsSpec: []vctypes.FieldSpec{{Name: "testa_id", Datatype: "string"}},
			},
			wantVct:        "https://verify.example.test/credentials/custom-y",
			wantWireFormat: "vc+sd-jwt",
		},
		{
			name: "w3c schema gets NO vct pin (fallback is SD-JWT-only)",
			schema: vctypes.Schema{
				ID:         "custom-w3c",
				Name:       "Testa W3C",
				Std:        "w3c_vcdm_2 (VCDM 2.0)",
				FieldsSpec: []vctypes.FieldSpec{{Name: "last_name", Datatype: "string"}},
			},
			wantVct:        "",
			wantWireFormat: "",
		},
		{
			name: "walt.id-style variant schema keeps the variant's own vct (no overwrite)",
			schema: vctypes.Schema{
				ID:     "builtin",
				Name:   "Built-in SD",
				Std:    "sd_jwt_vc (IETF)",
				Custom: false,
				Variants: []vctypes.SchemaVariant{
					{ID: "builtin", Std: "sd_jwt_vc (IETF)", Format: "vc+sd-jwt", Vct: "https://issuer.example/vct/BuiltIn"},
				},
				FieldsSpec: []vctypes.FieldSpec{{Name: "last_name", Datatype: "string"}},
			},
			wantVct:        "https://issuer.example/vct/BuiltIn",
			wantWireFormat: "vc+sd-jwt",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := apiTestH(&testAdapter{schemas: []vctypes.Schema{tc.schema}})
			tpl, err := h.buildTemplateForSchema(context.Background(), tc.schema.ID, nil, "selective")
			if err != nil {
				t.Fatalf("buildTemplateForSchema: %v", err)
			}
			if tpl.Vct != tc.wantVct {
				t.Errorf("Vct = %q, want %q", tpl.Vct, tc.wantVct)
			}
			if tpl.WireFormat != tc.wantWireFormat {
				t.Errorf("WireFormat = %q, want %q", tpl.WireFormat, tc.wantWireFormat)
			}
		})
	}
}
