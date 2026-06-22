package injicertify

import (
	"strings"

	"github.com/verifiably/verifiably-go/vctypes"
)

// AuthcodeCredConfig holds the per-format credential_config column values for a
// schema. It is computed by reusing the SAME in-package helpers the pre-auth
// SaveCustomSchema uses (buildVCTemplate / stdToCredentialFormat / vcdmContextURL
// / credentialTypesSorted) — so the auth-code (Flow B) path issues every data
// model the schema builder offers (W3C VCDM 1.1/2.0 as ldp_vc, IETF SD-JWT VC as
// vc+sd-jwt), not just ldp_vc.
type AuthcodeCredConfig struct {
	CredFormat    string  // "ldp_vc" | "vc+sd-jwt" | ...
	VCTemplateB64 string  // base64 vc_template (JSON-LD for ldp_vc; {vct,fields} for sd-jwt)
	SDJwtVct      *string // non-nil for sd-jwt formats (the sd_jwt_vct column)
	Context       *string // non-nil for ldp_vc/jwt_vc (the VCDM @context URL)
	CredType      *string // non-nil for ldp_vc/jwt_vc (alpha-sorted, comma-joined)
}

// BuildAuthcodeCredConfig maps a builder schema (Std + FieldsSpec) to the
// format-specific credential_config columns, mirroring SaveCustomSchema's switch.
func BuildAuthcodeCredConfig(schema vctypes.Schema) AuthcodeCredConfig {
	credFormat := stdToCredentialFormat(schema.Std)
	out := AuthcodeCredConfig{CredFormat: credFormat, VCTemplateB64: buildVCTemplate(schema)}
	switch credFormat {
	case "vc+sd-jwt", "dc+sd-jwt":
		vct := schema.Vct
		if vct == "" {
			vct = "https://verifiably.example.com/credentials/" + schema.ID
		}
		out.SDJwtVct = &vct
	default: // ldp_vc, jwt_vc_json
		c := vcdmContextURL(schema.Std)
		out.Context = &c
		joined := strings.Join(credentialTypesSorted(schema), ",")
		out.CredType = &joined
	}
	return out
}
