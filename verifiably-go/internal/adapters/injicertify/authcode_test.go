package injicertify

import (
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// BuildAuthcodeCredConfig must mirror SaveCustomSchema's per-format switch:
// JSON-LD formats (ldp_vc) get @context + sorted credential_type and NO
// sd_jwt_vct; SD-JWT formats get an sd_jwt_vct and NO @context/type.
func TestBuildAuthcodeCredConfig(t *testing.T) {
	t.Run("VCDM2 -> ldp_vc with v2 context + sorted type", func(t *testing.T) {
		cc := BuildAuthcodeCredConfig(vctypes.Schema{
			Name: "X", Std: "w3c_vcdm_2", AdditionalTypes: []string{"AlumniCard"},
			FieldsSpec: []vctypes.FieldSpec{{Name: "f"}},
		})
		if cc.CredFormat != "ldp_vc" {
			t.Errorf("CredFormat = %q, want ldp_vc", cc.CredFormat)
		}
		if cc.Context == nil || *cc.Context != "https://www.w3.org/ns/credentials/v2" {
			t.Errorf("Context = %v, want credentials/v2", cc.Context)
		}
		if cc.CredType == nil || *cc.CredType != "AlumniCard,VerifiableCredential" {
			t.Errorf("CredType = %v, want \"AlumniCard,VerifiableCredential\"", cc.CredType)
		}
		if cc.SDJwtVct != nil {
			t.Errorf("SDJwtVct should be nil for ldp_vc, got %v", *cc.SDJwtVct)
		}
		if cc.VCTemplateB64 == "" {
			t.Error("VCTemplateB64 should be populated")
		}
	})

	t.Run("VCDM1 -> ldp_vc with v1 context", func(t *testing.T) {
		cc := BuildAuthcodeCredConfig(vctypes.Schema{Name: "Y", Std: "w3c_vcdm_1"})
		if cc.Context == nil || *cc.Context != "https://www.w3.org/2018/credentials/v1" {
			t.Errorf("Context = %v, want credentials/v1", cc.Context)
		}
	})

	t.Run("SD-JWT -> vc+sd-jwt with default vct, no context/type", func(t *testing.T) {
		cc := BuildAuthcodeCredConfig(vctypes.Schema{
			ID: "yid", Name: "Health", Std: "sd_jwt_vc (IETF)",
			FieldsSpec: []vctypes.FieldSpec{{Name: "g"}},
		})
		if cc.CredFormat != "vc+sd-jwt" {
			t.Errorf("CredFormat = %q, want vc+sd-jwt", cc.CredFormat)
		}
		if cc.SDJwtVct == nil || *cc.SDJwtVct != "https://verifiably.example.com/credentials/yid" {
			t.Errorf("SDJwtVct = %v, want default vct derived from id", cc.SDJwtVct)
		}
		if cc.Context != nil || cc.CredType != nil {
			t.Error("Context/CredType must be nil for sd-jwt")
		}
	})

	t.Run("SD-JWT honours an explicit vct", func(t *testing.T) {
		cc := BuildAuthcodeCredConfig(vctypes.Schema{
			ID: "z", Name: "Z", Std: "sd_jwt_vc (IETF)", Vct: "https://issuer/vct/custom",
		})
		if cc.SDJwtVct == nil || *cc.SDJwtVct != "https://issuer/vct/custom" {
			t.Errorf("SDJwtVct = %v, want the explicit vct", cc.SDJwtVct)
		}
	})
}
