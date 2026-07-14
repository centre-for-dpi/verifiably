package injicertify

import (
	"encoding/base64"
	"strings"
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
		}, false)
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
		cc := BuildAuthcodeCredConfig(vctypes.Schema{Name: "Y", Std: "w3c_vcdm_1"}, false)
		if cc.Context == nil || *cc.Context != "https://www.w3.org/2018/credentials/v1" {
			t.Errorf("Context = %v, want credentials/v1", cc.Context)
		}
	})

	t.Run("SD-JWT -> vc+sd-jwt with default vct, no context/type", func(t *testing.T) {
		// The default vct is derived from the deployment host, not a hardcoded
		// placeholder — issuance + verification both read VERIFIABLY_PUBLIC_URL.
		t.Setenv("VERIFIABLY_PUBLIC_URL", "https://verify.example.test")
		cc := BuildAuthcodeCredConfig(vctypes.Schema{
			ID: "yid", Name: "Health", Std: "sd_jwt_vc (IETF)",
			FieldsSpec: []vctypes.FieldSpec{{Name: "g"}},
		}, false)
		if cc.CredFormat != "vc+sd-jwt" {
			t.Errorf("CredFormat = %q, want vc+sd-jwt", cc.CredFormat)
		}
		if cc.SDJwtVct == nil || *cc.SDJwtVct != "https://verify.example.test/credentials/yid" {
			t.Errorf("SDJwtVct = %v, want host-derived default vct", cc.SDJwtVct)
		}
		if cc.Context != nil || cc.CredType != nil {
			t.Error("Context/CredType must be nil for sd-jwt")
		}
	})

	t.Run("SD-JWT honours an explicit vct", func(t *testing.T) {
		cc := BuildAuthcodeCredConfig(vctypes.Schema{
			ID: "z", Name: "Z", Std: "sd_jwt_vc (IETF)", Vct: "https://issuer/vct/custom",
		}, false)
		if cc.SDJwtVct == nil || *cc.SDJwtVct != "https://issuer/vct/custom" {
			t.Errorf("SDJwtVct = %v, want the explicit vct", cc.SDJwtVct)
		}
	})

	t.Run("SD-JWT with token status adds an unquoted idx + uri status ref", func(t *testing.T) {
		cc := BuildAuthcodeCredConfig(vctypes.Schema{
			ID: "s", Name: "S", Std: "sd_jwt_vc (IETF)",
			FieldsSpec: []vctypes.FieldSpec{{Name: "f"}},
		}, true)
		raw, err := base64.StdEncoding.DecodeString(cc.VCTemplateB64)
		if err != nil {
			t.Fatalf("decode template: %v", err)
		}
		tmpl := string(raw)
		// idx must be an UNQUOTED marker (renders to a JSON number); uri a quoted
		// marker (renders to a string). Both resolved by the data-provider.
		if !strings.Contains(tmpl, `"idx": ${statusIdx}`) {
			t.Errorf("template missing unquoted idx marker:\n%s", tmpl)
		}
		if !strings.Contains(tmpl, `"uri": "${statusUri}"`) {
			t.Errorf("template missing quoted uri marker:\n%s", tmpl)
		}
	})

	t.Run("SD-JWT without token status emits NO status claim", func(t *testing.T) {
		cc := BuildAuthcodeCredConfig(vctypes.Schema{
			ID: "n", Name: "N", Std: "sd_jwt_vc (IETF)",
			FieldsSpec: []vctypes.FieldSpec{{Name: "f"}},
		}, false)
		raw, _ := base64.StdEncoding.DecodeString(cc.VCTemplateB64)
		if strings.Contains(string(raw), "status") {
			t.Errorf("template should have no status claim when withTokenStatus=false:\n%s", raw)
		}
	})
}
