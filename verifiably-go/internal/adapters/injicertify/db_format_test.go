package injicertify

import (
	"reflect"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// credentialTypesSorted must alphabetically sort ["VerifiableCredential", <specific>]
// so it matches Inji Certify's config-lookup key (Inji sorts the type array).
func TestCredentialTypesSorted(t *testing.T) {
	cases := []struct {
		name string
		in   vctypes.Schema
		want []string
	}{
		{"AdditionalTypes", vctypes.Schema{Name: "X", AdditionalTypes: []string{"FarmerCredential"}}, []string{"FarmerCredential", "VerifiableCredential"}},
		{"Name fallback strips spaces", vctypes.Schema{Name: "Testa Card"}, []string{"TestaCard", "VerifiableCredential"}},
		{"specific sorts before VerifiableCredential", vctypes.Schema{AdditionalTypes: []string{"AlumniCard"}}, []string{"AlumniCard", "VerifiableCredential"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := credentialTypesSorted(c.in); !reflect.DeepEqual(got, c.want) {
				t.Errorf("credentialTypesSorted = %v, want %v", got, c.want)
			}
		})
	}
}

func TestStdToCredentialFormat(t *testing.T) {
	cases := map[string]string{
		"sd_jwt_vc (IETF)": "vc+sd-jwt",
		"w3c_vcdm_1":       "ldp_vc",
		"w3c_vcdm_2":       "ldp_vc",
		"anything else":    "ldp_vc",
	}
	for std, want := range cases {
		if got := stdToCredentialFormat(std); got != want {
			t.Errorf("stdToCredentialFormat(%q) = %q, want %q", std, got, want)
		}
	}
}

// The SD-JWT template is a flat {vct, field:${field}} object — NOT a JSON-LD
// skeleton (no @context / issuer / type, which are ldp_vc-only).
func TestBuildVCTemplateSDJWT(t *testing.T) {
	m := decodeTemplate(t, vctypes.Schema{
		ID: "x", Name: "Testa", Std: "sd_jwt_vc (IETF)",
		FieldsSpec: []vctypes.FieldSpec{{Name: "testa_id"}, {Name: "last_name"}},
	})
	for _, forbidden := range []string{"@context", "issuer", "type", "credentialSubject"} {
		if _, ok := m[forbidden]; ok {
			t.Errorf("SD-JWT template must not contain %q", forbidden)
		}
	}
	if m["vct"] == nil || m["vct"] == "" {
		t.Error("SD-JWT template must carry a vct")
	}
	if m["testa_id"] != "${testa_id}" {
		t.Errorf("field not templated: testa_id = %v", m["testa_id"])
	}
}
