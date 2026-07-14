package backend

import (
	"reflect"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

func TestOID4VCIFormat(t *testing.T) {
	cases := map[string]string{
		"w3c_vcdm_2":      "jwt_vc_json",
		"w3c_vcdm_1":      "jwt_vc_json",
		"jwt_vc":          "jwt_vc_json",
		"":                "jwt_vc_json",
		"sd_jwt_vc":       "vc+sd-jwt",
		"sd_jwt_vc (IETF)": "vc+sd-jwt",
		"mso_mdoc":        "mso_mdoc",
	}
	for std, want := range cases {
		if got := OID4VCIFormat(std); got != want {
			t.Errorf("OID4VCIFormat(%q) = %q, want %q", std, got, want)
		}
	}
}

func TestCredentialConfigsFromSchemas(t *testing.T) {
	schemas := []vctypes.Schema{
		{
			ID:                "PersonCredential",
			Name:              "Person Credential",
			Std:               "w3c_vcdm_2",
			IssuerDisplayName: "Registro Civil",
			FieldsSpec: []vctypes.FieldSpec{
				{Name: "given_name"}, {Name: "family_name"},
			},
		},
		{
			ID:   "HealthCard_sd",
			Name: "Health Card",
			Std:  "sd_jwt_vc",
			Vct:  "https://example.gt/vct/health",
		},
		{
			ID:   "mDL",
			Name: "Mobile Driving Licence",
			Std:  "mso_mdoc",
		},
	}

	got := CredentialConfigsFromSchemas(schemas)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}

	// VCDM → jwt_vc_json with a VerifiableCredential type array + claims preview.
	vcdm := got[0]
	if vcdm.Format != "jwt_vc_json" {
		t.Errorf("vcdm format = %q, want jwt_vc_json", vcdm.Format)
	}
	if vcdm.Display != "Person Credential" || vcdm.Issuer != "Registro Civil" {
		t.Errorf("vcdm display/issuer = %q/%q", vcdm.Display, vcdm.Issuer)
	}
	if !reflect.DeepEqual(vcdm.Claims, []string{"given_name", "family_name"}) {
		t.Errorf("vcdm claims = %v", vcdm.Claims)
	}
	if len(vcdm.Types) == 0 || vcdm.Types[0] != "VerifiableCredential" {
		t.Errorf("vcdm types = %v, want first VerifiableCredential", vcdm.Types)
	}
	if vcdm.Vct != "" {
		t.Errorf("vcdm should have no vct, got %q", vcdm.Vct)
	}

	// SD-JWT → vc+sd-jwt with vct, no types.
	sd := got[1]
	if sd.Format != "vc+sd-jwt" {
		t.Errorf("sd format = %q, want vc+sd-jwt", sd.Format)
	}
	if sd.Vct != "https://example.gt/vct/health" {
		t.Errorf("sd vct = %q", sd.Vct)
	}
	if len(sd.Types) != 0 {
		t.Errorf("sd should have no types, got %v", sd.Types)
	}

	// mdoc → mso_mdoc.
	if got[2].Format != "mso_mdoc" {
		t.Errorf("mdoc format = %q, want mso_mdoc", got[2].Format)
	}
}

func TestCredentialConfigsFromSchemas_SDJWTVctFallsBackToID(t *testing.T) {
	got := CredentialConfigsFromSchemas([]vctypes.Schema{
		{ID: "SomeSdJwt", Std: "sd_jwt_vc"}, // no Vct set
	})
	if got[0].Vct != "SomeSdJwt" {
		t.Errorf("vct = %q, want fallback to ID SomeSdJwt", got[0].Vct)
	}
}
