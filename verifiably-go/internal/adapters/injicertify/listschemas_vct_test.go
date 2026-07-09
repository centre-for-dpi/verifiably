package injicertify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestListSchemasPinsVct covers the F19 fix on the issuer side: an SD-JWT VC
// credential configuration advertises a `vct` in the issuer metadata, and
// ListSchemas must carry it onto vctypes.Schema.Vct so the verifier's PD can
// pin $.vct to the exact value the issued token holds. A W3C (ldp_vc) config
// advertises no vct, so its Schema.Vct stays empty.
func TestListSchemasPinsVct(t *testing.T) {
	const meta = `{
	  "credential_configurations_supported": {
	    "custom-sd": {
	      "format": "vc+sd-jwt",
	      "vct": "https://verify.example.test/credentials/custom-sd",
	      "order": ["last_name", "testa_id", "statusIdx", "statusUri"]
	    },
	    "custom-w3c": {
	      "format": "ldp_vc",
	      "order": ["full_name"]
	    }
	  }
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/certify/.well-known/openid-credential-issuer" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(meta))
	}))
	defer srv.Close()

	a, err := New(Config{BaseURL: srv.URL}, "vendor")
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := a.ListSchemas(context.Background(), "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatalf("ListSchemas: %v", err)
	}
	byID := map[string]string{}   // id -> Vct
	stdByID := map[string]string{} // id -> Std
	fieldsByID := map[string][]string{}
	for _, s := range schemas {
		byID[s.ID] = s.Vct
		stdByID[s.ID] = s.Std
		for _, f := range s.FieldsSpec {
			fieldsByID[s.ID] = append(fieldsByID[s.ID], f.Name)
		}
	}

	if got, want := byID["custom-sd"], "https://verify.example.test/credentials/custom-sd"; got != want {
		t.Errorf("SD-JWT schema Vct = %q, want %q", got, want)
	}
	if got := stdByID["custom-sd"]; got != "sd_jwt_vc (IETF)" {
		t.Errorf("SD-JWT schema Std = %q, want sd_jwt_vc (IETF)", got)
	}
	// statusIdx/statusUri are internal markers, never operator-entered fields.
	for _, f := range fieldsByID["custom-sd"] {
		if f == "statusIdx" || f == "statusUri" {
			t.Errorf("SD-JWT schema exposes internal marker field %q", f)
		}
	}
	if got := byID["custom-w3c"]; got != "" {
		t.Errorf("W3C schema Vct = %q, want empty (no vct advertised)", got)
	}
}
