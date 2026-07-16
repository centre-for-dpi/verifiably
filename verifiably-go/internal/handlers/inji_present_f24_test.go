package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestInjiFieldNameFromPaths(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"$.vct"}, "vct"},
		{[]string{"$.last_name", "$.credentialSubject.last_name"}, "last_name"},
		{[]string{"$.credentialSubject.testa_id"}, "testa_id"},
		{[]string{}, ""},
		{[]string{"$."}, ""},
	}
	for _, c := range cases {
		if got := injiFieldNameFromPaths(c.in); got != c.want {
			t.Errorf("injiFieldNameFromPaths(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestFetchInjiVPRequestParsesPD covers the F24 extension: fetchInjiVPRequest
// parses the requested field names, the $.vct pattern, the descriptor name and
// the requested format from the presentation_definition.
func TestFetchInjiVPRequestParsesPD(t *testing.T) {
	jar := makeJAR(map[string]any{
		"nonce": "n1", "client_id": "did:web:verifier", "response_uri": "https://v/submit", "state": "req_1",
		"presentation_definition": map[string]any{
			"id": "pd-1",
			"input_descriptors": []any{map[string]any{
				"id":     "vc-1",
				"name":   "TestaSD",
				"format": map[string]any{"vc+sd-jwt": map[string]any{}},
				"constraints": map[string]any{"fields": []any{
					map[string]any{"path": []any{"$.vct"}, "filter": map[string]any{"pattern": "^https://x/cred$"}},
					map[string]any{"path": []any{"$.last_name", "$.credentialSubject.last_name"}},
					map[string]any{"path": []any{"$.testa_id"}},
				}},
			}},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(jar)) }))
	defer srv.Close()

	got, err := (&H{}).fetchInjiVPRequest(context.Background(), "openid4vp://authorize?request_uri="+url.QueryEscape(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	if got.DescName != "TestaSD" || got.Format != "vc+sd-jwt" || got.VctPattern != "^https://x/cred$" {
		t.Errorf("parsed = name:%q format:%q vct:%q", got.DescName, got.Format, got.VctPattern)
	}
	if len(got.RequestedFields) != 2 || got.RequestedFields[0] != "last_name" || got.RequestedFields[1] != "testa_id" {
		t.Errorf("RequestedFields = %v, want [last_name testa_id]", got.RequestedFields)
	}
}

func TestInjiMatchHeld(t *testing.T) {
	sd := sampleSDJWT(t)
	w3c := `{"type":["TestaW3C","VerifiableCredential"],"credentialSubject":{"id":"did:jwk:x","last_name":"Ochieng"}}`
	vctPat := "^https://verifiably\\.in-labs\\.cdpi\\.dev/credentials/custom-abc$"

	if ok, _ := injiMatchHeld(injiJAR{Format: "vc+sd-jwt", VctPattern: vctPat}, sd); !ok {
		t.Error("SD-JWT with matching vct should match")
	}
	if ok, reason := injiMatchHeld(injiJAR{Format: "vc+sd-jwt", VctPattern: "^https://nope$"}, sd); ok || reason == "" {
		t.Error("SD-JWT with non-matching vct should NOT match + give a reason")
	}
	if ok, _ := injiMatchHeld(injiJAR{Format: "vc+sd-jwt"}, w3c); ok {
		t.Error("W3C credential against a vc+sd-jwt request should NOT match")
	}
	if ok, _ := injiMatchHeld(injiJAR{Format: "ldp_vp"}, w3c); !ok {
		t.Error("W3C credential against an ldp_vp request should match")
	}
	if ok, _ := injiMatchHeld(injiJAR{Format: "ldp_vp"}, sd); ok {
		t.Error("SD-JWT against an ldp_vp request should NOT match")
	}
}

func TestInjiHeldFieldValue(t *testing.T) {
	sd := sampleSDJWT(t)
	if got := injiHeldFieldValue(sd, "last_name"); got != "Ndegwa" {
		t.Errorf("SD-JWT last_name = %q", got)
	}
	if got := injiHeldFieldValue(sd, "absent"); got != "" {
		t.Errorf("SD-JWT absent field = %q, want empty", got)
	}
	w3c := `{"credentialSubject":{"last_name":"Ochieng","testa_id":42}}`
	if got := injiHeldFieldValue(w3c, "last_name"); got != "Ochieng" {
		t.Errorf("W3C last_name = %q", got)
	}
	if got := injiHeldFieldValue(w3c, "testa_id"); got != "42" {
		t.Errorf("W3C testa_id = %q", got)
	}
}

func TestInjiPresentPreview(t *testing.T) {
	sd := sampleSDJWT(t)
	jar := injiJAR{
		Aud: "did:web:verifier", DescName: "TestaSD", Format: "vc+sd-jwt",
		RequestedFields: []string{"last_name", "testa_id"},
		VctPattern:      "^https://verifiably\\.in-labs\\.cdpi\\.dev/credentials/custom-abc$",
	}
	pv := injiPresentPreview(jar, "cred-1", sd)
	if !pv.Compatible {
		t.Fatalf("preview should be compatible: %s", pv.IncompatibleReason)
	}
	if pv.VerifierClientID != "did:web:verifier" || pv.CredentialTitle != "TestaSD" || pv.CredentialID != "cred-1" {
		t.Errorf("preview head = %+v", pv)
	}
	if len(pv.Fields) != 2 {
		t.Fatalf("fields = %v", pv.Fields)
	}
	byName := map[string]string{}
	for _, f := range pv.Fields {
		byName[f.Name] = f.Value
	}
	if byName["last_name"] != "Ndegwa" || byName["testa_id"] != "33764103" {
		t.Errorf("field values = %v", byName)
	}
	// incompatible when the vct doesn't match
	bad := injiPresentPreview(injiJAR{Format: "vc+sd-jwt", VctPattern: "^https://nope$"}, "c", sd)
	if bad.Compatible || bad.IncompatibleReason == "" {
		t.Error("mismatched vct should be incompatible with a reason")
	}
}

func TestInjiNormalizeRequestURI(t *testing.T) {
	if got := injiNormalizeRequestURI("  openid4vp://authorize?client_id=x&request_uri=y  "); got != "openid4vp://authorize?client_id=x&request_uri=y" {
		t.Errorf("openid4vp passthrough = %q", got)
	}
	if got := injiNormalizeRequestURI("openid4vp://x?a=1&amp;b=2"); got != "openid4vp://x?a=1&b=2" {
		t.Errorf("&amp; unescape = %q", got)
	}
	got := injiNormalizeRequestURI("https://v/vp-request/1")
	if !strings.HasPrefix(got, "openid4vp://authorize?request_uri=") || !strings.Contains(got, url.QueryEscape("https://v/vp-request/1")) {
		t.Errorf("bare https wrap = %q", got)
	}
}

func TestInjiCredTitle(t *testing.T) {
	if got := injiCredTitle(`{"type":["TestaW3C","VerifiableCredential"]}`); got != "TestaW3C" {
		t.Errorf("W3C title = %q", got)
	}
	if got := injiCredTitle(sampleSDJWT(t)); got != "custom-abc" {
		t.Errorf("SD-JWT title = %q, want custom-abc", got)
	}
}
