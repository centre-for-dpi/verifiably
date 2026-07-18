package injicertify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// Validity windows on the Inji Certify DPGs (pre-auth AND auth-code).
//
// The bug these pin: the issue form collected a validity window, put it on
// backend.IssueRequest, and this adapter never read it — only walt.id did. So
// every Inji Certify credential was issued with NO window, and an expired one
// verified as VALID (an absent bound imposes no constraint). On the reference
// deployment 0 of 9 credentials carried an expiry and nothing failed.
//
// Certify renders a STATIC vc_template with ${marker} substitutions, so three
// things must agree or the window silently vanishes again: the template asks
// for the markers, the config DECLARES them (else certify rejects the POSTed
// values as unknown claims), and issuance POSTS them.

const (
	tstValidFrom  = "2026-07-16T17:32:00Z"
	tstValidUntil = "2026-07-16T17:35:00Z"
)

func expiringSchema(std string) vctypes.Schema {
	return vctypes.Schema{
		ID:              "custom-dk05t158qnou",
		Name:            "Testa Card V2",
		Std:             std,
		Custom:          true,
		Expires:         true,
		AdditionalTypes: []string{"TestaCardV2"},
		FieldsSpec:      []vctypes.FieldSpec{{Name: "testa_id", Datatype: "string"}},
	}
}

// rawTemplate returns buildVCTemplate's output as text.
//
// Text, not a parsed map: an SD-JWT template with a status block or a validity
// window is deliberately NOT valid JSON — its numeric markers (`"idx":
// ${statusIdx}`, `"nbf": ${validFromEpoch}`) are unquoted so certify renders
// them as JSON numbers. Only the substituted result is JSON. (That is why the
// sibling decodeTemplate helper passes withTokenStatus=false.)
func rawTemplate(t *testing.T, schema vctypes.Schema, withStatus bool) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(buildVCTemplate(schema, withStatus))
	if err != nil {
		t.Fatalf("vc_template must be base64: %v", err)
	}
	return string(raw)
}

// SD-JWT's window is the registered nbf/exp claims — where a validity window
// belongs. Registered claims live in the plain JWT payload, so a holder cannot
// withhold their own expiry under selective disclosure and escape the temporal
// gate; a `valid_until` data claim could be withheld.
func TestVCTemplate_SDJWTCarriesNbfExp(t *testing.T) {
	tmpl := rawTemplate(t, expiringSchema("sd_jwt_vc (IETF)"), true)

	// UNQUOTED: NumericDate is a JSON number. Quoted markers would render a
	// string and certify 400s with json_processing_error.
	for _, want := range []string{`"nbf": ${validFromEpoch}`, `"exp": ${validUntilEpoch}`} {
		if !strings.Contains(tmpl, want) {
			t.Errorf("SD-JWT template must carry %s\ngot:\n%s", want, tmpl)
		}
	}
	if strings.Contains(tmpl, `"valid_until"`) {
		t.Errorf("the window must be nbf/exp, not a selectively-disclosable valid_until claim:\n%s", tmpl)
	}
}

// W3C VCDM 2.0 puts validFrom/validUntil at the TOP LEVEL — siblings of
// credentialSubject, never inside it. Inside, they would be an attribute of the
// subject rather than metadata about the credential, and could collide with the
// subject's own date fields.
func TestVCTemplate_W3CCarriesValidFromUntilAsMetadata(t *testing.T) {
	// W3C's markers are all quoted (statusListIndex is a string here), so this
	// template IS valid JSON and can be asserted structurally.
	tmpl := rawTemplate(t, expiringSchema("w3c_vcdm_2"), true)

	var doc map[string]any
	if err := json.Unmarshal([]byte(tmpl), &doc); err != nil {
		t.Fatalf("template must be valid JSON: %v\n%s", err, tmpl)
	}
	for _, k := range []string{"validFrom", "validUntil"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("W3C template must carry top-level %q\ngot:\n%s", k, tmpl)
		}
	}
	if sub, ok := doc["credentialSubject"].(map[string]any); ok {
		for _, k := range []string{"validFrom", "validUntil", "valid_until"} {
			if _, bad := sub[k]; bad {
				t.Errorf("%q must be credential metadata, not a credentialSubject attribute", k)
			}
		}
	}
}

// A non-expiring schema must carry NO temporal markers at all.
//
// This is not cosmetic: the SD-JWT markers are unquoted numbers, so an
// unconditional `"nbf": ${validFromEpoch}` renders as `"nbf": ,` when no window
// is supplied — invalid JSON, which would break every issuance of every
// credential that never expires.
func TestVCTemplate_NonExpiringSchemaHasNoTemporalMarkers(t *testing.T) {
	for _, std := range []string{"sd_jwt_vc (IETF)", "w3c_vcdm_2"} {
		s := expiringSchema(std)
		s.Expires = false
		tmpl := rawTemplate(t, s, true)
		for _, m := range []string{"${validFromEpoch}", "${validUntilEpoch}"} {
			if strings.Contains(tmpl, m) {
				t.Errorf("[%s] non-expiring schema must not reference %s — renders invalid JSON:\n%s", std, m, tmpl)
			}
		}
		if std == "sd_jwt_vc (IETF)" && (strings.Contains(tmpl, `"nbf"`) || strings.Contains(tmpl, `"exp"`)) {
			t.Errorf("[%s] non-expiring schema must carry no temporal claims:\n%s", std, tmpl)
		}
	}

	// Without the status block (whose idx marker is also unquoted) a
	// non-expiring SD-JWT template must be plain, valid JSON — i.e. we left no
	// dangling numeric marker behind.
	s := expiringSchema("sd_jwt_vc (IETF)")
	s.Expires = false
	var doc map[string]any
	plain := rawTemplate(t, s, false)
	if err := json.Unmarshal([]byte(plain), &doc); err != nil {
		t.Errorf("a non-expiring, statusless template must be valid JSON: %v\n%s", err, plain)
	}
}

// Each format's markers take the shape that format's slot requires: epoch
// seconds for SD-JWT's NumericDate nbf/exp, RFC3339 for W3C's validFrom.
func TestValidityClaims_ShapePerFormat(t *testing.T) {
	wantEpoch := func(s string) string {
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return strconv.FormatInt(ts.Unix(), 10)
	}

	sd := validityClaims("vc+sd-jwt", tstValidFrom, tstValidUntil)
	if sd["validFromEpoch"] != wantEpoch(tstValidFrom) || sd["validUntilEpoch"] != wantEpoch(tstValidUntil) {
		t.Errorf("SD-JWT claims must be JWT NumericDate seconds, got %v", sd)
	}

	w3c := validityClaims("ldp_vc", tstValidFrom, tstValidUntil)
	if w3c["validFrom"] != tstValidFrom || w3c["validUntil"] != tstValidUntil {
		t.Errorf("W3C claims must be RFC3339, got %v", w3c)
	}

	// An unset bound renders empty rather than leaking a literal ${…} into the
	// credential — no bound simply imposes no constraint.
	partial := validityClaims("ldp_vc", "", tstValidUntil)
	if partial["validFrom"] != "" || partial["validUntil"] != tstValidUntil {
		t.Errorf("an absent bound must render empty, got %v", partial)
	}
}

// The marker names POSTed at issuance and DECLARED in the config must be the
// same names the template asks for. If they ever drift, certify rejects the
// POSTed value as an unknown claim and the marker renders unresolved.
func TestValidityMarkerNames_MatchTemplateAndClaims(t *testing.T) {
	for _, tc := range []struct{ credFormat, std string }{
		{"vc+sd-jwt", "sd_jwt_vc (IETF)"},
		{"ldp_vc", "w3c_vcdm_2"},
	} {
		names := validityMarkerNames(tc.credFormat)
		if len(names) != 2 {
			t.Fatalf("[%s] expected 2 markers, got %v", tc.credFormat, names)
		}
		tmpl := rawTemplate(t, expiringSchema(tc.std), true)
		claims := validityClaims(tc.credFormat, tstValidFrom, tstValidUntil)
		for _, n := range names {
			if !strings.Contains(tmpl, "${"+n+"}") {
				t.Errorf("[%s] template does not reference declared marker ${%s}", tc.credFormat, n)
			}
			if _, ok := claims[n]; !ok {
				t.Errorf("[%s] issuance POSTs no value for declared marker %q", tc.credFormat, n)
			}
		}
	}
}

// The wire contract: what pre-auth issuance actually PUTS ON THE NETWORK.
//
// This is the test that would have caught the original bug — the internals
// could all look right while the adapter still never sent the window.
func TestIssueToWallet_PreAuthPostsValidityWindow(t *testing.T) {
	var got preAuthorizedDataRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "pre-authorized-data") {
			_ = json.NewDecoder(r.Body).Decode(&got)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"credential_offer_uri":"openid-credential-offer://x"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	a, err := New(Config{Mode: ModePreAuth, BaseURL: srv.URL}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.IssueToWallet(context.Background(), backend.IssueRequest{
		Schema:      expiringSchema("sd_jwt_vc (IETF)"),
		SubjectData: map[string]string{"testa_id": "123456"},
		ValidFrom:   tstValidFrom,
		ValidUntil:  tstValidUntil,
	}); err != nil {
		t.Fatalf("IssueToWallet: %v", err)
	}

	ts, _ := time.Parse(time.RFC3339, tstValidUntil)
	want := strconv.FormatInt(ts.Unix(), 10)
	if v, _ := got.Claims["validUntilEpoch"].(string); v != want {
		t.Errorf("pre-auth must POST validUntilEpoch=%q, got %q — the window was dropped", want, v)
	}
	if v, _ := got.Claims["validFromEpoch"].(string); v == "" {
		t.Error("pre-auth must POST validFromEpoch — the window was dropped")
	}
}

// A credential with no window must issue normally and POST no temporal markers:
// certify rejects claims the config never declared, and a non-expiring schema
// declares none.
func TestIssueToWallet_NonExpiringPostsNoValidityMarkers(t *testing.T) {
	var got preAuthorizedDataRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"credential_offer_uri":"openid-credential-offer://x"}`))
	}))
	defer srv.Close()

	a, err := New(Config{Mode: ModePreAuth, BaseURL: srv.URL}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatal(err)
	}
	s := expiringSchema("sd_jwt_vc (IETF)")
	s.Expires = false
	if _, err := a.IssueToWallet(context.Background(), backend.IssueRequest{
		Schema:      s,
		SubjectData: map[string]string{"testa_id": "123456"},
	}); err != nil {
		t.Fatalf("a non-expiring credential must still issue: %v", err)
	}
	for _, k := range []string{"validFromEpoch", "validUntilEpoch"} {
		if _, present := got.Claims[k]; present {
			t.Errorf("must not POST %q for a schema that declares no window", k)
		}
	}
}
