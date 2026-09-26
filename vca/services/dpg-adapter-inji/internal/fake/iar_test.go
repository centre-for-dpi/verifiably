// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
)

// form posts a form to the fake and returns the status and the body.
func form(t *testing.T, f *fake.Server, path string, values url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := f.Client().PostForm(f.URL()+path, values) //nolint:noctx // a test call to the fake
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Error(cerr)
		}
	}()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if jerr := json.Unmarshal(raw, &out); jerr != nil {
		t.Fatalf("%s: %s", path, raw)
	}
	return resp.StatusCode, out
}

// TestInteractiveAuthorization walks the interactive endpoint of the
// fake: the metadata names it, a broken first call fails, the first call
// asks for a presentation, the second call gives a code, and the token
// endpoint checks the PKCE verifier.
func TestInteractiveAuthorization(t *testing.T) {
	f := fake.New("../../testdata")
	defer f.Close()
	resp, err := f.Client().Get(f.URL() + fake.ASMetadataPath) //nolint:noctx // a test call to the fake
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if derr := json.NewDecoder(resp.Body).Decode(&meta); derr != nil {
		t.Fatal(derr)
	}
	if cerr := resp.Body.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	if meta["interactive_authorization_endpoint"] != f.URL()+fake.IARPath || meta["issuer"] != f.URL()+"/v1/certify" {
		t.Fatalf("metadata = %v", meta)
	}
	token := func(values url.Values) (int, map[string]any) { return form(t, f, "/v1/certify/oauth/token", values) }
	if status, out := token(url.Values{"grant_type": {"authorization_code"}, "code": {"iar_auth_1"}}); status != http.StatusBadRequest ||
		out["error"] != "invalid_grant" {
		t.Fatalf("a code before any challenge = %d %v", status, out)
	}
	if status, _ := form(t, f, fake.IARPath, url.Values{"response_type": {"code"}}); status != http.StatusBadRequest {
		t.Fatalf("a broken first call = %d", status)
	}
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	_, first := form(t, f, fake.IARPath, url.Values{
		"response_type": {"code"}, "client_id": {"w"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"}, "interaction_types_supported": {"openid4vp_presentation"},
		"authorization_details": {`[{"type":"openid_credential","credential_configuration_id":"FarmerCredential"}]`},
	})
	if first["status"] != "require_interaction" {
		t.Fatalf("first = %v", first)
	}
	for _, bad := range []url.Values{
		{"auth_session": {"other"}, "openid4vp_response": {`{"vp_token":"x"}`}},
		{"auth_session": {fake.AuthSession}, "openid4vp_response": {`{"vp_token":""}`}},
		{"auth_session": {fake.AuthSession}, "openid4vp_response": {`not json`}},
	} {
		if _, out := form(t, f, fake.IARPath, bad); out["status"] != "error" {
			t.Fatalf("%v = %v", bad, out)
		}
	}
	_, ok := form(t, f, fake.IARPath, url.Values{"auth_session": {fake.AuthSession}, "openid4vp_response": {`{"vp_token":{"type":"VerifiablePresentation"}}`}})
	if ok["status"] != "ok" {
		t.Fatalf("second = %v", ok)
	}
	code, isText := ok["code"].(string)
	if !isText {
		t.Fatalf("code = %v", ok["code"])
	}
	if _, out := token(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}}); out["access_token"] == nil {
		t.Fatalf("token = %v", out)
	}
	// The pre-authorized grant keeps its recorded answer.
	if _, out := token(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}}); out["access_token"] == nil {
		t.Fatalf("pre-authorized token = %v", out)
	}
	resp, err = f.Client().Post(f.URL()+fake.IARPath, "application/x-www-form-urlencoded", strings.NewReader("%zz")) //nolint:noctx // a test call
	if err != nil {
		t.Fatal(err)
	}
	if cerr := resp.Body.Close(); cerr != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a form that does not parse = %d %v", resp.StatusCode, cerr)
	}
}
