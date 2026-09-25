// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
)

// call sends one request and returns the status and the body.
func call(t *testing.T, f *fake.Server, method, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, f.URL()+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(raw)
}

func TestFakeKeepsCredentialConfigurations(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	const api = "/v1/certify/credential-configurations"
	if _, body := call(t, f, http.MethodGet, api+"/"+fake.SeededConfiguration, ""); !strings.Contains(body, "FarmerCredential") {
		t.Fatalf("the sample entry is missing: %s", body)
	}
	if _, body := call(t, f, http.MethodGet, api+"/Nope", ""); !strings.Contains(body, "config_not_found_by_id") {
		t.Fatalf("an unknown id: %s", body)
	}
	if _, body := call(t, f, http.MethodPost, api, "{"); !strings.Contains(body, "errors") {
		t.Fatalf("a broken body: %s", body)
	}
	entries := []string{
		`{"credentialConfigKeyId":"Ldp","credentialFormat":"ldp_vc","credentialTypes":["VerifiableCredential","Ldp"],"contextURLs":["c"],"scope":"s","metaDataDisplay":[{"name":"L"}]}`,
		`{"credentialConfigKeyId":"Sd","credentialFormat":"vc+sd-jwt","sdJwtVct":"v","scope":"s","sdJwtClaims":{"a":{}}}`,
		`{"credentialConfigKeyId":"Md","credentialFormat":"mso_mdoc","doctype":"org.iso.18013.5.1.mDL","scope":"s","msoMdocClaims":{"ns":{"a":{}}}}`,
		`{"credentialConfigKeyId":"Other","credentialFormat":"jwt_vc_json","scope":"s"}`,
	}
	for _, e := range entries {
		if code, body := call(t, f, http.MethodPost, api, e); code != http.StatusCreated || !strings.Contains(body, `"active"`) {
			t.Fatalf("create %s: %d %s", e, code, body)
		}
	}
	clashes := []string{
		`{"credentialConfigKeyId":"Ldp2","credentialFormat":"ldp_vc","credentialTypes":["VerifiableCredential","Ldp"],"contextURLs":["c"]}`,
		`{"credentialConfigKeyId":"Sd2","credentialFormat":"vc+sd-jwt","sdJwtVct":"v"}`,
		`{"credentialConfigKeyId":"Md2","credentialFormat":"mso_mdoc","doctype":"org.iso.18013.5.1.mDL"}`,
	}
	for _, e := range clashes {
		if _, body := call(t, f, http.MethodPost, api, e); !strings.Contains(body, "config_exists") {
			t.Fatalf("a duplicate passed: %s", body)
		}
	}
	if code, _ := call(t, f, http.MethodPost, api, `{"credentialConfigKeyId":"Other2","credentialFormat":"jwt_vc_json"}`); code != http.StatusCreated {
		t.Fatal("an unknown format never clashes")
	}
	if code, body := call(t, f, http.MethodPut, api+"/Ldp", entries[0]); code != http.StatusOK || !strings.Contains(body, `"Ldp"`) {
		t.Fatalf("update: %d %s", code, body)
	}
	if _, body := call(t, f, http.MethodPut, api+"/Nope", "{}"); !strings.Contains(body, "config_not_found_for_update") {
		t.Fatalf("update of an unknown id: %s", body)
	}
	if code, _ := call(t, f, http.MethodDelete, api+"/Ldp", ""); code != http.StatusNotFound {
		t.Fatalf("delete: %d", code)
	}
	if _, ok := f.Configuration("Sd"); !ok {
		t.Fatal("the created entry is not kept")
	}
	meta := get(t, f, "/v1/certify/issuance/.well-known/openid-credential-issuer")
	for _, want := range []string{`"Ldp"`, `"Sd"`, `"Md"`, "org.iso.18013.5.1.mDL", "IdentityCredential"} {
		if !strings.Contains(meta, want) {
			t.Errorf("the metadata lacks %s", want)
		}
	}
}

func TestFakeMetadataNeedsItsRecording(t *testing.T) {
	f := fake.New("testdata-that-does-not-exist")
	defer f.Close()
	if code, _ := call(t, f, http.MethodGet, "/v1/certify/issuance/.well-known/openid-credential-issuer", ""); code != http.StatusInternalServerError {
		t.Fatalf("status = %d", code)
	}
}
