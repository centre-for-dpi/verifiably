// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/claims"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
)

// postJSON sends one JSON body and returns the status and the answer.
func postJSON(t *testing.T, f *fake.Server, path, body string) (int, string) {
	t.Helper()
	resp, err := f.Client().Post(f.URL()+path, "application/json", strings.NewReader(body)) //nolint:noctx // a test call
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
	return resp.StatusCode, string(raw)
}

// TestFakeIssuesFromTheClaimsStore: with a claims directory, the fake
// reads the row of the staged subject and fills the template of its
// configuration, as the Postgres data provider and Certify do.
func TestFakeIssuesFromTheClaimsStore(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	dir := t.TempDir()
	f.SetClaimsDir(dir)
	template := "{\n  \"issuer\": \"${_issuer}\",\n#if($v_status_uri && $v_status_uri != \"\")\n  \"credentialStatus\": {\"id\": \"${v_status_uri}#${v_status_index}\"},\n#end\n" +
		"  \"credentialSubject\": {\"id\": \"${_holderId}\", \"fullName\": \"${c1}\", \"credits\": ${c2}\n#if($claim_169_values)\n, \"identityQR\": \"x\"\n#end\n  }\n}\n"
	entry := map[string]any{
		"credentialConfigKeyId": "vca-residence-ldp", "credentialFormat": "ldp_vc", "scope": "vca_credential",
		"credentialTypes": []string{"VerifiableCredential", "ResidencePermitCredential"},
		"vcTemplate":      base64.StdEncoding.EncodeToString([]byte(template)), "metaDataDisplay": []any{},
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if status, body := postJSON(t, f, "/v1/certify/credential-configurations", string(raw)); status != http.StatusCreated {
		t.Fatalf("create = %d %s", status, body)
	}
	w := claims.Writer{Dir: dir}
	row := claims.Row{Subject: claims.Key("s-1"), ConfigID: "vca-residence-ldp", ExpiresAt: time.Now().Add(time.Hour),
		StatusURI: "https://status.gov.example/1", StatusIndex: "4", Claims: []string{"Amina Wanjiru", "42"}}
	if errErr := w.Put(row); errErr != nil {
		t.Fatal(errErr)
	}
	postJSON(t, f, "/v1/certify/pre-authorized-data", `{"credential_configuration_id":"vca-residence-ldp","claims":{"id":"s-1"}}`)
	status, body := postJSON(t, f, "/v1/certify/issuance/credential", `{"format":"ldp_vc"}`)
	if status != http.StatusOK {
		t.Fatalf("credential = %d %s", status, body)
	}
	var answer struct {
		Credential struct {
			Issuer  string         `json:"issuer"`
			Status  map[string]any `json:"credentialStatus"`
			Subject map[string]any `json:"credentialSubject"`
		} `json:"credential"`
	}
	if errErr := json.Unmarshal([]byte(body), &answer); errErr != nil {
		t.Fatalf("%v: %s", errErr, body)
	}
	c := answer.Credential
	if c.Issuer != fake.FakeIssuer || c.Subject["fullName"] != "Amina Wanjiru" || c.Subject["credits"] != float64(42) ||
		c.Subject["id"] != fake.FakeHolder || c.Status["id"] != "https://status.gov.example/1#4" || c.Subject["identityQR"] != nil {
		t.Errorf("credential = %s", body)
	}
	// Without a status address the guarded entry goes.
	row.StatusURI = ""
	if errErr := w.Put(row); errErr != nil {
		t.Fatal(errErr)
	}
	if _, body := postJSON(t, f, "/v1/certify/issuance/credential", `{"format":"ldp_vc"}`); strings.Contains(body, "credentialStatus") {
		t.Errorf("the entry stays: %s", body)
	}
	// Another format gets the recorded answer.
	if _, body := postJSON(t, f, "/v1/certify/issuance/credential", `{"format":"vc+sd-jwt"}`); !strings.Contains(body, "credentialSubject") {
		t.Errorf("recorded answer = %s", body)
	}
	// No row answers the error of the plugin.
	postJSON(t, f, "/v1/certify/pre-authorized-data", `{"credential_configuration_id":"vca-residence-ldp","claims":{"id":"other"}}`)
	if status, body := postJSON(t, f, "/v1/certify/issuance/credential", `{"format":"ldp_vc"}`); status != http.StatusBadRequest ||
		!strings.Contains(body, "ERROR_FETCHING_DATA_RECORD_FROM_TABLE") {
		t.Errorf("no row = %d %s", status, body)
	}
	// A row of an unknown configuration, and a broken template.
	for _, id := range []string{"unknown", "broken"} {
		if id == "broken" {
			bad := map[string]any{"credentialConfigKeyId": "broken", "credentialFormat": "ldp_vc", "vcTemplate": "%%", "metaDataDisplay": []any{},
				"credentialTypes": []string{"VerifiableCredential", "Broken"}}
			raw2, merr := json.Marshal(bad)
			if merr != nil {
				t.Fatal(merr)
			}
			postJSON(t, f, "/v1/certify/credential-configurations", string(raw2))
		}
		if errErr := w.Put(claims.Row{Subject: claims.Key(id), ConfigID: id, ExpiresAt: time.Now().Add(time.Hour)}); errErr != nil {
			t.Fatal(errErr)
		}
		postJSON(t, f, "/v1/certify/pre-authorized-data", `{"claims":{"id":"`+id+`"}}`)
		if status, _ := postJSON(t, f, "/v1/certify/issuance/credential", `{"format":"ldp_vc"}`); status != http.StatusBadRequest {
			t.Errorf("%s = %d", id, status)
		}
	}
	// A template that does not render JSON is a server error.
	notJSON := map[string]any{"credentialConfigKeyId": "text", "credentialFormat": "ldp_vc", "metaDataDisplay": []any{},
		"credentialTypes": []string{"VerifiableCredential", "Text"}, "vcTemplate": base64.StdEncoding.EncodeToString([]byte("not json"))}
	raw, err = json.Marshal(notJSON)
	if err != nil {
		t.Fatal(err)
	}
	postJSON(t, f, "/v1/certify/credential-configurations", string(raw))
	if err := w.Put(claims.Row{Subject: claims.Key("text"), ConfigID: "text", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	postJSON(t, f, "/v1/certify/pre-authorized-data", `{"claims":{"id":"text"}}`)
	if status, _ := postJSON(t, f, "/v1/certify/issuance/credential", `{"format":"ldp_vc"}`); status != http.StatusInternalServerError {
		t.Errorf("text template = %d", status)
	}
}
