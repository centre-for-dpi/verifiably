// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"context"
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
	residence := `{"format":"ldp_vc","credential_definition":{"type":["ResidencePermitCredential","VerifiableCredential"]}}`
	status, body := postJSON(t, f, "/v1/certify/issuance/credential", residence)
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
	if _, body := postJSON(t, f, "/v1/certify/issuance/credential", residence); strings.Contains(body, "credentialStatus") {
		t.Errorf("the entry stays: %s", body)
	}
	// Another format gets the recorded answer.
	if _, body := postJSON(t, f, "/v1/certify/issuance/credential", `{"format":"vc+sd-jwt"}`); !strings.Contains(body, "credentialSubject") {
		t.Errorf("recorded answer = %s", body)
	}
	// No row answers the error of the plugin.
	postJSON(t, f, "/v1/certify/pre-authorized-data", `{"credential_configuration_id":"vca-residence-ldp","claims":{"id":"other"}}`)
	if status, body := postJSON(t, f, "/v1/certify/issuance/credential", residence); status != http.StatusBadRequest ||
		!strings.Contains(body, "ERROR_FETCHING_DATA_RECORD_FROM_TABLE") {
		t.Errorf("no row = %d %s", status, body)
	}
	// A request for a type no configuration has, and a broken template.
	for _, id := range []string{"Unknown", "Broken"} {
		if id == "Broken" {
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
		request := `{"format":"ldp_vc","credential_definition":{"type":["VerifiableCredential","` + id + `"]}}`
		if status, _ := postJSON(t, f, "/v1/certify/issuance/credential", request); status != http.StatusBadRequest {
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
	text := `{"format":"ldp_vc","credential_definition":{"type":["Text","VerifiableCredential"]}}`
	if status, _ := postJSON(t, f, "/v1/certify/issuance/credential", text); status != http.StatusInternalServerError {
		t.Errorf("text template = %d", status)
	}
}

// register stores one ldp_vc configuration with a template in the fake.
func register(t *testing.T, f *fake.Server, id, typ, template string) {
	t.Helper()
	entry := map[string]any{
		"credentialConfigKeyId": id, "credentialFormat": "ldp_vc", "scope": "vca_credential",
		"credentialTypes": []string{"VerifiableCredential", typ}, "metaDataDisplay": []any{},
		"vcTemplate": base64.StdEncoding.EncodeToString([]byte(template)),
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if status, body := postJSON(t, f, "/v1/certify/credential-configurations", string(raw)); status != http.StatusCreated {
		t.Fatalf("create %s = %d %s", id, status, body)
	}
}

// TestFakePicksTheTemplateFromTheRequest: Certify 0.14.0 picks the
// configuration from the scope of the token and the body of the request,
// never from the row. The fake does the same, so a test sees what a row
// of one configuration gives under the template of another. The guard
// of the template then decides: it renders only for the row of its own
// configuration.
func TestFakePicksTheTemplateFromTheRequest(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	dir := t.TempDir()
	f.SetClaimsDir(dir)
	plain := "{\n  \"type\": [\"VerifiableCredential\", \"%s\"],\n  \"credentialSubject\": {\"value\": \"${c1}\"}\n}\n"
	register(t, f, "farmer", "FarmerRegistration", strings.Replace(plain, "%s", "FarmerRegistration", 1))
	register(t, f, "licence", "MedicalLicence", strings.Replace(plain, "%s", "MedicalLicence", 1))
	guarded := "#if($config_id == 'guarded')\n" + strings.Replace(plain, "%s", "GuardedLicence", 1) + "#end\n"
	register(t, f, "guarded", "GuardedLicence", guarded)
	w := claims.Writer{Dir: dir}
	if err := w.Put(claims.Row{Subject: claims.Key("s-1"), ConfigID: "farmer", ExpiresAt: time.Now().Add(time.Hour),
		Claims: []string{"plot 17"}}); err != nil {
		t.Fatal(err)
	}
	postJSON(t, f, "/v1/certify/pre-authorized-data", `{"credential_configuration_id":"farmer","claims":{"id":"s-1"}}`)
	ask := func(typ string) (int, string) {
		return postJSON(t, f, "/v1/certify/issuance/credential",
			`{"format":"ldp_vc","credential_definition":{"type":["VerifiableCredential","`+typ+`"]}}`)
	}
	// An unguarded template of another configuration renders the row.
	if status, body := ask("MedicalLicence"); status != http.StatusOK || !strings.Contains(body, "MedicalLicence") ||
		!strings.Contains(body, "plot 17") {
		t.Errorf("unguarded = %d %s", status, body)
	}
	// A guarded template of another configuration renders nothing.
	if status, body := ask("GuardedLicence"); status == http.StatusOK || strings.Contains(body, "plot 17") {
		t.Errorf("guarded = %d %s", status, body)
	}
	// A guarded template renders the row of its own configuration.
	if err := w.Put(claims.Row{Subject: claims.Key("s-1"), ConfigID: "guarded", ExpiresAt: time.Now().Add(time.Hour),
		Claims: []string{"licence 9"}}); err != nil {
		t.Fatal(err)
	}
	if status, body := ask("GuardedLicence"); status != http.StatusOK || !strings.Contains(body, "licence 9") {
		t.Errorf("own row = %d %s", status, body)
	}
	// The query reads only a row whose end lies ahead (ADR-056
	// decision 3), so an expired row gives no credential.
	f.SetNow(func() time.Time { return time.Now().Add(2 * time.Hour) })
	if status, body := ask("GuardedLicence"); status != http.StatusBadRequest || !strings.Contains(body, "ERROR_FETCHING_DATA_RECORD_FROM_TABLE") {
		t.Errorf("expired row = %d %s", status, body)
	}
	f.SetNow(nil)
	// A request that names no type finds no configuration.
	if status, _ := postJSON(t, f, "/v1/certify/issuance/credential", `{"format":"ldp_vc"}`); status != http.StatusBadRequest {
		t.Errorf("no type = %d", status)
	}
	// A bearer token names the row by its sub. A token that does not
	// read leaves the staged subject.
	if err := w.Put(claims.Row{Subject: "token-row", ConfigID: "guarded", ExpiresAt: time.Now().Add(time.Hour),
		Claims: []string{"licence 10"}}); err != nil {
		t.Fatal(err)
	}
	body := `{"format":"ldp_vc","credential_definition":{"type":["VerifiableCredential","GuardedLicence"]}}`
	for token, want := range map[string]string{
		"Bearer e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"token-row"}`)) + ".s": "licence 10",
		"Bearer e30." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + ".s":                  "licence 9",
		"Bearer e30.%%%.s": "licence 9",
		"Bearer x":         "licence 9",
		"Basic x":          "licence 9",
	} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.URL()+"/v1/certify/issuance/credential",
			strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", token)
		resp, err := f.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(resp.Body)
		if cerr := resp.Body.Close(); err != nil || cerr != nil {
			t.Fatal(err, cerr)
		}
		if !strings.Contains(string(raw), want) {
			t.Errorf("%s: %s, want %s", token, raw, want)
		}
	}
}

// TestRenderFollowsTheVelocityBlocks: the renderer keeps the block of a
// true condition, drops the block of a false one, and nests.
func TestRenderFollowsTheVelocityBlocks(t *testing.T) {
	template := "#if($config_id == 'a')\nA\n#if($v_status_uri && $v_status_uri != \"\")\nS ${v_status_uri}\n#end\n" +
		"#if($claim_169_values)\nQ\n#end\n#if($other)\nO\n#end\nZ ${c1}\n#end\n"
	cases := []struct {
		row  claims.Row
		want string
	}{
		{claims.Row{ConfigID: "a", StatusURI: "u", Claims: []string{"1"}}, "A\nS u\nZ 1\n"},
		{claims.Row{ConfigID: "a", Claims: []string{"1"}}, "A\nZ 1\n"},
		{claims.Row{ConfigID: "b", StatusURI: "u", Claims: []string{"1"}}, ""},
		{claims.Row{Claims: []string{"1"}}, ""},
	}
	for _, c := range cases {
		if got := fake.Render(template, c.row); got != c.want {
			t.Errorf("Render(%+v) = %q, want %q", c.row, got, c.want)
		}
	}
	if got := fake.Render("#if($config_id == \"a\")\nX\n#end\n", claims.Row{ConfigID: "a"}); got != "X\n" {
		t.Errorf("double quotes = %q", got)
	}
}
