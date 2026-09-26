// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
)

const testdata = "../../testdata"

func TestFakeServesTheRecordedAnswers(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	cases := map[string]string{
		"/v1/auth/signin":                             "access_token",
		"/v1/orgs/org-1/oid4vc/issuer-1/template":     "FarmerCredential",
		"/v1/orgs/org-1/oid4vp/verifier":              "publicVerifierId",
		"/v1/orgs/org-1/oid4vp/verifier-presentation": "state",
	}
	for path, want := range cases {
		if body := get(t, f, path); !strings.Contains(body, want) {
			t.Fatalf("%s returned %q, want a body with %q", path, body, want)
		}
	}
	posts := map[string]string{
		"/v1/orgs/org-1/schemas":                      "schemaLedgerId",
		"/v1/orgs/org-1/oid4vc/issuer-1/create-offer": "credentialOffer",
		"/v1/orgs/org-1/oid4vp/presentation":          "authorizationRequest",
		"/v1/orgs/org-1/oid4vc/issuer-1/template":     "d4e8a1f7",
	}
	for path, want := range posts {
		if body := post(t, f, path, "{}"); !strings.Contains(body, want) {
			t.Fatalf("%s returned %q, want a body with %q", path, body, want)
		}
	}
}

func TestFakeCountsTheSignins(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	post(t, f, "/v1/auth/signin", "{}")
	post(t, f, "/v1/auth/signin", "{}")
	if f.Signins() != 2 {
		t.Fatalf("sign ins = %d", f.Signins())
	}
}

func TestFakeSwitchesTheAnswers(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	f.SetSession(fake.SessionVerified)
	if !strings.Contains(get(t, f, "/v1/orgs/org-1/oid4vp/verifier-presentation"), "ResponseVerified") {
		t.Fatal("the verified session is missing")
	}
	f.SetSession(fake.SessionError)
	if !strings.Contains(get(t, f, "/v1/orgs/org-1/oid4vp/verifier-presentation"), "Error") {
		t.Fatal("the failed session is missing")
	}
	f.SetTemplates(fake.Templates)
	if !strings.Contains(get(t, f, "/v1/orgs/org-1/oid4vc/issuer-1/template"), "IdentityCredential") {
		t.Fatal("the template listing is missing")
	}
}

func TestFakeServesTheStatusesInOrder(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	f.SetStatus("/v1/auth/signin", http.StatusTeapot, http.StatusForbidden)
	if code := status(t, f, "/v1/auth/signin"); code != http.StatusTeapot {
		t.Fatalf("first status = %d", code)
	}
	if code := status(t, f, "/v1/auth/signin"); code != http.StatusForbidden {
		t.Fatalf("second status = %d", code)
	}
	if code := status(t, f, "/v1/auth/signin"); code != http.StatusOK {
		t.Fatalf("third status = %d, the list is empty", code)
	}
	f.SetStatus("/v1/auth/signin", http.StatusTeapot)
	f.SetStatus("/v1/auth/signin")
	if code := status(t, f, "/v1/auth/signin"); code != http.StatusOK {
		t.Fatalf("status = %d, an empty list removes the setting", code)
	}
}

func TestFakeReportsAMissingRecording(t *testing.T) {
	f := fake.New("testdata-that-does-not-exist")
	defer f.Close()
	if code := status(t, f, "/v1/auth/signin"); code != http.StatusInternalServerError {
		t.Fatalf("status = %d", code)
	}
}

func TestFakeAnswersAnUnknownPathWithNotFound(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	if code := status(t, f, "/unknown"); code != http.StatusNotFound {
		t.Fatalf("status = %d", code)
	}
}

func TestFakeRecordsTheRequestBody(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	post(t, f, "/v1/auth/signin", `{"email":"admin@example.org"}`)
	var body map[string]any
	if err := f.RequestJSON("/v1/auth/signin", &body); err != nil {
		t.Fatalf("RequestJSON: %v", err)
	}
	if body["email"] != "admin@example.org" {
		t.Fatalf("body = %v", body)
	}
	if len(f.Request("/v1/auth/signin")) == 0 {
		t.Fatal("the fake recorded no body")
	}
}

func get(t *testing.T, f *fake.Server, path string) string {
	t.Helper()
	resp, err := f.Client().Get(f.URL() + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	body, verr := io.ReadAll(resp.Body)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	return string(body)
}

func post(t *testing.T, f *fake.Server, path, request string) string {
	t.Helper()
	resp, err := f.Client().Post(f.URL()+path, "application/json", strings.NewReader(request))
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	body, verr := io.ReadAll(resp.Body)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	return string(body)
}

func status(t *testing.T, f *fake.Server, path string) int {
	t.Helper()
	resp, err := f.Client().Get(f.URL() + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	return resp.StatusCode
}

// call sends one request and returns the status and the body.
func call(t *testing.T, f *fake.Server, method, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, f.URL()+path, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

// TestFakeServesTheOrganisationCalls covers the answers written from
// the platform sources (P6-C1).
func TestFakeServesTheOrganisationCalls(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	org := "/v1/orgs/0b6c2f0e-5a38-4a1e-9d2b-3f7c1e6a9d41"
	cases := []struct {
		method, path string
		status       int
		want         string
	}{
		{http.MethodGet, "/v1/orgs", 200, "Platform-admin"},
		{http.MethodPost, "/v1/orgs", 201, "[ORGANISATION]"},
		{http.MethodGet, org, 200, "SHARED"},
		{http.MethodGet, org + "/dids", 200, "isPrimaryDid"},
		{http.MethodGet, org + "/users", 200, "[ISSUER EMAIL]"},
		{http.MethodPut, org + "/primary-did", 201, "Primary DID"},
		{http.MethodPost, org + "/agents/wallet", 201, "tenantId"},
		{http.MethodPost, org + "/agents/did", 201, "did:key"},
		{http.MethodDelete, org, 202, "deleted"},
		{http.MethodDelete, org, 404, ""},
		{http.MethodGet, org, 404, ""},
		{http.MethodPatch, org, 404, ""},
	}
	for _, c := range cases {
		code, body := call(t, f, c.method, c.path)
		if code != c.status || !strings.Contains(body, c.want) {
			t.Errorf("%s %s = %d %q, want %d with %q", c.method, c.path, code, body, c.status, c.want)
		}
	}
	f.SetOrgs(fake.NoOrgs)
	if code, _ := call(t, f, http.MethodGet, "/v1/orgs"); code != 404 {
		t.Errorf("an empty platform answered %d", code)
	}
	if calls := f.Calls(); len(calls) != len(cases)+1 || calls[0] != "GET /v1/orgs" {
		t.Errorf("calls = %v", calls)
	}
	missing := fake.New(t.TempDir())
	defer missing.Close()
	if code, _ := call(t, missing, http.MethodPost, "/v1/orgs"); code != 500 {
		t.Errorf("a missing answer gave %d", code)
	}
}

// TestFakeServesTheSchemaCalls covers the answers of P6-C2.
func TestFakeServesTheSchemaCalls(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	for body, want := range map[string]string{
		`{"type":"indy"}`: "/SCHEMA/",
		`{"type":"json","schemaPayload":{"schemaType":"no_ledger"}}`: "schema-file-server",
		`{"type":"json","schemaPayload":{"schemaType":"json"}}`:      "schemaLedgerId",
		`not json`: "schemaLedgerId",
	} {
		if got := post(t, f, "/v1/orgs/org-1/schemas", body); !strings.Contains(got, want) {
			t.Errorf("%s gave %q, want %q", body, got, want)
		}
	}
	if code, body := call(t, f, http.MethodPost, "/v1/orgs/org-1/cred-defs"); code != 201 || !strings.Contains(body, "CLAIM_DEF") {
		t.Errorf("cred-defs = %d %s", code, body)
	}
	if body := get(t, f, "/v1/platform/ledgers"); !strings.Contains(body, "bcovrin:testnet") {
		t.Errorf("ledgers = %s", body)
	}
}
