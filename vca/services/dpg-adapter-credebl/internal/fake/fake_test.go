// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
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
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func post(t *testing.T, f *fake.Server, path, request string) string {
	t.Helper()
	resp, err := f.Client().Post(f.URL()+path, "application/json", strings.NewReader(request))
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func status(t *testing.T, f *fake.Server, path string) int {
	t.Helper()
	resp, err := f.Client().Get(f.URL() + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
