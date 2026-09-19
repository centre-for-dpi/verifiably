// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// signinHandler answers the sign in call and passes the rest on.
func signinHandler(t *testing.T, next http.HandlerFunc) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
			return
		}
		next(w, r)
	}
}

func TestParseDcqlReadsBothShapes(t *testing.T) {
	wrapped := `{"query":{"credentials":[{"id":"vc-1","format":"dc+sd-jwt",
      "claims":[{"path":["fullName"]}]}]}}`
	got, err := ParseDcql(wrapped)
	if err != nil {
		t.Fatalf("ParseDcql: %v", err)
	}
	if len(got.Query.Credentials) != 1 || got.Query.Credentials[0].Format != "dc+sd-jwt" {
		t.Fatalf("query = %+v", got)
	}
	bare := `{"credentials":[{"id":"vc-1","format":"dc+sd-jwt"}]}`
	got, err = ParseDcql(bare)
	if err != nil {
		t.Fatalf("ParseDcql: %v", err)
	}
	if len(got.Query.Credentials) != 1 {
		t.Fatalf("query = %+v", got)
	}
}

func TestParseDcqlRejectsABadDocument(t *testing.T) {
	for _, bad := range []string{"  ", "{", `{"query":{}}`} {
		if _, err := ParseDcql(bad); err == nil {
			t.Fatalf("ParseDcql(%q) returned no error", bad)
		}
	}
}

func TestCreatePresentationSendsTheQuery(t *testing.T) {
	var body map[string]any
	var query string
	srv := httptest.NewServer(signinHandler(t, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		if cerr := json.NewDecoder(r.Body).Decode(&body); cerr != nil {
			t.Fatalf("unexpected error: %v", cerr)
		}
		mustWrite(t, w, []byte(`{"data":{"authorizationRequest":"openid4vp://x",
          "verificationSession":{"id":"s-1"}}}`))
	}))
	defer srv.Close()
	parsed, err := ParseDcql(`{"credentials":[{"id":"vc-1","format":"dc+sd-jwt"}]}`)
	if err != nil {
		t.Fatalf("ParseDcql: %v", err)
	}
	got, err := newClient(srv, nil).CreatePresentation(context.Background(), "v-1", parsed)
	if err != nil {
		t.Fatalf("CreatePresentation: %v", err)
	}
	if got.State != "s-1" || got.RequestURI != "openid4vp://x" {
		t.Fatalf("presentation = %+v", got)
	}
	if !strings.Contains(query, "verifierId=v-1") {
		t.Fatalf("query = %q", query)
	}
	if body["responseMode"] != "direct_post" {
		t.Fatalf("body = %v", body)
	}
	signer := mustAs[map[string]any](t, body["requestSigner"])
	if signer["method"] != "DID" {
		t.Fatalf("signer = %v", signer)
	}
	if body["dcql"] == nil {
		t.Fatal("the query did not reach the platform")
	}
}

func TestCreatePresentationReportsAnEmptyAnswer(t *testing.T) {
	srv := httptest.NewServer(signinHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte(`{"data":{"authorizationRequest":""}}`))
	}))
	defer srv.Close()
	_, err := newClient(srv, nil).CreatePresentation(context.Background(), "v", DcqlQuery{})
	if err == nil {
		t.Fatal("CreatePresentation accepted an empty answer")
	}
}

func TestPresentationReadsTheSession(t *testing.T) {
	srv := httptest.NewServer(signinHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "id=s-1") {
			t.Errorf("query = %q", r.URL.RawQuery)
		}
		mustWrite(t, w, []byte(`{"data":{"state":"ResponseVerified",
          "authorizationResponsePayload":{"vp_token":{"vc-1":["token-a"]}}}}`))
	}))
	defer srv.Close()
	got, err := newClient(srv, nil).Presentation(context.Background(), "s-1")
	if err != nil {
		t.Fatalf("Presentation: %v", err)
	}
	if got.State != StateVerified || len(got.Tokens) != 1 || got.Tokens[0] != "token-a" {
		t.Fatalf("session = %+v", got)
	}
}

func TestPresentationNeedsAState(t *testing.T) {
	srv := httptest.NewServer(signinHandler(t, func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	if _, err := newClient(srv, nil).Presentation(context.Background(), "  "); err == nil {
		t.Fatal("Presentation accepted an empty state")
	}
}

func TestPresentationReportsAFailure(t *testing.T) {
	srv := httptest.NewServer(signinHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := newClient(srv, nil).Presentation(context.Background(), "s-1"); err == nil {
		t.Fatal("Presentation accepted a failure")
	}
}

func TestTokensReadEveryShape(t *testing.T) {
	cases := map[string]int{
		`"one"`:                     1,
		`["one","two"]`:             2,
		`{"b":["two"],"a":["one"]}`: 2,
		`""`:                        0,
		`123`:                       0,
		``:                          0,
	}
	for in, want := range cases {
		if got := Tokens(json.RawMessage(in)); len(got) != want {
			t.Fatalf("Tokens(%s) = %v, want %d", in, got, want)
		}
	}
	got := Tokens(json.RawMessage(`{"b":["two"],"a":["one"]}`))
	if got[0] != "one" || got[1] != "two" {
		t.Fatalf("the order must be stable, got %v", got)
	}
}

func TestEnsureVerifierCreatesOne(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(signinHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if cerr := json.NewDecoder(r.Body).Decode(&body); cerr != nil {
			t.Fatalf("unexpected error: %v", cerr)
		}
		mustWrite(t, w, []byte(`{"data":{"id":"v-1"}}`))
	}))
	defer srv.Close()
	got, err := newClient(srv, nil).EnsureVerifier(context.Background(), "vca", "https://x/logo.png")
	if err != nil || got != "v-1" {
		t.Fatalf("EnsureVerifier = %q, %v", got, err)
	}
	metadata := mustAs[map[string]any](t, body["clientMetadata"])
	if metadata["logo_uri"] != "https://x/logo.png" {
		t.Fatalf("metadata = %v", metadata)
	}
}

func TestEnsureVerifierFindsAnExistingOne(t *testing.T) {
	srv := httptest.NewServer(signinHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusConflict)
			return
		}
		mustWrite(t, w, []byte(`{"data":[{"id":"v-1","publicVerifierId":"vca"}]}`))
	}))
	defer srv.Close()
	got, err := newClient(srv, nil).EnsureVerifier(context.Background(), "vca", "")
	if err != nil || got != "v-1" {
		t.Fatalf("EnsureVerifier = %q, %v", got, err)
	}
}

func TestEnsureVerifierReportsAMissingListing(t *testing.T) {
	list := `{"data":[]}`
	status := http.StatusOK
	srv := httptest.NewServer(signinHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(status)
		mustWrite(t, w, []byte(list))
	}))
	defer srv.Close()
	c := newClient(srv, nil)
	if _, err := c.EnsureVerifier(context.Background(), "vca", ""); err == nil {
		t.Fatal("EnsureVerifier accepted a listing without the verifier")
	}
	status = http.StatusInternalServerError
	if _, err := c.EnsureVerifier(context.Background(), "vca", ""); err == nil {
		t.Fatal("EnsureVerifier accepted a failed listing")
	}
}

func TestEnsureVerifierReportsAnEmptyIdentifierAndAFailure(t *testing.T) {
	body := `{"data":{"id":""}}`
	status := http.StatusOK
	srv := httptest.NewServer(signinHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		mustWrite(t, w, []byte(body))
	}))
	defer srv.Close()
	c := newClient(srv, nil)
	if _, err := c.EnsureVerifier(context.Background(), "vca", ""); err == nil {
		t.Fatal("EnsureVerifier accepted an empty identifier")
	}
	status = http.StatusForbidden
	if _, err := c.EnsureVerifier(context.Background(), "vca", ""); err == nil {
		t.Fatal("EnsureVerifier accepted a failure")
	}
}
