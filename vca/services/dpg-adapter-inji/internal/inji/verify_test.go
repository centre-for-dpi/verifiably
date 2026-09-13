// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCreateRequestBuildsTheWalletUri(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"transactionId":"tx-1","requestId":"req-1","expiresAt":1777000000}`))
	}))
	defer srv.Close()
	v := NewVerify(newHTTP(srv), "did:web:verifier.example:v1:verify", "https://verify.example")
	got, err := v.CreateRequest(context.Background(), `{"id":"x","input_descriptors":[]}`, "nonce-1")
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if got.State != "tx-1|req-1" {
		t.Fatalf("state = %q", got.State)
	}
	if got.ExpiresAt != 1777000000 {
		t.Fatalf("expiry = %d", got.ExpiresAt)
	}
	u, err := url.Parse(got.RequestURI)
	if err != nil {
		t.Fatalf("the request URI is broken: %v", err)
	}
	if u.Scheme != "openid4vp" {
		t.Fatalf("scheme = %q", u.Scheme)
	}
	if u.Query().Get("client_id") != "did:web:verifier.example:v1:verify" {
		t.Fatalf("client id = %q", u.Query().Get("client_id"))
	}
	want := "https://verify.example/v1/verify/vp-request/req-1"
	if u.Query().Get("request_uri") != want {
		t.Fatalf("request URI = %q, want %q", u.Query().Get("request_uri"), want)
	}
	if body["clientId"] != "did:web:verifier.example:v1:verify" || body["nonce"] != "nonce-1" {
		t.Fatalf("body = %v", body)
	}
	if body["presentationDefinition"] == nil {
		t.Fatal("the definition did not reach the service")
	}
	if v.ClientID() != "did:web:verifier.example:v1:verify" {
		t.Fatalf("client id = %q", v.ClientID())
	}
}

func TestCreateRequestUsesTheBaseUrlWhenNoPublicUrlIsSet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"transactionId":"tx","requestId":"req"}`))
	}))
	defer srv.Close()
	v := NewVerify(newHTTP(srv), "did:x", "")
	got, err := v.CreateRequest(context.Background(), "", "")
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	if !strings.Contains(got.RequestURI, url.QueryEscape(srv.URL)) {
		t.Fatalf("request URI = %q", got.RequestURI)
	}
}

func TestCreateRequestChecksTheDefinitionAndTheAnswer(t *testing.T) {
	body := `{"transactionId":"tx","requestId":""}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	v := NewVerify(newHTTP(srv), "did:x", "")
	if _, err := v.CreateRequest(context.Background(), "{", ""); err == nil {
		t.Fatal("CreateRequest accepted a broken definition")
	}
	if _, err := v.CreateRequest(context.Background(), "", ""); err == nil {
		t.Fatal("CreateRequest accepted an answer without a request id")
	}
}

func TestCreateRequestReportsAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	v := NewVerify(newHTTP(srv), "did:x", "")
	if _, err := v.CreateRequest(context.Background(), "", ""); err == nil {
		t.Fatal("CreateRequest accepted a failure")
	}
}

func TestResultReadsTheTransaction(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write([]byte(`{"transactionId":"tx-1","vpResultStatus":"SUCCESS","vcResults":[]}`))
	}))
	defer srv.Close()
	v := NewVerify(newHTTP(srv), "did:x", "")
	got, err := v.Result(context.Background(), "tx-1|req-1")
	if err != nil {
		t.Fatalf("Result: %v", err)
	}
	if path != "/v1/verify/vp-result/tx-1" {
		t.Fatalf("path = %q", path)
	}
	if !got.Succeeded() || !got.Answered() {
		t.Fatalf("result = %+v", got)
	}
}

func TestResultNeedsATransactionId(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	v := NewVerify(newHTTP(srv), "did:x", "")
	if _, err := v.Result(context.Background(), "|req"); err == nil {
		t.Fatal("Result accepted a state without a transaction id")
	}
}

func TestResultReportsAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	v := NewVerify(newHTTP(srv), "did:x", "")
	if _, err := v.Result(context.Background(), "tx"); err == nil {
		t.Fatal("Result accepted a failure")
	}
}

func TestTransactionIDOf(t *testing.T) {
	if got := TransactionIDOf("tx|req"); got != "tx" {
		t.Fatalf("id = %q", got)
	}
	if got := TransactionIDOf("tx"); got != "tx" {
		t.Fatalf("id = %q", got)
	}
}

func TestAnsweredAndSucceeded(t *testing.T) {
	if (Result{}).Answered() {
		t.Fatal("an empty status means no answer")
	}
	if !(Result{VPResultStatus: "success"}).Succeeded() {
		t.Fatal("the status comparison ignores the letter case")
	}
	if (Result{VPResultStatus: "INVALID"}).Succeeded() {
		t.Fatal("an invalid status is not a success")
	}
}

func TestRequestedClaimsReadsEveryFieldPath(t *testing.T) {
	definition := `{"id":"x","input_descriptors":[{"id":"d","constraints":{"fields":[
      {"path":["$.credentialSubject.fullName","$['vc']['fullName']"]},
      {"path":["$.age_over_18"]},
      {"path":[""]}]}}]}`
	got := RequestedClaims(definition)
	want := map[string]bool{"fullName": true, "age_over_18": true}
	if len(got) != len(want) {
		t.Fatalf("claims = %v", got)
	}
	for _, name := range got {
		if !want[name] {
			t.Fatalf("claims = %v", got)
		}
	}
	if RequestedClaims("{") != nil {
		t.Fatal("a broken definition names no claim")
	}
}

func TestMatchesRequestedClaims(t *testing.T) {
	farmer := VCResult{VC: json.RawMessage(`{"credentialSubject":{"fullName":"Ada"}}`)}
	library := VCResult{VC: json.RawMessage(`{"credentialSubject":{"memberNumber":"LIB-77"}}`)}
	compact := VCResult{VC: json.RawMessage(`"header.payload.sig"`)}
	if !MatchesRequestedClaims([]VCResult{library}, nil) {
		t.Fatal("an empty name list skips the check")
	}
	if !MatchesRequestedClaims([]VCResult{farmer}, []string{"fullName"}) {
		t.Fatal("the matching credential was not found")
	}
	if MatchesRequestedClaims([]VCResult{library}, []string{"fullName"}) {
		t.Fatal("a credential without the claim must lower the verdict")
	}
	if !MatchesRequestedClaims([]VCResult{compact}, []string{"fullName"}) {
		t.Fatal("a compact token carries its claims in disclosures, so the check passes")
	}
	if !MatchesRequestedClaims(nil, []string{"fullName"}) {
		t.Fatal("no readable credential means no verdict change")
	}
}

func TestClaimNameOf(t *testing.T) {
	cases := map[string]string{
		"$.credentialSubject.fullName": "fullName",
		"$['vc']['type']":              "type",
		"  $.age_over_18  ":            "age_over_18",
		"":                             "",
		"$":                            "$",
	}
	for in, want := range cases {
		if got := claimNameOf(in); got != want {
			t.Fatalf("claimNameOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClaimNamesOfAnUnreadableCredential(t *testing.T) {
	if _, ok := claimNames(nil); ok {
		t.Fatal("an empty credential is not readable")
	}
	if _, ok := claimNames(json.RawMessage(`[1,2]`)); ok {
		t.Fatal("a list is not a credential document")
	}
	names, ok := claimNames(json.RawMessage(`{"a":{"b":1},"c":[{"d":2}]}`))
	if !ok || !names["b"] || !names["d"] {
		t.Fatalf("names = %v", names)
	}
}
