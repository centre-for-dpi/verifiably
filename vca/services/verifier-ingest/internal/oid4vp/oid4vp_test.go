// SPDX-License-Identifier: Apache-2.0

package oid4vp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/oid4vp"
)

// clock is the fixed time of the tests.
var clock = time.Unix(1700000000, 0).UTC()

// request returns one request with a DCQL query.
func request() oid4vp.Request {
	return oid4vp.Request{
		ClientID:     "https://verify.example",
		ResponseURI:  "https://verify.example/oid4vp/response",
		ResponseMode: oid4vp.ResponseModeDirectPost,
		Nonce:        "n1",
		State:        "s1",
		DCQL:         `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]}}]}`,
		IssuedAt:     clock,
		ExpiresAt:    clock.Add(5 * time.Minute),
	}
}

func TestParseResponseMode(t *testing.T) {
	for _, value := range []string{"", " direct_post "} {
		got, err := oid4vp.ParseResponseMode(value)
		if err != nil || got != oid4vp.ResponseModeDirectPost {
			t.Errorf("ParseResponseMode(%q) = %q, %v", value, got, err)
		}
	}
	if got, err := oid4vp.ParseResponseMode("direct_post.jwt"); err != nil || got != oid4vp.ResponseModeDirectPostJWT {
		t.Errorf("ParseResponseMode = %q, %v", got, err)
	}
	if _, err := oid4vp.ParseResponseMode("fragment"); err == nil {
		t.Error("an unknown response mode wants an error")
	}
}

func TestClaimsAndSign(t *testing.T) {
	claims, err := request().Claims()
	if err != nil {
		t.Fatal(err)
	}
	if claims["response_type"] != "vp_token" || claims["aud"] != oid4vp.AudienceSelfIssued {
		t.Errorf("claims = %v", claims)
	}
	if claims["nonce"] != "n1" || claims["state"] != "s1" {
		t.Errorf("claims = %v", claims)
	}
	if _, ok := claims["dcql_query"]; !ok {
		t.Error("the request object carries the query")
	}
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	token, err := request().Sign(key, "kid-1")
	if err != nil {
		t.Fatal(err)
	}
	header, err := jose.PeekHeader(token)
	if err != nil {
		t.Fatal(err)
	}
	if header.Typ != oid4vp.TypeRequestObject || header.Kid != "kid-1" {
		t.Errorf("header = %+v", header)
	}
	back, err := oid4vp.ReadRequestObject(" " + token + " ")
	if err != nil {
		t.Fatal(err)
	}
	if back["client_id"] != "https://verify.example" {
		t.Errorf("claims = %v", back)
	}
	if _, err := oid4vp.ReadRequestObject("not a token"); err == nil {
		t.Error("a token that is not a JWS wants an error")
	}
}

func TestSignWithoutQuery(t *testing.T) {
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	r := request()
	r.DCQL = "   "
	token, err := r.Sign(key, "")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := oid4vp.ReadRequestObject(token)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := claims["dcql_query"]; ok {
		t.Error("a request without a query writes no dcql_query")
	}
	broken := request()
	broken.DCQL = "{"
	if _, err := broken.Claims(); err == nil {
		t.Error("a broken query wants an error")
	}
	if _, err := broken.Sign(key, ""); err == nil {
		t.Error("a broken query wants an error from Sign too")
	}
	if _, err := r.Sign("not a key", ""); err == nil {
		t.Error("a value that is not a key wants an error")
	}
}

func TestAuthorizeURL(t *testing.T) {
	got := oid4vp.AuthorizeURL(oid4vp.DefaultScheme, "client", "https://verify.example/r/1")
	if !strings.HasPrefix(got, "openid4vp://authorize?") {
		t.Errorf("url = %q", got)
	}
	if !strings.Contains(got, "request_uri=https%3A%2F%2Fverify.example%2Fr%2F1") {
		t.Errorf("url = %q", got)
	}
}

func TestAllowlistRefuses(t *testing.T) {
	cases := map[string]struct {
		allow oid4vp.Allowlist
		url   string
	}{
		"no host allowed": {oid4vp.Allowlist{}, "https://wallet.example/r"},
		"not a URL":       {oid4vp.Allowlist{Hosts: []string{"wallet.example"}}, "https://a b.example"},
		"plain http":      {oid4vp.Allowlist{Hosts: []string{"wallet.example"}}, "http://wallet.example/r"},
		"other scheme":    {oid4vp.Allowlist{Hosts: []string{"wallet.example"}}, "file:///etc/passwd"},
		"user name":       {oid4vp.Allowlist{Hosts: []string{"wallet.example"}}, "https://user@wallet.example"},
		"no host":         {oid4vp.Allowlist{Hosts: []string{"wallet.example"}}, "https:///r"},
		"other host":      {oid4vp.Allowlist{Hosts: []string{"wallet.example"}}, "https://evil.example/r"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.allow.Check(context.Background(), c.url)
			if err == nil {
				t.Fatal("want an error")
			}
			if !errors.Is(err, oid4vp.ErrRefused) {
				t.Errorf("error = %v, want ErrRefused", err)
			}
		})
	}
}

func TestAllowlistAccepts(t *testing.T) {
	allow := oid4vp.Allowlist{Hosts: []string{"wallet.example", ".gov.example"}}
	for _, url := range []string{"https://wallet.example/r", "https://WALLET.example./r", "https://id.gov.example/r"} {
		if _, err := allow.Check(context.Background(), url); err != nil {
			t.Errorf("Check(%q) = %v", url, err)
		}
	}
	dev := oid4vp.Allowlist{Hosts: []string{"localhost"}, AllowPlainHTTP: true}
	if _, err := dev.Check(context.Background(), "http://localhost:9/r"); err != nil {
		t.Errorf("a development deployment reaches localhost, got %v", err)
	}
}

func TestFetch(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(" token.value.here \n"))
	}))
	defer s.Close()
	f := oid4vp.Fetcher{Allow: oid4vp.Allowlist{Hosts: []string{"127.0.0.1"}, AllowPlainHTTP: true}}
	got, err := f.Fetch(context.Background(), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got != "token.value.here" {
		t.Errorf("token = %q", got)
	}
}

func TestFetchLimitsAndErrors(t *testing.T) {
	allow := oid4vp.Allowlist{Hosts: []string{"127.0.0.1"}, AllowPlainHTTP: true}
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 100)))
	}))
	defer big.Close()
	small := oid4vp.Fetcher{Allow: allow, MaxBytes: 10}
	if _, err := small.Fetch(context.Background(), big.URL); err == nil {
		t.Error("a request object over the limit wants an error")
	}
	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer missing.Close()
	f := oid4vp.Fetcher{Allow: allow, Timeout: time.Second}
	if _, err := f.Fetch(context.Background(), missing.URL); err == nil {
		t.Error("a 404 answer wants an error")
	}
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := closed.URL
	closed.Close()
	if _, err := f.Fetch(context.Background(), url); err == nil {
		t.Error("a server that is gone wants an error")
	}
	if _, err := f.Fetch(context.Background(), "https://evil.example/r"); err == nil {
		t.Error("a host outside the list wants an error")
	}
	withClient := oid4vp.Fetcher{Allow: allow, Client: &http.Client{Timeout: time.Second}}
	if _, err := withClient.Fetch(context.Background(), "http://127.0.0.1:1/r"); err == nil {
		t.Error("a closed port wants an error")
	}
	if _, err := f.Fetch(context.Background(), "http://127.0.0.1/\x7f"); err == nil {
		t.Error("a URL the request builder refuses wants an error")
	}
}
