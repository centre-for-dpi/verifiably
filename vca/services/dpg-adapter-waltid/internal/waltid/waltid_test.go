// SPDX-License-Identifier: Apache-2.0

package waltid

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// newClient returns a client whose three roles point at the server.
func newClient(t *testing.T, srv *httptest.Server, opts Options) *Client {
	t.Helper()
	c := dpgclient.New(dpgclient.Options{
		BaseURL: srv.URL, HTTP: srv.Client(), Retries: -1, Sleep: func(time.Duration) {},
	})
	opts.Issuer, opts.Verifier, opts.Wallet = c, c, c
	return New(opts)
}

func TestNewFillsTheDefaultStandardVersion(t *testing.T) {
	c := New(Options{})
	if c.standardVersion != "draft13" {
		t.Fatalf("standard version = %q", c.standardVersion)
	}
	if c.HasIssuer() || c.HasVerifier() || c.HasWallet() {
		t.Fatal("a client without URLs serves no role")
	}
}

func TestEveryCallNeedsItsRole(t *testing.T) {
	c := New(Options{})
	ctx := context.Background()
	if _, err := c.Metadata(ctx); !errors.Is(err, ErrNoIssuer) {
		t.Fatalf("Metadata error = %v", err)
	}
	if _, _, err := c.EnsureIssuerKey(ctx); !errors.Is(err, ErrNoIssuer) {
		t.Fatalf("EnsureIssuerKey error = %v", err)
	}
	if _, err := c.CreateOffer(ctx, "/x", IssuanceRequest{}); !errors.Is(err, ErrNoIssuer) {
		t.Fatalf("CreateOffer error = %v", err)
	}
	if _, err := c.Verify(ctx, VerifyRequest{}); !errors.Is(err, ErrNoVerifier) {
		t.Fatalf("Verify error = %v", err)
	}
	if _, err := c.SessionResult(ctx, "x"); !errors.Is(err, ErrNoVerifier) {
		t.Fatalf("SessionResult error = %v", err)
	}
	if _, err := c.Login(ctx, Account{}); !errors.Is(err, ErrNoWallet) {
		t.Fatalf("Login error = %v", err)
	}
	s := WalletSession{}
	if _, err := c.ListCredentials(ctx, s); !errors.Is(err, ErrNoWallet) {
		t.Fatalf("ListCredentials error = %v", err)
	}
	if err := c.DeleteCredential(ctx, s, "x"); !errors.Is(err, ErrNoWallet) {
		t.Fatalf("DeleteCredential error = %v", err)
	}
	if _, err := c.ResolveOffer(ctx, s, "x"); !errors.Is(err, ErrNoWallet) {
		t.Fatalf("ResolveOffer error = %v", err)
	}
	if err := c.AcceptOffer(ctx, s, "x"); !errors.Is(err, ErrNoWallet) {
		t.Fatalf("AcceptOffer error = %v", err)
	}
	if _, err := c.Present(ctx, s, "x", nil, nil); !errors.Is(err, ErrNoWallet) {
		t.Fatalf("Present error = %v", err)
	}
}

func TestMetadataReadsThePathOfTheStandardVersion(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write([]byte(`{"credential_issuer":"https://i.example","credential_configurations_supported":{}}`))
	}))
	defer srv.Close()
	c := newClient(t, srv, Options{StandardVersion: "draft11"})
	meta, err := c.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if path != "/draft11/.well-known/openid-credential-issuer" {
		t.Fatalf("path = %q", path)
	}
	if meta.CredentialIssuer != "https://i.example" || len(meta.Raw) == 0 {
		t.Fatalf("metadata = %+v", meta)
	}
}

func TestMetadataReportsABrokenDocument(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	c := newClient(t, srv, Options{})
	if _, err := c.Metadata(context.Background()); err == nil {
		t.Fatal("Metadata accepted a broken document")
	}
}

func TestEnsureIssuerKeyUsesThePinnedKey(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer srv.Close()
	c := newClient(t, srv, Options{IssuerKey: `{"type":"jwk"}`, IssuerDid: "did:key:zPinned"})
	key, did, err := c.EnsureIssuerKey(context.Background())
	if err != nil {
		t.Fatalf("EnsureIssuerKey: %v", err)
	}
	if did != "did:key:zPinned" || string(key) != `{"type":"jwk"}` {
		t.Fatalf("key %s did %q", key, did)
	}
	if calls != 0 {
		t.Fatal("a pinned key must not onboard a new one")
	}
}

func TestEnsureIssuerKeyOnboardsOnceAndCachesTheAnswer(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"issuerKey":{"type":"jwk"},"issuerDid":"did:key:zNew"}`))
	}))
	defer srv.Close()
	c := newClient(t, srv, Options{})
	for i := 0; i < 2; i++ {
		_, did, err := c.EnsureIssuerKey(context.Background())
		if err != nil || did != "did:key:zNew" {
			t.Fatalf("EnsureIssuerKey: %q %v", did, err)
		}
	}
	if calls != 1 {
		t.Fatalf("onboard calls = %d, want 1", calls)
	}
}

func TestEnsureIssuerKeyReportsAnEmptyAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := newClient(t, srv, Options{})
	if _, _, err := c.EnsureIssuerKey(context.Background()); err == nil {
		t.Fatal("EnsureIssuerKey accepted an empty answer")
	}
}

func TestEnsureIssuerKeyReportsAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	c := newClient(t, srv, Options{})
	if _, _, err := c.EnsureIssuerKey(context.Background()); err == nil {
		t.Fatal("EnsureIssuerKey accepted a failure")
	}
}

func TestCreateOfferReportsAnEmptyAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	c := newClient(t, srv, Options{})
	if _, err := c.CreateOffer(context.Background(), "/x", IssuanceRequest{}); err == nil {
		t.Fatal("CreateOffer accepted an empty answer")
	}
}

func TestVerifyReportsAnEmptyAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	c := newClient(t, srv, Options{})
	if _, err := c.Verify(context.Background(), VerifyRequest{}); err == nil {
		t.Fatal("Verify accepted an empty answer")
	}
}

func TestLoginReportsAMissingTokenOrWallet(t *testing.T) {
	body := `{"token":""}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/wallets") {
			_, _ = w.Write([]byte(`{"wallets":[]}`))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := newClient(t, srv, Options{})
	if _, err := c.Login(context.Background(), Account{Email: "a@b"}); err == nil {
		t.Fatal("Login accepted an empty token")
	}
	body = `{"token":"t"}`
	if _, err := c.Login(context.Background(), Account{Email: "a@b"}); err == nil {
		t.Fatal("Login accepted an account without a wallet")
	}
}

func TestLoginReportsAFailedListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/wallets") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"token":"t"}`))
	}))
	defer srv.Close()
	c := newClient(t, srv, Options{})
	if _, err := c.Login(context.Background(), Account{Email: "a@b"}); err == nil {
		t.Fatal("Login accepted a failed listing")
	}
}

func TestPresentReadsTheRedirect(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"redirectUri":"https://verifier.example/ok"}`))
	}))
	defer srv.Close()
	c := newClient(t, srv, Options{})
	got, err := c.Present(context.Background(), WalletSession{WalletID: "w"}, "openid4vp://x",
		[]string{"c1"}, map[string][]string{"c1": {"age_over_18"}})
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if got.RedirectURI != "https://verifier.example/ok" {
		t.Fatalf("redirect = %q", got.RedirectURI)
	}
	if body["disclosures"] == nil || body["presentationRequest"] != "openid4vp://x" {
		t.Fatalf("body = %v", body)
	}
}

func TestPresentAcceptsAnEmptyAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	c := newClient(t, srv, Options{})
	if _, err := c.Present(context.Background(), WalletSession{}, "x", nil, nil); err != nil {
		t.Fatalf("Present: %v", err)
	}
}

func TestListAndDeleteAndResolveAndAcceptReachTheWallet(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	c := newClient(t, srv, Options{})
	s := WalletSession{Token: "t", WalletID: "w1"}
	ctx := context.Background()
	if _, err := c.ListCredentials(ctx, s); err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if err := c.DeleteCredential(ctx, s, "c1"); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	if _, err := c.ResolveOffer(ctx, s, "offer"); err != nil {
		t.Fatalf("ResolveOffer: %v", err)
	}
	if err := c.AcceptOffer(ctx, s, "offer"); err != nil {
		t.Fatalf("AcceptOffer: %v", err)
	}
	want := []string{
		"GET /wallet-api/wallet/w1/credentials",
		"DELETE /wallet-api/wallet/w1/credentials/c1",
		"POST /wallet-api/wallet/w1/exchange/resolveCredentialOffer",
		"POST /wallet-api/wallet/w1/exchange/useOfferRequest",
	}
	for i, w := range want {
		if seen[i] != w {
			t.Fatalf("call %d = %q, want %q", i, seen[i], w)
		}
	}
}

func TestSessionResultReadsTheSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/openid4vc/session/a%20b" {
			t.Errorf("path = %q", r.URL.EscapedPath())
		}
		_, _ = w.Write([]byte(`{"id":"a b","verificationResult":true}`))
	}))
	defer srv.Close()
	c := newClient(t, srv, Options{})
	got, err := c.SessionResult(context.Background(), "a b")
	if err != nil {
		t.Fatalf("SessionResult: %v", err)
	}
	if got.VerificationResult == nil || !*got.VerificationResult {
		t.Fatalf("session = %+v", got)
	}
}
