// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// newHTTP returns a client for the server without a retry wait.
func newHTTP(srv *httptest.Server) *dpgclient.Client {
	return dpgclient.New(dpgclient.Options{
		BaseURL: srv.URL, HTTP: srv.Client(), Retries: -1, Sleep: func(time.Duration) {},
	})
}

func TestNilClientsTurnTheRolesOff(t *testing.T) {
	if NewCertify(nil, "") != nil {
		t.Fatal("a nil client must turn the issuer role off")
	}
	if NewVerify(nil, "did:x", "") != nil {
		t.Fatal("a nil client must turn the verifier role off")
	}
	var c *Certify
	var v *Verify
	ctx := context.Background()
	if c.BaseURL() != "" || v.ClientID() != "" {
		t.Fatal("a missing role has no address")
	}
	if _, err := c.Metadata(ctx); !errors.Is(err, ErrNoCertify) {
		t.Fatalf("Metadata error = %v", err)
	}
	if _, err := c.Stage(ctx, "x", nil); !errors.Is(err, ErrNoCertify) {
		t.Fatalf("Stage error = %v", err)
	}
	if _, err := c.FetchOffer(ctx, "/x"); !errors.Is(err, ErrNoCertify) {
		t.Fatalf("FetchOffer error = %v", err)
	}
	if _, err := c.Redeem(ctx, "code"); !errors.Is(err, ErrNoCertify) {
		t.Fatalf("Redeem error = %v", err)
	}
	if _, _, err := c.RequestCredential(ctx, "t", CredentialRequest{}); !errors.Is(err, ErrNoCertify) {
		t.Fatalf("RequestCredential error = %v", err)
	}
	if _, err := v.CreateRequest(ctx, "", ""); !errors.Is(err, ErrNoVerify) {
		t.Fatalf("CreateRequest error = %v", err)
	}
	if _, err := v.Result(ctx, "x"); !errors.Is(err, ErrNoVerify) {
		t.Fatalf("Result error = %v", err)
	}
}

func TestNewCertifyFillsTheDefaultMetadataPath(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		mustWrite(t, w, []byte(`{"credential_issuer":"https://i.example"}`))
	}))
	defer srv.Close()
	c := NewCertify(newHTTP(srv), "")
	meta, err := c.Metadata(context.Background())
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if path != "/v1/certify/issuance/.well-known/openid-credential-issuer" {
		t.Fatalf("path = %q", path)
	}
	if meta.CredentialIssuer != "https://i.example" || len(meta.Raw) == 0 {
		t.Fatalf("metadata = %+v", meta)
	}
	if c.BaseURL() != srv.URL {
		t.Fatalf("base URL = %q", c.BaseURL())
	}
}

func TestMetadataReportsABrokenDocument(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte("not json"))
	}))
	defer srv.Close()
	if _, err := NewCertify(newHTTP(srv), "/m").Metadata(context.Background()); err == nil {
		t.Fatal("Metadata accepted a broken document")
	}
}

func TestStageReportsAnErrorListAndAnEmptyAnswer(t *testing.T) {
	body := `{"errors":[{"errorCode":"invalid_request","errorMessage":"unknown claim"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte(body))
	}))
	defer srv.Close()
	c := NewCertify(newHTTP(srv), "/m")
	_, err := c.Stage(context.Background(), "x", map[string]any{"a": "b"})
	if err == nil || !strings.Contains(err.Error(), "invalid_request") {
		t.Fatalf("error = %v", err)
	}
	body = `{"credential_offer_uri":""}`
	if _, serr := c.Stage(context.Background(), "x", nil); serr == nil {
		t.Fatal("Stage accepted an empty offer URI")
	}
	body = `{"credential_offer_uri":"openid-credential-offer://x"}`
	got, err := c.Stage(context.Background(), "x", nil)
	if err != nil || got != "openid-credential-offer://x" {
		t.Fatalf("Stage = %q, %v", got, err)
	}
}

func TestStageReportsAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	if _, err := NewCertify(newHTTP(srv), "/m").Stage(context.Background(), "x", nil); err == nil {
		t.Fatal("Stage accepted a failure")
	}
}

func TestOfferDocumentURLKeepsThePathAndDropsTheHost(t *testing.T) {
	cases := map[string]string{
		"openid-credential-offer://host?credential_offer_uri=https%3A%2F%2Fpublic.example%2Foffer%2F1": "/offer/1",
		"https://public.example/offer/2?x=1": "/offer/2?x=1",
		"/offer/3":                           "/offer/3",
	}
	for in, want := range cases {
		got, err := OfferDocumentURL(in)
		if err != nil || got != want {
			t.Fatalf("OfferDocumentURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := OfferDocumentURL("  "); err == nil {
		t.Fatal("an empty offer URI was accepted")
	}
}

func TestFetchOfferNeedsThePreAuthorizedGrant(t *testing.T) {
	body := `{"credential_issuer":"https://i.example","grants":{}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte(body))
	}))
	defer srv.Close()
	c := NewCertify(newHTTP(srv), "/m")
	if _, err := c.FetchOffer(context.Background(), "/offer/1"); err == nil {
		t.Fatal("FetchOffer accepted an offer without the grant")
	}
	body = `{"credential_issuer":"https://i.example","grants":{"` + PreAuthGrant +
		`":{"pre-authorized_code":"code-1"}}}`
	offer, err := c.FetchOffer(context.Background(), "/offer/1")
	if err != nil {
		t.Fatalf("FetchOffer: %v", err)
	}
	if offer.PreAuthorizedCode() != "code-1" {
		t.Fatalf("code = %q", offer.PreAuthorizedCode())
	}
}

func TestFetchOfferReportsAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := NewCertify(newHTTP(srv), "/m").FetchOffer(context.Background(), "/o"); err == nil {
		t.Fatal("FetchOffer accepted a failure")
	}
}

func TestRedeemSendsTheGrantAsAForm(t *testing.T) {
	var gotType, gotBody string
	body := `{"access_token":"at","c_nonce":"n1"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		raw, rerr := io.ReadAll(r.Body)
		if rerr != nil {
			t.Errorf("the read failed: %v", rerr)
		}
		gotBody = string(raw)
		mustWrite(t, w, []byte(body))
	}))
	defer srv.Close()
	c := NewCertify(newHTTP(srv), "/m")
	token, err := c.Redeem(context.Background(), "code-1")
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if token.AccessToken != "at" || token.CNonce != "n1" {
		t.Fatalf("token = %+v", token)
	}
	if gotType != "application/x-www-form-urlencoded" {
		t.Fatalf("content type = %q", gotType)
	}
	if !strings.Contains(gotBody, "pre-authorized_code=code-1") {
		t.Fatalf("body = %q", gotBody)
	}
	if !strings.Contains(gotBody, "grant_type=urn") {
		t.Fatalf("body %q has no grant type", gotBody)
	}
	body = `{"access_token":""}`
	if _, err := c.Redeem(context.Background(), "code-1"); err == nil {
		t.Fatal("Redeem accepted an empty access token")
	}
}

func TestRedeemReportsAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	if _, err := NewCertify(newHTTP(srv), "/m").Redeem(context.Background(), "c"); err == nil {
		t.Fatal("Redeem accepted a failure")
	}
}

func TestBuildCredentialRequestPerFormat(t *testing.T) {
	ldp := BuildCredentialRequest(Configuration{
		Format: "ldp_vc",
		CredentialDefinition: &CredentialDefinition{
			Type:    []string{"VerifiableCredential", "FarmerCredential"},
			Context: []string{"https://www.w3.org/ns/credentials/v2"},
		},
	}, "proof")
	if ldp.CredentialDefinition == nil || len(ldp.CredentialDefinition.Context) != 1 {
		t.Fatalf("a JSON-LD request must repeat the context: %+v", ldp)
	}
	if ldp.Vct != "" {
		t.Fatal("a JSON-LD request carries no vct")
	}
	sd := BuildCredentialRequest(Configuration{Format: "vc+sd-jwt", Vct: "https://v.example/vct"}, "proof")
	if sd.Vct != "https://v.example/vct" || sd.CredentialDefinition != nil {
		t.Fatalf("request = %+v", sd)
	}
	if sd.Proof.ProofType != "jwt" || sd.Proof.JWT != "proof" {
		t.Fatalf("proof = %+v", sd.Proof)
	}
	bare := BuildCredentialRequest(Configuration{Format: "ldp_vc"}, "proof")
	if bare.CredentialDefinition != nil {
		t.Fatal("a configuration without a definition adds none")
	}
}

func TestRequestCredentialUnwrapsBothShapes(t *testing.T) {
	body := `{"format":"ldp_vc","credential":{"type":["VerifiableCredential"]}}`
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		mustWrite(t, w, []byte(body))
	}))
	defer srv.Close()
	c := NewCertify(newHTTP(srv), "/m")
	raw, format, err := c.RequestCredential(context.Background(), "at", CredentialRequest{})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if format != "ldp_vc" || !strings.HasPrefix(string(raw), "{") {
		t.Fatalf("credential = %s format = %q", raw, format)
	}
	if gotAuth != "Bearer at" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	body = `{"format":"vc+sd-jwt","credential":"header.payload.sig~disclosure~"}`
	raw, _, err = c.RequestCredential(context.Background(), "at", CredentialRequest{})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if string(raw) != "header.payload.sig~disclosure~" {
		t.Fatalf("credential = %s, a compact token must lose its quotes", raw)
	}
	body = `{"format":"ldp_vc"}`
	if _, _, err := c.RequestCredential(context.Background(), "at", CredentialRequest{}); err == nil {
		t.Fatal("RequestCredential accepted an empty credential")
	}
	body = "not json"
	if _, _, err := c.RequestCredential(context.Background(), "at", CredentialRequest{}); err == nil {
		t.Fatal("RequestCredential accepted a broken answer")
	}
}

func TestRequestCredentialReportsAFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	_, _, err := NewCertify(newHTTP(srv), "/m").RequestCredential(context.Background(), "at", CredentialRequest{})
	if err == nil {
		t.Fatal("RequestCredential accepted a failure")
	}
}

func TestProofKeySignsTheHeaderInjiAccepts(t *testing.T) {
	key := NewProofKey()
	now := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	token, err := key.Sign("https://inji-certify.example.org", "nonce-1", now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token = %q", token)
	}
	header := decodePart(t, parts[0])
	if header["typ"] != ProofType || header["alg"] != "ES256" {
		t.Fatalf("header = %v", header)
	}
	if _, ok := header["kid"]; ok {
		t.Fatal("Inji rejects a header that names the key twice, so the proof carries no kid")
	}
	if header["jwk"] == nil {
		t.Fatal("the header carries no key")
	}
	claims := decodePart(t, parts[1])
	if claims["aud"] != "https://inji-certify.example.org" || claims["nonce"] != "nonce-1" {
		t.Fatalf("claims = %v", claims)
	}
	if _, ok := claims["iss"]; ok {
		t.Fatal("the pre-authorized flow has no named holder, so the proof carries no iss")
	}
	if mustAs[float64](t, claims["iat"]) != float64(now.Unix()) {
		t.Fatalf("iat = %v", claims["iat"])
	}
	if mustAs[float64](t, claims["exp"]) != float64(now.Add(ProofLife).Unix()) {
		t.Fatalf("exp = %v", claims["exp"])
	}
	// The signature is 64 bytes, which is the fixed size of ES256.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature = %d bytes, %v", len(sig), err)
	}
}

func TestProofKeySignsWithoutANonce(t *testing.T) {
	token, err := NewProofKey().Sign("https://i.example", "", time.Now())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims := decodePart(t, strings.Split(token, ".")[1])
	if _, ok := claims["nonce"]; ok {
		t.Fatal("a missing nonce must add no claim")
	}
}

func TestProofKeyNeedsAnAudience(t *testing.T) {
	if _, err := NewProofKey().Sign("  ", "n", time.Now()); err == nil {
		t.Fatal("Sign accepted an empty audience")
	}
}

func TestProofKeyKeepsOneKey(t *testing.T) {
	key := NewProofKey()
	first, err := key.JWK()
	if err != nil {
		t.Fatalf("JWK: %v", err)
	}
	again, err := key.JWK()
	if err != nil {
		t.Fatalf("JWK: %v", err)
	}
	if first["x"] != again["x"] {
		t.Fatal("the proof key changed between two calls")
	}
	if first["crv"] != "P-256" || first["kty"] != "EC" {
		t.Fatalf("jwk = %v", first)
	}
}

func TestProofKeyReportsAFailedKey(t *testing.T) {
	key := &ProofKey{generate: func() (*ecdsa.PrivateKey, error) { return nil, errors.New("no entropy") }}
	if _, err := key.JWK(); err == nil {
		t.Fatal("JWK accepted a failed key")
	}
	if _, err := key.Sign("https://i.example", "", time.Now()); err == nil {
		t.Fatal("Sign accepted a failed key")
	}
}

// decodePart reads one base64url part of a token.
func decodePart(t *testing.T, part string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("read: %v", err)
	}
	return out
}

func TestKeyIDReadsBothCredentialShapes(t *testing.T) {
	linked := []byte(`{"proof":{"verificationMethod":"did:web:i.example#key-0"}}`)
	if got := KeyID(linked); got != "did:web:i.example#key-0" {
		t.Fatalf("KeyID = %q", got)
	}
	many := []byte(`{"proof":[{"type":"x"},{"verificationMethod":"did:web:i.example#key-1"}]}`)
	if got := KeyID(many); got != "did:web:i.example#key-1" {
		t.Fatalf("KeyID = %q", got)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"did:web:i.example#key-2"}`))
	token := []byte(header + ".payload.sig~disclosure~")
	if got := KeyID(token); got != "did:web:i.example#key-2" {
		t.Fatalf("KeyID = %q", got)
	}
}

func TestKeyIDOfAnUnreadableCredential(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("plain text"),
		[]byte(`{"proof":{}}`),
		[]byte(`{"proof":"a string"}`),
		[]byte("!!!.payload.sig"),
		[]byte(base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".p.s"),
	}
	for i, in := range cases {
		if got := KeyID(in); got != "" {
			t.Fatalf("case %d: KeyID = %q, want an empty value", i, got)
		}
	}
}
