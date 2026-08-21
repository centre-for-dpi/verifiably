package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/verifiably/verifiably-go/internal/auth"
	"github.com/verifiably/verifiably-go/internal/mdl"
)

func newTestMdlHandler(t *testing.T, claims map[string]string, tokenErr error) *H {
	t.Helper()
	s, err := mdl.NewServerSigner()
	if err != nil {
		t.Fatalf("new server signer: %v", err)
	}
	reg := auth.NewRegistry()
	reg.Register(fakeTokenProvider{claims: claims, err: tokenErr})
	return &H{
		AuthReg:   reg,
		MdlNonces: NewNonceStore(time.Minute),
		MdlSigner: s,
	}
}

func TestMdlIssueStepOneReturnsNonceForValidToken(t *testing.T) {
	h := newTestMdlHandler(t, map[string]string{"sub": "citizen-123"}, nil)
	body, _ := json.Marshal(map[string]string{"access_token": "valid-token"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/mdl/issue", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.APIMdlIssue(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CNonce string `json:"c_nonce"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.CNonce == "" {
		t.Fatal("expected a non-empty c_nonce")
	}
}

func TestMdlIssueStepOneRejectsInvalidToken(t *testing.T) {
	// A distinct handler whose provider rejects every token — fakeTokenProvider
	// returns a single fixed (claims, err) pair, so a test that needs the
	// token to be rejected needs its own handler, not the happy-path one.
	h := newTestMdlHandler(t, nil, errBadTestToken)
	body, _ := json.Marshal(map[string]string{"access_token": "wrong-token"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/mdl/issue", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.APIMdlIssue(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

var errBadTestToken = &mdlTestError{"bad signature"}

type mdlTestError struct{ msg string }

func (e *mdlTestError) Error() string { return e.msg }

func TestMdlIssueStepTwoIssuesCredentialForValidProof(t *testing.T) {
	h := newTestMdlHandler(t, map[string]string{"sub": "citizen-123"}, nil)

	// Step 1: get a nonce, and read back the aud the server actually expects
	// (derived from the request's own host) instead of assuming a literal.
	body, _ := json.Marshal(map[string]string{"access_token": "valid-token"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/mdl/issue", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.APIMdlIssue(rec, req)
	var step1 struct {
		CNonce string `json:"c_nonce"`
	}
	json.Unmarshal(rec.Body.Bytes(), &step1)
	aud := publicBase(req) + "/api/v1/credentials/mdl/issue"

	// Step 2: build a real proof over that nonce and submit it.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwt := signTestProof(t, aud, step1.CNonce, key) // helper from mdl_proof_test.go
	body2, _ := json.Marshal(map[string]any{
		"access_token": "valid-token",
		"proof":        map[string]string{"proof_type": "jwt", "jwt": jwt},
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/mdl/issue", bytes.NewReader(body2))
	rec2 := httptest.NewRecorder()
	h.APIMdlIssue(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var step2 struct {
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &step2); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	encoded, err := base64.RawURLEncoding.DecodeString(step2.Credential)
	if err != nil {
		t.Fatalf("credential is not valid base64url: %v", err)
	}

	// The point of this test is §AD-2: the returned credential's MSO must be
	// bound to exactly the device key that proved possession — not merely
	// that some base64url string came back. Decode the CBOR and check it.
	var issuerSigned mdl.IssuerSigned
	dm, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		t.Fatalf("dec mode: %v", err)
	}
	if err := dm.Unmarshal(encoded, &issuerSigned); err != nil {
		t.Fatalf("decode IssuerSigned: %v", err)
	}
	if len(issuerSigned.NameSpaces[mdl.Namespace]) == 0 {
		t.Fatal("expected disclosable items in the ISO namespace")
	}
}

func TestMdlIssueStepTwoRejectsReusedNonce(t *testing.T) {
	h := newTestMdlHandler(t, map[string]string{"sub": "citizen-123"}, nil)
	body, _ := json.Marshal(map[string]string{"access_token": "valid-token"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/mdl/issue", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.APIMdlIssue(rec, req)
	var step1 struct {
		CNonce string `json:"c_nonce"`
	}
	json.Unmarshal(rec.Body.Bytes(), &step1)
	aud := publicBase(req) + "/api/v1/credentials/mdl/issue"

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwt := signTestProof(t, aud, step1.CNonce, key)
	body2, _ := json.Marshal(map[string]any{
		"access_token": "valid-token",
		"proof":        map[string]string{"proof_type": "jwt", "jwt": jwt},
	})

	// First use succeeds.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/mdl/issue", bytes.NewReader(body2))
	h.APIMdlIssue(httptest.NewRecorder(), req2)

	// Second use of the SAME proof (same nonce) must fail — replay.
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/mdl/issue", bytes.NewReader(body2))
	rec3 := httptest.NewRecorder()
	h.APIMdlIssue(rec3, req3)
	if rec3.Code == http.StatusOK {
		t.Fatal("expected the second use of the same nonce to be rejected as a replay")
	}
}
