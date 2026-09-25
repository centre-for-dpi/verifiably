// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/fake"
)

const testdata = "../../testdata"

func TestFakeServesTheRecordedAnswers(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	cases := map[string]string{
		"/draft13/.well-known/openid-credential-issuer": "credential_configurations_supported",
		"/onboard/issuer":                                      "issuerDid",
		"/openid4vc/jwt/issue":                                 "openid-credential-offer://",
		"/openid4vc/verify":                                    "openid4vp://",
		"/openid4vc/session/x":                                 "9c0e2f1b",
		"/wallet-api/auth/login":                               "token",
		"/wallet-api/wallet/accounts/wallets":                  "wallets",
		"/wallet-api/wallet/w/credentials":                     "UniversityDegree",
		"/wallet-api/wallet/w/exchange/resolveCredentialOffer": "pre-authorized_code",
		"/wallet-api/wallet/w/exchange/usePresentationRequest": "redirectUri",
	}
	for path, want := range cases {
		body := get(t, f, path)
		if !strings.Contains(body, want) {
			t.Fatalf("%s returned %q, want a body with %q", path, body, want)
		}
	}
}

func TestFakeSwitchesToTheClaimedWalletAfterAnOffer(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	before := get(t, f, "/wallet-api/wallet/w/credentials")
	if strings.Contains(before, "8f4d1c62") {
		t.Fatal("the wallet holds the new credential too early")
	}
	post(t, f, "/wallet-api/wallet/w/exchange/useOfferRequest", "openid-credential-offer://x")
	after := get(t, f, "/wallet-api/wallet/w/credentials")
	if !strings.Contains(after, "8f4d1c62") {
		t.Fatal("the wallet did not gain the claimed credential")
	}
	if string(f.Request("/wallet-api/wallet/w/exchange/useOfferRequest")) != "openid-credential-offer://x" {
		t.Fatal("the fake did not record the request body")
	}
}

func TestFakeSwitchesTheVerifierSession(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	f.SetSession(fake.SessionAccepted)
	if !strings.Contains(get(t, f, "/openid4vc/session/x"), `"verificationResult": true`) {
		t.Fatal("the accepted session is missing")
	}
	f.SetSession(fake.SessionRejected)
	if !strings.Contains(get(t, f, "/openid4vc/session/x"), `"verificationResult": false`) {
		t.Fatal("the rejected session is missing")
	}
}

func TestFakeForcesAStatusAndClearsIt(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	f.SetStatus("/onboard/issuer", http.StatusTeapot)
	if code := status(t, f, "/onboard/issuer"); code != http.StatusTeapot {
		t.Fatalf("status = %d", code)
	}
	f.SetStatus("/onboard/issuer", 0)
	if code := status(t, f, "/onboard/issuer"); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
}

func TestFakeReportsAMissingRecording(t *testing.T) {
	f := fake.New("testdata-that-does-not-exist")
	defer f.Close()
	if code := status(t, f, "/onboard/issuer"); code != http.StatusInternalServerError {
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

func TestRequestJSONReadsTheRecordedBody(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	post(t, f, "/openid4vc/jwt/issue", `{"credentialConfigurationId":"x"}`)
	var body map[string]any
	if err := f.RequestJSON("/openid4vc/jwt/issue", &body); err != nil {
		t.Fatalf("RequestJSON: %v", err)
	}
	if body["credentialConfigurationId"] != "x" {
		t.Fatalf("body = %v", body)
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
		t.Fatalf("read %s: %v", path, verr)
	}
	return string(body)
}

func post(t *testing.T, f *fake.Server, path, body string) {
	t.Helper()
	resp, err := f.Client().Post(f.URL()+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	if cerr := resp.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
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

// postBody posts a JSON body and returns the status and the answer.
func postBody(t *testing.T, f *fake.Server, path, body string) (int, string) {
	t.Helper()
	resp, err := f.Client().Post(f.URL()+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	raw, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		t.Fatal(rerr)
	}
	return resp.StatusCode, string(raw)
}

// TestFakeOnboardFollowsTheRequest checks the onboarding answer: the key
// of the asked type, and a did:web of the asked host.
func TestFakeOnboardFollowsTheRequest(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	code, body := postBody(t, f, "/onboard/issuer", `{"key":{"backend":"jwk","keyType":"Ed25519"},"did":{"method":"key"}}`)
	if code != http.StatusOK || !strings.Contains(body, "did:key:z6Mk") {
		t.Fatalf("Ed25519 did:key: %d %s", code, body)
	}
	code, body = postBody(t, f, "/onboard/issuer", `{"key":{"backend":"jwk","keyType":"secp256r1"},"did":{"method":"web","config":{"domain":"localhost:18002","path":"/issuer"}}}`)
	if code != http.StatusOK || !strings.Contains(body, `"did:web:localhost%3A18002:issuer"`) || !strings.Contains(body, `"P-256"`) {
		t.Fatalf("did:web: %d %s", code, body)
	}
	if code, _ := postBody(t, f, "/onboard/issuer", `{`); code != http.StatusBadRequest {
		t.Fatalf("a broken body: %d", code)
	}
	missing := fake.New(t.TempDir())
	defer missing.Close()
	if code, _ := postBody(t, missing, "/onboard/issuer", `{"did":{"method":"web","config":{"domain":"a"}}}`); code != http.StatusInternalServerError {
		t.Fatalf("a missing recording: %d", code)
	}
}

func TestFakeServesVerifier2Sessions(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	code, body := postBody(t, f, "/verification-session/create", `{"flow_type":"cross_device"}`)
	if code != http.StatusOK || !strings.Contains(body, "bootstrapAuthorizationRequestUrl") {
		t.Fatalf("create = %d %q", code, body)
	}
	if f.LastPath() != "/verification-session/create" {
		t.Fatalf("last path = %q", f.LastPath())
	}
	for state, want := range map[fake.Session2State]string{
		fake.Session2Active:     `"ACTIVE"`,
		fake.Session2Successful: `"SUCCESSFUL"`,
		fake.Session2Failed:     `"FAILED"`,
		fake.Session2Expired:    `"EXPIRED"`,
	} {
		f.SetSession2(state)
		if got := get(t, f, "/verification-session/s/info"); !strings.Contains(got, want) {
			t.Errorf("%s: %q", state, got)
		}
	}
}
