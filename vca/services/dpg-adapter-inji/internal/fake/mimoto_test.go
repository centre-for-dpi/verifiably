// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
)

// mimotoCall sends one call to the fake Mimoto and returns the status
// and the body.
func mimotoCall(t *testing.T, f *fake.Server, method, path, cookie, body string, header ...string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, f.URL()+"/v1/mimoto"+path, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := f.Client().Do(req)
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
	return resp.StatusCode, raw
}

// TestFakeMimotoRefusesBadCalls checks the refusals of the fake Mimoto:
// a login without a trusted token, a call without the session, a change
// without the CSRF token, a bad PIN, a locked wallet, a PDF without its
// media type, and a bad presentation.
func TestFakeMimotoRefusesBadCalls(t *testing.T) {
	f := fake.New("../../testdata")
	defer f.Close()
	c := fake.MimotoCookie + "; XSRF-TOKEN=t"
	x := []string{"X-XSRF-TOKEN", "t"}
	const wallet = "/wallets/4f1c9a7e-2b8d-4d3a-9e61-7a2c5b0d8e13"
	checks := []struct {
		name, method, path, cookie, body string
		header                           []string
		want                             int
	}{
		{"no bearer", http.MethodPost, "/auth/google/token-login", "", "", nil, http.StatusUnauthorized},
		{"refused token", http.MethodPost, "/auth/google/token-login", "", "", []string{"Authorization", "Bearer " + fake.RefusedToken}, http.StatusUnauthorized},
		{"login", http.MethodPost, "/auth/google/token-login", "", "", []string{"Authorization", "Bearer t"}, http.StatusOK},
		{"no session", http.MethodGet, wallet + "/credentials", "", "", nil, http.StatusUnauthorized},
		{"no wallet yet", http.MethodGet, "/wallets", c, "", nil, http.StatusOK},
		{"no CSRF token", http.MethodPost, "/wallets", fake.MimotoCookie, `{"walletPin":"123456","confirmWalletPin":"123456"}`, nil, http.StatusForbidden},
		{"short PIN", http.MethodPost, "/wallets", c, `{"walletPin":"1","confirmWalletPin":"1"}`, x, http.StatusBadRequest},
		{"locked", http.MethodGet, wallet + "/credentials", c, "", nil, http.StatusBadRequest},
		{"wallet", http.MethodPost, "/wallets", c, `{"walletPin":"123456","confirmWalletPin":"123456"}`, x, http.StatusOK},
		{"second wallet", http.MethodPost, "/wallets", c, `{"walletPin":"123456","confirmWalletPin":"123456"}`, x, http.StatusBadRequest},
		{"wrong PIN", http.MethodPost, wallet + "/unlock", c, `{"walletPin":"654321"}`, x, http.StatusBadRequest},
		{"unlock", http.MethodPost, wallet + "/unlock", c, `{"walletPin":"123456"}`, x, http.StatusOK},
		{"PDF as JSON", http.MethodGet, wallet + "/credentials/c1", c, "", []string{"Accept", "application/json"}, http.StatusNotAcceptable},
		{"PDF", http.MethodGet, wallet + "/credentials/c1", c, "", []string{"Accept", "application/pdf"}, http.StatusOK},
		{"bad download", http.MethodPost, wallet + "/credentials", c, `{}`, x, http.StatusBadRequest},
		{"bare request", http.MethodPost, wallet + "/presentations", c, `{"authorizationRequestUrl":"https://x"}`, x, http.StatusBadRequest},
		{"empty selection", http.MethodPatch, wallet + "/presentations/p1", c, `{"selectedCredentials":[]}`, x, http.StatusBadRequest},
		{"list", http.MethodGet, wallet + "/credentials", c, "", nil, http.StatusOK},
		{"delete", http.MethodDelete, wallet + "/credentials/c9d27f40-6a1e-4b95-8f3c-2e7d1a5b9c04", c, "", x, http.StatusOK},
		{"request", http.MethodPost, wallet + "/presentations", c, `{"authorizationRequestUrl":"openid4vp://authorize?request_uri=x"}`, x, http.StatusOK},
		{"selection", http.MethodPatch, wallet + "/presentations/p1", c, `{"selectedCredentials":["c1"]}`, x, http.StatusOK},
		{"unknown call", http.MethodPut, wallet + "/credentials", c, "", x, http.StatusNotFound},
	}
	for _, tc := range checks {
		if got, body := mimotoCall(t, f, tc.method, tc.path, tc.cookie, tc.body, tc.header...); got != tc.want {
			t.Errorf("%s: status %d, want %d: %s", tc.name, got, tc.want, body)
		}
	}
	if f.MimotoLogins() != 1 || len(f.MimotoPresented()) != 1 || f.MimotoWalletsMade() != 1 || f.MimotoWalletPIN() != "123456" {
		t.Fatalf("logins %d, presented %v", f.MimotoLogins(), f.MimotoPresented())
	}
	if _, list := mimotoCall(t, f, http.MethodGet, wallet+"/credentials", c, ""); !bytes.Contains(list, []byte("National ID")) ||
		bytes.Contains(list, []byte("Farmer Credential")) {
		t.Fatalf("the list after the delete = %s", list)
	}
	f.ForgetMimotoSession()
	if got, _ := mimotoCall(t, f, http.MethodGet, wallet+"/credentials", c, ""); got != http.StatusUnauthorized {
		t.Fatalf("a forgotten session answered %d", got)
	}
}

// TestFakeMimotoLocksAfterFiveWrongPins follows the passcode rule of the
// release, and lists the wallet as locked.
func TestFakeMimotoLocksAfterFiveWrongPins(t *testing.T) {
	f := fake.New("../../testdata")
	defer f.Close()
	f.SeedMimotoWallet("135790")
	mimotoCall(t, f, http.MethodPost, "/auth/google/token-login", "", "", "Authorization", "Bearer t")
	c := fake.MimotoCookie + "; XSRF-TOKEN=t"
	const unlock = "/wallets/4f1c9a7e-2b8d-4d3a-9e61-7a2c5b0d8e13/unlock"
	want := []struct {
		status int
		code   string
	}{
		{http.StatusBadRequest, "invalid_pin"}, {http.StatusBadRequest, "invalid_pin"}, {http.StatusBadRequest, "invalid_pin"},
		{http.StatusBadRequest, "last_attempt_before_lockout"}, {http.StatusLocked, "temporarily_locked"},
		{http.StatusLocked, "temporarily_locked"},
	}
	for i, w := range want {
		pin := "000000"
		if i == len(want)-1 {
			pin = "135790"
		}
		got, body := mimotoCall(t, f, http.MethodPost, unlock, c, `{"walletPin":"`+pin+`"}`, "X-XSRF-TOKEN", "t")
		if got != w.status || !bytes.Contains(body, []byte(w.code)) {
			t.Fatalf("attempt %d: %d %s", i+1, got, body)
		}
	}
	if _, list := mimotoCall(t, f, http.MethodGet, "/wallets", c, ""); !bytes.Contains(list, []byte("temporarily_locked")) {
		t.Fatalf("the wallet list = %s", list)
	}
	if err := f.ClaimInInjiWeb("t", "135790"); err == nil {
		t.Fatal("a locked wallet took a claim")
	}
}

// TestFakeMimotoWithoutFixtures reports a missing recorded answer as a
// server error, and it presents nothing before a presentation.
func TestFakeMimotoWithoutFixtures(t *testing.T) {
	f := fake.New(t.TempDir())
	defer f.Close()
	if f.MimotoPresented() != nil {
		t.Fatal("the fake presented before a call")
	}
	mimotoCall(t, f, http.MethodPost, "/auth/google/token-login", "", "", "Authorization", "Bearer t")
	if got, _ := mimotoCall(t, f, http.MethodPost, "/wallets", fake.MimotoCookie+"; XSRF-TOKEN=t",
		`{"walletPin":"123456","confirmWalletPin":"123456"}`, "X-XSRF-TOKEN", "t"); got != http.StatusInternalServerError {
		t.Fatalf("a missing wallet answer gave %d", got)
	}
}

// TestFakeMimotoClaimAndLock covers the claim of Inji Web, a download
// that names no issuer, a PIN with a letter, the lost wallet key, and a
// deployment without the recorded answers, where a seed names no wallet.
func TestFakeMimotoClaimAndLock(t *testing.T) {
	f := fake.New("../../testdata")
	defer f.Close()
	if err := f.ClaimInInjiWeb("t", "135790"); err == nil {
		t.Fatal("a claim without a wallet passed")
	}
	if err := f.ClaimInInjiWeb(fake.RefusedToken, "135790"); err == nil {
		t.Fatal("a claim with a refused token passed")
	}
	f.SeedMimotoWallet("135790")
	if err := f.ClaimInInjiWeb("t", "135790"); err != nil {
		t.Fatalf("the claim: %v", err)
	}
	c := "SESSION=mimoto-session-2; XSRF-TOKEN=t"
	const base = "/wallets/4f1c9a7e-2b8d-4d3a-9e61-7a2c5b0d8e13"
	if got, list := mimotoCall(t, f, http.MethodGet, base+"/credentials", c, ""); got != http.StatusOK || !bytes.Contains(list, []byte("Inji Certify")) {
		t.Fatalf("the list after the claim: %d %s", got, list)
	}
	if got, _ := mimotoCall(t, f, http.MethodPost, base+"/credentials", c, `{"issuer":"InjiCertify"}`, "X-XSRF-TOKEN", "t"); got != http.StatusBadRequest {
		t.Fatalf("a download without a code: %d", got)
	}
	if got, _ := mimotoCall(t, f, http.MethodPost, base+"/unlock", c, `{"walletPin":"13579a"}`, "X-XSRF-TOKEN", "t"); got != http.StatusBadRequest {
		t.Fatalf("a PIN with a letter: %d", got)
	}
	f.LockMimotoSessions()
	if got, body := mimotoCall(t, f, http.MethodGet, base+"/credentials", c, ""); got != http.StatusBadRequest || !bytes.Contains(body, []byte("wallet_locked")) {
		t.Fatalf("a session without the key: %d %s", got, body)
	}

	empty := fake.New(t.TempDir())
	defer empty.Close()
	empty.SeedMimotoWallet("135790")
	if empty.MimotoWalletPIN() != "135790" {
		t.Fatal("the seed lost its PIN")
	}
	mimotoCall(t, empty, http.MethodPost, "/auth/google/token-login", "", "", "Authorization", "Bearer t")
	cc := fake.MimotoCookie + "; XSRF-TOKEN=t"
	for _, call := range []struct{ method, path, body string }{
		{http.MethodPost, "/wallets//unlock", `{"walletPin":"000000"}`},
	} {
		if got, _ := mimotoCall(t, empty, call.method, call.path, cc, call.body, "X-XSRF-TOKEN", "t"); got == http.StatusOK {
			t.Errorf("%s %s without the recorded answers passed", call.method, call.path)
		}
	}
}
