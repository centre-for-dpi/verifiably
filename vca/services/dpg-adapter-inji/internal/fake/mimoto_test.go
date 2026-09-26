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
// a login without a trusted token, a call without the session, a bad
// PIN, a locked wallet, a PDF without its media type, and a bad
// presentation.
func TestFakeMimotoRefusesBadCalls(t *testing.T) {
	f := fake.New("../../testdata")
	defer f.Close()
	c := fake.MimotoCookie
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
		{"short PIN", http.MethodPost, "/wallets", c, `{"walletPin":"1","confirmWalletPin":"1"}`, nil, http.StatusBadRequest},
		{"locked", http.MethodGet, wallet + "/credentials", c, "", nil, http.StatusBadRequest},
		{"wallet", http.MethodPost, "/wallets", c, `{"walletPin":"123456","confirmWalletPin":"123456"}`, nil, http.StatusOK},
		{"wrong PIN", http.MethodPost, wallet + "/unlock", c, `{"walletPin":"654321"}`, nil, http.StatusBadRequest},
		{"unlock", http.MethodPost, wallet + "/unlock", c, `{"walletPin":"123456"}`, nil, http.StatusOK},
		{"PDF as JSON", http.MethodGet, wallet + "/credentials/c1", c, "", []string{"Accept", "application/json"}, http.StatusNotAcceptable},
		{"PDF", http.MethodGet, wallet + "/credentials/c1", c, "", []string{"Accept", "application/pdf"}, http.StatusOK},
		{"bare request", http.MethodPost, wallet + "/presentations", c, `{"authorizationRequestUrl":"https://x"}`, nil, http.StatusBadRequest},
		{"empty selection", http.MethodPatch, wallet + "/presentations/p1", c, `{"selectedCredentials":[]}`, nil, http.StatusBadRequest},
		{"list", http.MethodGet, wallet + "/credentials", c, "", nil, http.StatusOK},
		{"delete", http.MethodDelete, wallet + "/credentials/c9d27f40-6a1e-4b95-8f3c-2e7d1a5b9c04", c, "", nil, http.StatusOK},
		{"request", http.MethodPost, wallet + "/presentations", c, `{"authorizationRequestUrl":"openid4vp://authorize?request_uri=x"}`, nil, http.StatusOK},
		{"selection", http.MethodPatch, wallet + "/presentations/p1", c, `{"selectedCredentials":["c1"]}`, nil, http.StatusOK},
		{"unknown call", http.MethodPut, wallet + "/credentials", c, "", nil, http.StatusNotFound},
	}
	for _, tc := range checks {
		if got, body := mimotoCall(t, f, tc.method, tc.path, tc.cookie, tc.body, tc.header...); got != tc.want {
			t.Errorf("%s: status %d, want %d: %s", tc.name, got, tc.want, body)
		}
	}
	if f.MimotoLogins() != 1 || len(f.MimotoPresented()) != 1 {
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

// TestFakeMimotoWithoutFixtures reports a missing recorded answer as a
// server error, and it presents nothing before a presentation.
func TestFakeMimotoWithoutFixtures(t *testing.T) {
	f := fake.New(t.TempDir())
	defer f.Close()
	if f.MimotoPresented() != nil {
		t.Fatal("the fake presented before a call")
	}
	mimotoCall(t, f, http.MethodPost, "/auth/google/token-login", "", "", "Authorization", "Bearer t")
	if got, _ := mimotoCall(t, f, http.MethodPost, "/wallets", fake.MimotoCookie,
		`{"walletPin":"123456","confirmWalletPin":"123456"}`); got != http.StatusInternalServerError {
		t.Fatalf("a missing wallet answer gave %d", got)
	}
}
