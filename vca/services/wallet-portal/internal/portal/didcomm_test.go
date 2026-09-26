// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// P6-C3: a DIDComm invitation that the holder pastes or scans gets a
// page that names it and points at a DIDComm wallet, not an error.

// invitationURI is an out of band invitation with a credential offer.
var invitationURI = "https://agent.registry.gov.test?oob=" + base64.RawURLEncoding.EncodeToString([]byte(
	`{"@type":"https://didcomm.org/out-of-band/1.1/invitation","label":"Ministry of Agriculture",`+
		`"requests~attach":[{"data":{"base64":"`+base64.StdEncoding.EncodeToString(
		[]byte(`{"@type":"https://didcomm.org/issue-credential/2.0/offer-credential"}`))+`"}}]}`))

// TestWalletDetectsOobInvitation is P6-C3 for the pages.
func TestWalletDetectsOobInvitation(t *testing.T) {
	h := setupShell(t, nil, holderDeployment())
	for _, path := range []string{"/wallet/claim/offer", "/wallet/scan"} {
		field := "offer"
		if path == "/wallet/scan" {
			field = "text"
		}
		rec := h.post(t, path, url.Values{field: {invitationURI}})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		page := rec.Body.String()
		a11ytest.AssertPage(t, page)
		for _, want := range []string{
			"DIDComm invitation", "Ministry of Agriculture", "credential offer", "DIDComm wallet",
			"<code>" + invitationURI + "</code>", `href="` + invitationURI + `"`, "Open in a wallet",
		} {
			if !strings.Contains(page, want) {
				t.Errorf("%s lacks %q", path, want)
			}
		}
		if strings.Contains(page, `aria-invalid="true"`) {
			t.Errorf("%s reads the invitation as a bad text", path)
		}
	}
	// The camera scanner gets the card as a fragment.
	form := url.Values{"payload": {invitationURI}}
	req := httptest.NewRequest(http.MethodPost, "/wallet/scan/read", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", h.guard.Token(citizen()))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Ministry of Agriculture") {
		t.Fatalf("scan read: %d %s", rec.Code, rec.Body.String())
	}
	a11ytest.AssertFragment(t, rec.Body.String())
}
