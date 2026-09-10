package injicertify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// BootstrapOffers seeds the wallet's "paste example" helper at startup. Per the
// backend.Adapter contract it degrades to an empty slice rather than an error —
// a Certify instance still coming up must not block the whole app. That is why
// its early returns carry //nolint:nilerr, and these tests pin the behaviour so
// the annotation cannot quietly become a swallowed real error.

func newAdapterAgainst(t *testing.T, h http.HandlerFunc, mode Mode) *Adapter {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	a, err := New(Config{BaseURL: srv.URL, Mode: mode}, "Inji Certify · Pre-Auth")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestBootstrapOffers_UnreachableIssuerDoesNotError(t *testing.T) {
	a := newAdapterAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}, ModePreAuth)

	offers, err := a.BootstrapOffers(context.Background())
	if err != nil {
		t.Fatalf("BootstrapOffers must not error when the issuer is down: %v", err)
	}
	if len(offers) != 0 {
		t.Errorf("offers = %v, want none", offers)
	}
}

// An auth-code offer needs a live wallet to complete the eSignet round trip, so
// it is useless as a startup fixture. The adapter bails before issuing rather
// than minting an offer nothing can redeem.
func TestBootstrapOffers_AuthCodeModeIssuesNothing(t *testing.T) {
	var issued bool
	a := newAdapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			issued = true
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"credential_configurations_supported":{` +
			`"CedulaCredential":{"format":"vc+sd-jwt","vct":"Cedula"}}}`))
	}, ModeAuthCode)

	offers, err := a.BootstrapOffers(context.Background())
	if err != nil {
		t.Fatalf("BootstrapOffers: %v", err)
	}
	if len(offers) != 0 {
		t.Errorf("offers = %v, want none in auth-code mode", offers)
	}
	if issued {
		t.Error("auth-code mode must not attempt a speculative issuance")
	}
}
