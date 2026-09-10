package credebl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// authOK writes the signin response the adapter's token cache accepts.
func authOK(w http.ResponseWriter) {
	payload, _ := json.Marshal(map[string]any{"exp": int64(9999999999)})
	tok := "h." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]string{"access_token": tok},
	})
}

// bootstrapSrv authenticates successfully and then hands every other path to
// rest, so a test only has to describe the failure it wants.
func bootstrapSrv(t *testing.T, rest http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			authOK(w)
			return
		}
		rest(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// BootstrapOffers seeds the wallet's "paste example" helper at startup. The
// backend.Adapter contract requires it to degrade to an empty slice rather than
// an error: a DPG that is slow to come up must not take the whole app down with
// it. These two tests pin that contract, which is also why the two returns
// carry //nolint:nilerr.

func TestBootstrapOffers_UnreachableBackendDoesNotError(t *testing.T) {
	s := bootstrapSrv(t, func(w http.ResponseWriter, _ *http.Request) {
		// Schema listing fails — the state a DPG is in while still booting.
		w.WriteHeader(http.StatusBadGateway)
	})
	a := newTestAdapter(t, s.URL)

	offers, err := a.BootstrapOffers(context.Background())
	if err != nil {
		t.Fatalf("BootstrapOffers must not error when the backend is down: %v", err)
	}
	if len(offers) != 0 {
		t.Errorf("offers = %v, want none", offers)
	}
}

func TestBootstrapOffers_FailedIssuanceDoesNotError(t *testing.T) {
	s := bootstrapSrv(t, func(w http.ResponseWriter, r *http.Request) {
		// Templates list fine, so BootstrapOffers gets as far as issuing...
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"t1","name":"Cedula","format":"dc+sd-jwt",` +
				`"attributes":{"vct":"Cedula","attributes":[` +
				`{"key":"fullName","value_type":"string"}]}}]}`))
			return
		}
		// ...and the speculative issuance itself fails.
		w.WriteHeader(http.StatusInternalServerError)
	})
	a := newTestAdapter(t, s.URL)

	offers, err := a.BootstrapOffers(context.Background())
	if err != nil {
		t.Fatalf("BootstrapOffers must not error when issuance fails: %v", err)
	}
	if len(offers) != 0 {
		t.Errorf("offers = %v, want none", offers)
	}
}

// resolveTemplateID caches template ids in a sync.Map, which stores `any`. The
// value is read back through a comma-ok assertion so a wrong-typed entry is a
// cache miss rather than a panic in the middle of a bulk issuance run.

func TestResolveTemplateID_ReturnsCachedID(t *testing.T) {
	s := bootstrapSrv(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("resolveTemplateID must not call the backend on a cache hit")
		w.WriteHeader(http.StatusInternalServerError)
	})
	a := newTestAdapter(t, s.URL)
	a.customTemplates.Store("Cedula", "template-123")

	got, err := a.resolveTemplateID(context.Background(), vctypes.Schema{ID: "Cedula"})
	if err != nil {
		t.Fatalf("resolveTemplateID: %v", err)
	}
	if got != "template-123" {
		t.Errorf("resolveTemplateID = %q, want template-123", got)
	}
}

func TestResolveTemplateID_WrongTypedCacheEntryIsAMiss(t *testing.T) {
	var called bool
	s := bootstrapSrv(t, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusBadGateway)
	})
	a := newTestAdapter(t, s.URL)
	// Not a string: the comma-ok must treat this as absent and go to the
	// backend, rather than panicking on a bare type assertion.
	a.customTemplates.Store("Cedula", 42)

	_, err := a.resolveTemplateID(context.Background(), vctypes.Schema{ID: "Cedula"})
	if err == nil {
		t.Fatal("expected the backend error to surface on a cache miss")
	}
	if !called {
		t.Error("a wrong-typed cache entry must fall through to the backend")
	}
}

// The verifier's template dropdown is derived from the issuer's schema list. A
// CREDEBL instance that is unreachable yields an empty dropdown, not a 500 on
// the verifier page — the operator can still use direct verify. That is why the
// return carries //nolint:nilerr.
func TestListOID4VPTemplates_UnreachableBackendYieldsEmptyDropdown(t *testing.T) {
	s := bootstrapSrv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	a := newTestAdapter(t, s.URL)

	tmpl, err := a.ListOID4VPTemplates(context.Background())
	if err != nil {
		t.Fatalf("an unreachable backend must not fail the verifier page: %v", err)
	}
	if tmpl == nil {
		t.Error("must return an empty map, not nil — the template ranges over it")
	}
	if len(tmpl) != 0 {
		t.Errorf("templates = %v, want empty", tmpl)
	}
}
