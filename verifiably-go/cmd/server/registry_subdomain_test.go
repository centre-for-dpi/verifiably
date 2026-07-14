package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPurposeSubdomainRootRedirect verifies that only the bare root of each
// purpose-named host is redirected to its surface; every other host and every
// non-root path (incl. /admin/login, which the admin-gated surfaces depend on)
// passes straight through.
func TestPurposeSubdomainRootRedirect(t *testing.T) {
	const passthrough = "PASSTHROUGH"
	h := purposeSubdomainRootRedirect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(passthrough))
	}))

	cases := []struct {
		name     string
		host     string
		path     string
		wantLoc  string // "" => expect passthrough
	}{
		{"identity-registry root redirects", "identity.registry.in-labs.cdpi.dev", "/", "/registrar/identities"},
		{"identity-registry root with port redirects", "identity.registry.in-labs.cdpi.dev:443", "/", "/registrar/identities"},
		{"esignet-config root redirects", "esignet-config.in-labs.cdpi.dev", "/", "/admin/esignet"},
		{"esignet-config root with port redirects", "esignet-config.in-labs.cdpi.dev:8443", "/", "/admin/esignet"},
		{"identity-registry admin login passes through", "identity.registry.in-labs.cdpi.dev", "/admin/login", ""},
		{"esignet-config admin login passes through", "esignet-config.in-labs.cdpi.dev", "/admin/login", ""},
		{"identity-registry registrar path passes through", "identity.registry.in-labs.cdpi.dev", "/registrar/identities", ""},
		{"esignet-config config path passes through", "esignet-config.in-labs.cdpi.dev", "/admin/esignet", ""},
		{"main host root passes through", "verifiably.in-labs.cdpi.dev", "/", ""},
		{"admin host root passes through", "admin.registry.in-labs.cdpi.dev", "/", ""},
		{"identity lookalike host does not redirect", "identity-registry.in-labs.cdpi.dev", "/", ""},
		{"esignet product host does not redirect", "esignet.in-labs.cdpi.dev", "/", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example"+tc.path, nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if tc.wantLoc != "" {
				if rec.Code != http.StatusFound {
					t.Fatalf("host=%s path=%s: got status %d, want %d", tc.host, tc.path, rec.Code, http.StatusFound)
				}
				if loc := rec.Header().Get("Location"); loc != tc.wantLoc {
					t.Fatalf("host=%s path=%s: got Location %q, want %q", tc.host, tc.path, loc, tc.wantLoc)
				}
				return
			}
			if rec.Code != http.StatusOK || rec.Body.String() != passthrough {
				t.Fatalf("host=%s path=%s: got status %d body %q, want passthrough", tc.host, tc.path, rec.Code, rec.Body.String())
			}
		})
	}
}
