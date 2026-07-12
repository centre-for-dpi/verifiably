package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIdentityRegistryRootRedirect verifies that only the bare root of the
// identity.registry.<domain> host is redirected to the national ID registry;
// every other host and every non-root path (incl. /admin/login, which the
// admin-gated registrar view depends on) passes straight through.
func TestIdentityRegistryRootRedirect(t *testing.T) {
	const passthrough = "PASSTHROUGH"
	h := identityRegistryRootRedirect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(passthrough))
	}))

	cases := []struct {
		name         string
		host         string
		path         string
		wantRedirect bool
	}{
		{"identity-registry root redirects", "identity.registry.in-labs.cdpi.dev", "/", true},
		{"identity-registry root with port redirects", "identity.registry.in-labs.cdpi.dev:443", "/", true},
		{"identity-registry admin login passes through", "identity.registry.in-labs.cdpi.dev", "/admin/login", false},
		{"identity-registry registrar path passes through", "identity.registry.in-labs.cdpi.dev", "/registrar/identities", false},
		{"main host root passes through", "verifiably.in-labs.cdpi.dev", "/", false},
		{"admin host root passes through", "admin.registry.in-labs.cdpi.dev", "/", false},
		{"lookalike host does not redirect", "identity-registry.in-labs.cdpi.dev", "/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example"+tc.path, nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if tc.wantRedirect {
				if rec.Code != http.StatusFound {
					t.Fatalf("host=%s path=%s: got status %d, want %d", tc.host, tc.path, rec.Code, http.StatusFound)
				}
				if loc := rec.Header().Get("Location"); loc != "/registrar/identities" {
					t.Fatalf("host=%s path=%s: got Location %q, want /registrar/identities", tc.host, tc.path, loc)
				}
				return
			}
			if rec.Code != http.StatusOK || rec.Body.String() != passthrough {
				t.Fatalf("host=%s path=%s: got status %d body %q, want passthrough", tc.host, tc.path, rec.Code, rec.Body.String())
			}
		})
	}
}
