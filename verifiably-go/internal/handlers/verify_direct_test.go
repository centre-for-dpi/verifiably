package handlers

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/metrics"
	"github.com/verifiably/verifiably-go/vctypes"
)

// verifyDirectAdapter returns a fixed verdict from VerifyDirect. It embeds a nil
// backend.Adapter so any method the handler calls unexpectedly panics with a
// clear trace rather than silently returning a zero value.
type verifyDirectAdapter struct {
	backend.Adapter
	res backend.VerificationResult
}

func (a verifyDirectAdapter) VerifyDirect(context.Context, backend.DirectVerifyRequest) (backend.VerificationResult, error) {
	return a.res, nil
}

// The delegation gate resolves credential type names against the schema
// catalog so its prose reads "Cedula has expired" rather than the wire type.
// An empty catalog is a valid state (the fallback is the wire type), which is
// what this fake models.
func (a verifyDirectAdapter) ListAllSchemas(context.Context) ([]vctypes.Schema, error) {
	return nil, nil
}

func verifyFragmentTemplates(t *testing.T) *template.Template {
	t.Helper()
	tmpl := template.New("").Funcs(template.FuncMap{
		"list": func(args ...any) []any { return args },
		"t":    func(s string, _ ...any) string { return s },
	})
	// Only the fragment the handler renders; its content is irrelevant to the
	// assertion, which is about the counter rather than the markup.
	tmpl = template.Must(tmpl.New("fragment_verify_result").Parse(`<div>{{.Valid}}</div>`))
	return tmpl
}

// counterValue reads verification_completed_total for a given status label out
// of the rendered Prometheus exposition.
func counterValue(t *testing.T, dpg, status string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if !strings.HasPrefix(line, "verification_completed_total{") {
			continue
		}
		if !strings.Contains(line, `dpg="`+dpg+`"`) || !strings.Contains(line, `status="`+status+`"`) {
			continue
		}
		if f := strings.Fields(line); len(f) == 2 {
			return f[1]
		}
	}
	return "0"
}

// sessionWith creates a session on h and returns the cookies that address it.
// Without carrying them onto the subsequent request the handler would mint a
// fresh session with an empty VerifierDpg, and the counter would be emitted
// under dpg="" — which is exactly the kind of silent mismatch these tests
// exist to catch elsewhere.
func sessionWith(t *testing.T, h *H, verifierDpg string) []*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	sess := h.Sessions.MustGet(rec, httptest.NewRequest("GET", "/", nil))
	sess.VerifierDpg = verifierDpg
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("session store issued no cookie")
	}
	return cookies
}

func postVerifyDirect(t *testing.T, h *H, cookies []*http.Cookie, credential string) {
	t.Helper()
	form := url.Values{"method": {"paste"}, "credential_data": {credential}}
	req := httptest.NewRequest("POST", "/verifier/verify/direct", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	h.VerifyDirect(httptest.NewRecorder(), req)
}

// Regression test for the direct-verify counter.
//
// VerifyDirect used to emit verification_completed_total BEFORE running
// attachDelegationVerdict, which applies the temporal and revocation gates and
// can set res.Valid = false. A credential the gates rejected was therefore
// counted as status="ok", and the `directStatus = "error"` assignment meant to
// correct it sat below the already-emitted counter doing nothing — ineffassign
// flagged it, which is how the bug surfaced.
//
// The counter now runs after the gates. This drives the real handler with an
// adapter verdict that is Valid on its face but carries an expired credential,
// and asserts on the scraped counter rather than any intermediate variable, so
// a re-ordering regression cannot pass.
func TestVerifyDirect_ExpiredCredentialIsCountedAsError(t *testing.T) {
	const dpg = "test-expired-dpg"
	expired := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)

	h := &H{
		Sessions:  NewStore(),
		Templates: verifyFragmentTemplates(t),
		Adapter: verifyDirectAdapter{res: backend.VerificationResult{
			// The DPG says it verified: signature good, issuer known.
			Valid: true,
			Credentials: []backend.NormalizedCredential{{
				Types:  []string{"CedulaCredential"},
				Format: "w3c_vcdm_2",
				Claims: map[string]string{"validUntil": expired},
				Raw:    map[string]any{"validUntil": expired},
			}},
		}},
	}
	cookies := sessionWith(t, h, dpg)

	before := counterValue(t, dpg, "error")
	postVerifyDirect(t, h, cookies, "eyJhbGciOiJFUzI1NiJ9.e30.sig")
	after := counterValue(t, dpg, "error")

	if before == after {
		t.Errorf("verification_completed_total{status=\"error\"} did not move (%s -> %s): "+
			"a credential the temporal gate rejected must not be counted as ok", before, after)
	}
	if ok := counterValue(t, dpg, "ok"); ok != "0" {
		t.Errorf("status=\"ok\" was counted (%s) for a credential the gates rejected", ok)
	}
}

// The happy path still counts as ok, so the fix did not simply invert the
// label.
func TestVerifyDirect_ValidCredentialIsCountedAsOK(t *testing.T) {
	const dpg = "test-valid-dpg"

	h := &H{
		Sessions:  NewStore(),
		Templates: verifyFragmentTemplates(t),
		Adapter: verifyDirectAdapter{res: backend.VerificationResult{
			Valid: true,
			Credentials: []backend.NormalizedCredential{{
				Types:  []string{"CedulaCredential"},
				Format: "w3c_vcdm_2",
				Claims: map[string]string{},
				Raw:    map[string]any{},
			}},
		}},
	}
	cookies := sessionWith(t, h, dpg)

	postVerifyDirect(t, h, cookies, "eyJhbGciOiJFUzI1NiJ9.e30.sig")

	if got := counterValue(t, dpg, "ok"); got == "0" {
		t.Error("a credential that passes every gate must be counted as ok")
	}
}

// An empty paste is rejected before the adapter is called at all, so no
// verification is counted either way.
func TestVerifyDirect_EmptyPasteIsRejectedEarly(t *testing.T) {
	h := &H{
		Sessions:  NewStore(),
		Templates: verifyFragmentTemplates(t),
		Adapter:   verifyDirectAdapter{}, // VerifyDirect would return a zero verdict
	}
	form := url.Values{"method": {"paste"}, "credential_data": {"   "}}
	req := httptest.NewRequest("POST", "/verifier/verify/direct", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	h.VerifyDirect(rec, req)

	if !strings.Contains(rec.Body.String(), "Paste a credential first") {
		t.Errorf("expected the empty-paste toast, got: %s", rec.Body.String())
	}
}
