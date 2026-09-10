package waltid

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/httpx"
	"github.com/verifiably/verifiably-go/vctypes"
)

func adapterAgainst(t *testing.T, h http.HandlerFunc) *Adapter {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	a, err := New(Config{
		IssuerBaseURL:   srv.URL,
		VerifierBaseURL: srv.URL,
		WalletBaseURL:   srv.URL,
		StandardVersion: "draft13",
	}, "Walt Community Stack")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.issuer = httpx.New(srv.URL)
	return a
}

// BootstrapOffers must degrade to an empty slice rather than an error: it runs
// once at startup, and a walt.id stack that is still coming up must not take
// the app down with it. Both early returns carry //nolint:nilerr, and these
// tests are what stop that annotation hiding a genuine swallowed error later.

func TestBootstrapOffers_UnreachableIssuerDoesNotError(t *testing.T) {
	a := adapterAgainst(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	offers, err := a.BootstrapOffers(context.Background())
	if err != nil {
		t.Fatalf("BootstrapOffers must not error when the issuer is down: %v", err)
	}
	if len(offers) != 0 {
		t.Errorf("offers = %v, want none", offers)
	}
}

func TestBootstrapOffers_FailedIssuanceDoesNotError(t *testing.T) {
	a := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		// Metadata resolves, so BootstrapOffers finds a schema to try...
		if strings.Contains(r.URL.Path, ".well-known") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"credential_configurations_supported":{` +
				`"UniversityDegree_jwt_vc_json":{"format":"jwt_vc_json",` +
				`"credential_definition":{"type":["VerifiableCredential","UniversityDegree"]}}}}`))
			return
		}
		// ...and the issue call itself fails.
		w.WriteHeader(http.StatusInternalServerError)
	})

	offers, err := a.BootstrapOffers(context.Background())
	if err != nil {
		t.Fatalf("BootstrapOffers must not error when issuance fails: %v", err)
	}
	if len(offers) != 0 {
		t.Errorf("offers = %v, want none", offers)
	}
}

// friendlyClaimError turns walt.id's wallet 400 bodies into something an
// operator who does not read Kotlin can act on. The empty-offer case is the one
// that actually happens in this stack — Inji Certify advertises a
// credential_issuer URL whose .well-known lives somewhere else, so walt.id
// resolves no credentials and 400s on the claim.
func TestFriendlyClaimError_EmptyOfferedCredentials(t *testing.T) {
	err := friendlyClaimError(errors.New("Resolved an empty list of offered credentials"), "")
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, want := range []string{"well-known", "credential_issuer", "Inji Web Wallet"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message should mention %q so the operator knows what to do; got: %s", want, msg)
		}
	}
	// ST1005: an error string is a fragment, not a sentence.
	if strings.HasSuffix(msg, ".") || strings.HasSuffix(msg, "\n") {
		t.Errorf("error string must not end in punctuation: %q", msg)
	}
}

func TestFriendlyClaimError_UnrecognisedBodyIsTruncated(t *testing.T) {
	err := friendlyClaimError(errors.New(strings.Repeat("x", 500)), "")
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(err.Error()) > 300 {
		t.Errorf("an unrecognised wallet body must be truncated, got %d chars", len(err.Error()))
	}
}

// An offer the wallet cannot resolve is wrapped in ErrOfferUnresolvable so the
// handler layer can branch on the typed error rather than string-matching. The
// wrap must survive errors.Is.
func TestParseOffer_UnresolvableIsTyped(t *testing.T) {
	a := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/auth/login"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"t0k3n"}`))
		case strings.HasSuffix(r.URL.Path, "/accounts/wallets"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"wallets":[{"id":"w1"}]}`))
		default:
			// The resolve call itself rejects the offer, which is the path
			// that must produce a typed error.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("unknown issuer"))
		}
	})

	_, err := a.ParseOffer(context.Background(), "openid-credential-offer://x?credential_offer_uri=http://127.0.0.1:1/nope")
	if err == nil {
		t.Fatal("expected an error for an unresolvable offer")
	}
	if !errors.Is(err, backend.ErrOfferUnresolvable) {
		t.Errorf("error must wrap ErrOfferUnresolvable so handlers can branch on it; got %v", err)
	}
}

// After a successful claim the adapter re-lists the wallet to back-fill the
// credential's real subject fields, because walt.id's useOfferRequest response
// does not echo the stored credential id. That re-list is best-effort: the
// claim has already succeeded, so failing it here would tell the holder their
// credential was rejected when it is sitting in their wallet. Hence the
// //nolint:nilerr — and hence this test, which stops that annotation from ever
// covering a real error.
func TestClaimCredential_BackfillFailureKeepsTheClaim(t *testing.T) {
	var claimed bool
	a := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/auth/login"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"t0k3n"}`))
		case strings.HasSuffix(r.URL.Path, "/accounts/wallets"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"wallets":[{"id":"w1"}]}`))
		case strings.Contains(r.URL.Path, "/exchange/useOfferRequest"):
			claimed = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			// The wallet re-list fails — the back-fill cannot happen.
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	cred, err := a.ClaimCredential(context.Background(), vctypes.Credential{
		ID:     "pending-1",
		Fields: map[string]string{"offer_uri": "openid-credential-offer://x", "config_id": "Cedula"},
	})
	if err != nil {
		t.Fatalf("a failed back-fill must not fail the claim: %v", err)
	}
	if !claimed {
		t.Fatal("the claim call was never made")
	}
	if cred.Status != "accepted" {
		t.Errorf("Status = %q, want accepted — the credential IS in the wallet", cred.Status)
	}
}
