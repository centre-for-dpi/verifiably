package waltid

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/internal/delegation"
)

// fakeJWT wraps a claims map as a compact JWS with dummy header/signature — the
// normalizer only base64url-decodes the payload (signatures are the host's job).
func fakeJWT(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

func TestNormalize_VPJWT_DelegationPair_EndToEnd(t *testing.T) {
	birthCert := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential", "BirthCertificate"},
		"issuer":   "did:web:registry",
		"credentialSubject": map[string]any{
			"id":         "did:example:child",
			"subjectRef": "urn:person:child-1",
			"givenName":  "Maria",
		},
	}
	delegationVC := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential", "DelegatedAccessCredential"},
		"issuer":   "did:web:registry",
		"credentialSubject": map[string]any{
			"id":         "did:example:parent",
			"onBehalfOf": map[string]any{"id": "urn:person:child-1"},
		},
		"termsOfUse": []any{map[string]any{
			"type":             "DelegationCapability",
			"controller":       "did:web:registry",
			"invocationTarget": "urn:person:child-1",
			"delegate":         "did:example:parent",
			"allowedAction":    []any{"present"},
			"caveat":           []any{map[string]any{"validUntil": "2033-03-10T00:00:00Z"}},
		}},
	}
	vpJWT := fakeJWT(map[string]any{
		"holder": "did:example:parent",
		"vp": map[string]any{
			"holder":               "did:example:parent",
			"verifiableCredential": []any{birthCert, delegationVC},
		},
	})
	raw, _ := json.Marshal(map[string]any{"vp_token": vpJWT})

	creds, holder := normalizePresentedCredentials(raw)
	if len(creds) != 2 {
		t.Fatalf("expected 2 normalized credentials, got %d", len(creds))
	}
	if holder == nil || holder.ID != "did:example:parent" || !holder.Confirmed {
		t.Fatalf("expected confirmed holder did:example:parent, got %+v", holder)
	}
	// VCDM2 format detected from @context.
	if creds[0].Format != "w3c_vcdm_2" {
		t.Errorf("expected w3c_vcdm_2 format, got %q", creds[0].Format)
	}

	// Full path: normalize -> evaluate -> authorized.
	got := delegation.Evaluate(context.Background(), creds, holder, delegation.Options{
		Now:             time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC),
		RequestedAction: "present",
		Status:          func(context.Context, delegation.StatusRef) (bool, error) { return false, nil },
		Trust:           func(context.Context, string, string) error { return nil },
		FailClosed:      true,
	})
	if !got.Authorized {
		t.Fatalf("expected authorized delegation from normalized walt.id VP, got %+v", got)
	}
}

func TestNormalize_SDJWT_SingleCredential(t *testing.T) {
	// issuer JWT payload with a delegation claim + a disclosed claim.
	issuerJWT := fakeJWT(map[string]any{
		"vct": "https://example/DelegationCredential",
		"iss": "did:web:registry",
		"sub": "did:example:parent",
		"delegation": map[string]any{
			"on_behalf_of": "urn:person:child-1",
			"valid_until":  "2033-03-10T00:00:00Z",
		},
		"status": map[string]any{"status_list": map[string]any{"uri": "https://r/sl/1", "idx": float64(7)}},
	})
	// one disclosure: ["salt","role","Mother"]
	disc := base64.RawURLEncoding.EncodeToString([]byte(`["salt","role","Mother"]`))
	raw, _ := json.Marshal(map[string]any{"vp_token": issuerJWT + "~" + disc + "~"})

	creds, _ := normalizePresentedCredentials(raw)
	if len(creds) != 1 {
		t.Fatalf("expected 1 SD-JWT credential, got %d", len(creds))
	}
	c := creds[0]
	if c.SubjectID != "did:example:parent" || c.Issuer != "did:web:registry" {
		t.Errorf("unexpected subject/issuer: %+v", c)
	}
	if c.Claims["role"] != "Mother" {
		t.Errorf("expected disclosed role=Mother, got %q", c.Claims["role"])
	}
	if _, ok := c.Raw["delegation"]; !ok {
		t.Errorf("expected delegation claim preserved in Raw, got %+v", c.Raw)
	}
}
