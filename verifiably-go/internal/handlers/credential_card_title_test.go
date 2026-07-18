package handlers

import (
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// Naming a presented credential on a delegated-access card.
//
// The bug: these cards showed the raw slug ("custom-dk05t158qnou") while the
// picker beside them showed "Testa Card V2". Only delegated results were
// affected — a single-credential verify never builds these views, and its
// template branch prints the name remembered from the request it built.
// A combined presentation has one name per credential and no such
// carry-through, so each must be resolved from the credential itself.

func testSchemas() []vctypes.Schema {
	return []vctypes.Schema{
		{
			ID: "custom-dk05t158qnou", Name: "Testa Card V2", Std: "sd_jwt_vc (IETF)",
			Custom: true, AdditionalTypes: []string{"TestaCardV2"},
		},
		{
			ID: "custom-dk05yjxzjvmu", Name: "Testa Director Authority", Std: "sd_jwt_vc (IETF)",
			Custom: true, AdditionalTypes: []string{"TestaDirectorAuthority"},
		},
		{
			ID: "custom-dk05qef8tfs1", Name: "Testa Card V1", Std: "w3c_vcdm_2",
			Custom: true, AdditionalTypes: []string{"TestaCardV1"},
		},
	}
}

func TestCredentialCardTitle_ResolvesIssuerGivenName(t *testing.T) {
	t.Setenv("VERIFIABLY_PUBLIC_URL", "https://verifiably.bootcamp.cdpi.dev")
	schemas := testSchemas()

	for _, tc := range []struct {
		name  string
		types []string
		want  string
	}{
		{
			// SD-JWT: the presented type IS the vct, whose tail is the schema id.
			"sd-jwt vct url",
			[]string{"https://verifiably.bootcamp.cdpi.dev/credentials/custom-dk05t158qnou"},
			"Testa Card V2",
		},
		{
			"sd-jwt vct url, delegation",
			[]string{"https://verifiably.bootcamp.cdpi.dev/credentials/custom-dk05yjxzjvmu"},
			"Testa Director Authority",
		},
		{
			// W3C: the meaningful type is the custom type name; the generic
			// VerifiableCredential must be skipped.
			"w3c type array",
			[]string{"VerifiableCredential", "TestaCardV1"},
			"Testa Card V1",
		},
		{
			// Base-independent: if the deployment's public URL changed after
			// issuance, the tail still resolves the schema id.
			"vct from a different host still resolves by id",
			[]string{"https://old-host.example/credentials/custom-dk05t158qnou"},
			"Testa Card V2",
		},
		{
			// A credential we don't host: the slug is the most we know, and is
			// still better than the whole URL.
			"unknown vct falls back to the slug",
			[]string{"https://other.example/credentials/custom-unknown"},
			"custom-unknown",
		},
		{"no usable type", []string{"VerifiableCredential"}, "Credential"},
		{"no types at all", nil, "Credential"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := credentialCardTitle(schemas, backend.NormalizedCredential{Types: tc.types})
			if got != tc.want {
				t.Errorf("credentialCardTitle = %q, want %q", got, tc.want)
			}
		})
	}
}

// With no schemas loaded (nil adapter, or a vendor we can't reach) the card
// must still render something sane rather than panic or blank.
func TestCredentialCardTitle_NoSchemasFallsBackToSlug(t *testing.T) {
	got := credentialCardTitle(nil, backend.NormalizedCredential{
		Types: []string{"https://verifiably.bootcamp.cdpi.dev/credentials/custom-dk05t158qnou"},
	})
	if got != "custom-dk05t158qnou" {
		t.Errorf("got %q, want the slug fallback", got)
	}
}

// The expiry prose names the credential too, and used to be worse than the
// card: it returned Types[0] verbatim — the whole vct URL on SD-JWT, and the
// useless generic "VerifiableCredential" on W3C, which cannot say WHICH half of
// a delegated pair expired.
func TestTemporalCredLabel_UsesIssuerGivenName(t *testing.T) {
	t.Setenv("VERIFIABLY_PUBLIC_URL", "https://verifiably.bootcamp.cdpi.dev")
	schemas := testSchemas()

	sd := backend.NormalizedCredential{
		Types: []string{"https://verifiably.bootcamp.cdpi.dev/credentials/custom-dk05t158qnou"},
	}
	if got := temporalCredLabel(schemas, sd); got != "Testa Card V2" {
		t.Errorf("SD-JWT label = %q, want %q (not the raw vct URL)", got, "Testa Card V2")
	}

	w3c := backend.NormalizedCredential{Types: []string{"VerifiableCredential", "TestaCardV1"}}
	if got := temporalCredLabel(schemas, w3c); got != "Testa Card V1" {
		t.Errorf("W3C label = %q, want %q (not \"VerifiableCredential\")", got, "Testa Card V1")
	}

	if got := temporalCredLabel(schemas, backend.NormalizedCredential{}); got != "credential" {
		t.Errorf("unnamed label = %q, want %q", got, "credential")
	}
}

// The temporal check must not claim a window it never checked.
//
// A credential with no bounds is a PASS — not expiring is legitimate, and most
// credentials here have none. But saying "within its validity window" about a
// credential that HAS no window is indistinguishable from one that was really
// checked, and that wording is what made a real bug invisible: every Inji
// Certify credential was issued without a window, so expired ones verified
// green under a note asserting they'd been checked.
func TestCredTemporalCheck_NoWindowPassesButSaysSo(t *testing.T) {
	now := time.Date(2026, 7, 16, 17, 41, 0, 0, time.UTC)

	none := credTemporalCheck(backend.NormalizedCredential{Raw: map[string]any{}}, now)
	if none.Status != "pass" {
		t.Errorf("a non-expiring credential must still verify green, got %q", none.Status)
	}
	if none.Note == "within its validity window" {
		t.Error("must not claim to be within a window that does not exist")
	}

	within := credTemporalCheck(backend.NormalizedCredential{Raw: map[string]any{
		"nbf": float64(now.Add(-time.Hour).Unix()),
		"exp": float64(now.Add(time.Hour).Unix()),
	}}, now)
	if within.Status != "pass" || within.Note != "within its validity window" {
		t.Errorf("a credential inside its window = {%q,%q}, want a checked pass", within.Status, within.Note)
	}

	// And the case that started all of this: past exp must FAIL.
	expired := credTemporalCheck(backend.NormalizedCredential{Raw: map[string]any{
		"nbf": float64(now.Add(-time.Hour).Unix()),
		"exp": float64(now.Add(-time.Minute).Unix()),
	}}, now)
	if expired.Status != "fail" {
		t.Errorf("an expired credential must fail, got %q (%s)", expired.Status, expired.Note)
	}
}
