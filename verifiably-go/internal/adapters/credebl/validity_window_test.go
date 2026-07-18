package credebl

import (
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// CREDEBL and the validity window.
//
// CREDEBL's create-offer takes only authorizationType/pin/credentials
// [{templateId,payload}] — there is no validity field, and payload is validated
// against the template's declared attributes, so injecting nbf/exp would risk a
// template-validation rejection rather than an expiring credential. CREDEBL
// therefore cannot express a window today.
//
// That makes REFUSING the contract. The bug this guards is not "CREDEBL lacks a
// feature", it is "the adapter accepted a window and issued a credential
// without one": the operator sets an expiry, issuance reports success, and the
// credential verifies as valid forever — a silent security downgrade that is
// indistinguishable from working. An adapter must carry the window or say it
// cannot; never both accept it and drop it.
func TestCredebl_RefusesValidityWindowItCannotCarry(t *testing.T) {
	expiring := vctypes.Schema{
		Name:    "Testa Card V2",
		Std:     "sd_jwt_vc (IETF)",
		Expires: true,
	}
	for _, tc := range []struct {
		name string
		req  backend.IssueRequest
	}{
		{"schema declares a window", backend.IssueRequest{Schema: expiring}},
		{"issuance supplies dates", backend.IssueRequest{
			Schema:     vctypes.Schema{Name: "Card", Std: "sd_jwt_vc (IETF)"},
			ValidFrom:  "2026-07-16T17:32:00Z",
			ValidUntil: "2026-07-16T17:35:00Z",
		}},
		{"validUntil alone", backend.IssueRequest{
			Schema:     vctypes.Schema{Name: "Card", Std: "sd_jwt_vc (IETF)"},
			ValidUntil: "2026-07-16T17:35:00Z",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := errIfValidityUnsupported(tc.req)
			if err == nil {
				t.Fatal("CREDEBL must refuse a window it cannot carry — dropping it issues a credential that never expires")
			}
			// The operator has to be able to act on this, so the message must
			// name the consequence, not just fail.
			if !strings.Contains(strings.ToLower(err.Error()), "never expire") {
				t.Errorf("error must explain the consequence, got: %v", err)
			}
		})
	}
}

// Most credentials never expire, and those must keep issuing normally — the
// guard must not become a blanket block on CREDEBL issuance.
func TestCredebl_IssuesNonExpiringCredentialsNormally(t *testing.T) {
	req := backend.IssueRequest{
		Schema:      vctypes.Schema{Name: "Plain Card", Std: "sd_jwt_vc (IETF)"},
		SubjectData: map[string]string{"name": "Ada"},
	}
	if err := errIfValidityUnsupported(req); err != nil {
		t.Errorf("a credential with no window must issue: %v", err)
	}
}

// A schema built the legacy way (opting into expiry via a valid_until claim
// field) must be refused too — otherwise the old shape slips through the guard
// and silently never expires.
func TestCredebl_RefusesLegacyValidUntilSchema(t *testing.T) {
	legacy := vctypes.Schema{
		Name: "Legacy Card",
		Std:  "sd_jwt_vc (IETF)",
		FieldsSpec: []vctypes.FieldSpec{
			{Name: "valid_until", Datatype: "string", Format: "datetime"},
		},
	}
	if err := errIfValidityUnsupported(backend.IssueRequest{Schema: legacy}); err == nil {
		t.Fatal("a legacy valid_until schema declares a window too — it must be refused, not silently dropped")
	}
}
