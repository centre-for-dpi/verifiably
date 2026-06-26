package delegation

import (
	"context"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
)

// TestEvaluate_Linkage_NonSubjectRefIdentifier mirrors a real issuer setup that
// previously failed: the identity credential has NO field literally named
// subjectRef — just a disclosed "holderName" — and the delegation's onBehalfOf
// names that value (not the subject DID). Linkage must succeed: onBehalfOf
// identifies the principal by a disclosed identifier. This is what lets the
// JIT issuer guidance ("map onBehalfOf to an identifier field or the DID") hold
// for any field the issuer chooses, without a magic subjectRef name.
func TestEvaluate_Linkage_NonSubjectRefIdentifier(t *testing.T) {
	identity := backend.NormalizedCredential{
		Types:     []string{"VerifiableCredential", "PetCard"},
		SubjectID: "did:key:zSubjectAbc",
		Issuer:    "did:web:registry",
		Format:    "w3c_vcdm_2",
		Claims:    map[string]string{"holderName": "Johnte Dohnte", "holderId": "P-99"},
		Raw: map[string]any{
			"type":   []any{"VerifiableCredential", "PetCard"},
			"issuer": "did:web:registry",
			"credentialSubject": map[string]any{
				"id":         "did:key:zSubjectAbc",
				"holderName": "Johnte Dohnte",
				"holderId":   "P-99",
			},
		},
	}
	deleg := backend.NormalizedCredential{
		Types:     []string{"VerifiableCredential", "DelegatedAccessCredential"},
		SubjectID: "did:example:parent",
		Issuer:    "did:web:registry",
		Format:    "w3c_vcdm_2",
		Raw: map[string]any{
			"type":   []any{"VerifiableCredential", "DelegatedAccessCredential"},
			"issuer": "did:web:registry",
			"credentialSubject": map[string]any{
				"id":         "did:example:parent",
				"onBehalfOf": map[string]any{"id": "Johnte Dohnte"},
			},
			"termsOfUse": []any{map[string]any{
				"type":             "DelegationCapability",
				"invocationTarget": "Johnte Dohnte",
				"delegate":         "did:example:parent",
				"allowedAction":    []any{"present"},
			}},
		},
	}
	got := Evaluate(context.Background(), []backend.NormalizedCredential{identity, deleg}, parentHolder(), baseOpts())
	if !got.Linkage {
		t.Fatalf("expected linkage via disclosed identifier, got reason: %s", got.Reason)
	}
	if !got.Authorized {
		t.Fatalf("expected authorized, got reason: %s", got.Reason)
	}
}

// TestEvaluate_Linkage_NoMatchStillFails confirms the check is not blanket-loose:
// an onBehalfOf that matches NONE of the identity's identifiers is still denied,
// and the reason lists the available identifiers so the issuer can fix it.
func TestEvaluate_Linkage_NoMatchStillFails(t *testing.T) {
	identity := backend.NormalizedCredential{
		Types:     []string{"VerifiableCredential", "PetCard"},
		SubjectID: "did:key:zSubjectAbc",
		Issuer:    "did:web:registry",
		Format:    "w3c_vcdm_2",
		Claims:    map[string]string{"holderName": "Someone Else"},
		Raw: map[string]any{
			"credentialSubject": map[string]any{"id": "did:key:zSubjectAbc", "holderName": "Someone Else"},
		},
	}
	deleg := delegationCredJSONLD() // onBehalfOf urn:person:child-1 — unrelated
	got := Evaluate(context.Background(), []backend.NormalizedCredential{identity, deleg}, parentHolder(), baseOpts())
	if got.Linkage || got.Authorized {
		t.Fatalf("expected linkage failure for unrelated subject, got authorized=%v", got.Authorized)
	}
}
