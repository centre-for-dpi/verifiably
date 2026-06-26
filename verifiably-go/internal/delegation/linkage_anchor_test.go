package delegation

import (
	"context"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
)

// petCardSubject builds an identity credential with DID did:key:zSubjectAbc and the
// given credentialSubject fields (string values are also surfaced as Claims, as
// vp.FromVCObject would).
func petCardSubject(fields map[string]string) backend.NormalizedCredential {
	cs := map[string]any{"id": "did:key:zSubjectAbc"}
	claims := map[string]string{}
	for k, v := range fields {
		cs[k] = v
		claims[k] = v
	}
	return backend.NormalizedCredential{
		Types:     []string{"VerifiableCredential", "PetCard"},
		SubjectID: "did:key:zSubjectAbc",
		Issuer:    "did:web:registry",
		Format:    "w3c_vcdm_2",
		Claims:    claims,
		Raw:       map[string]any{"credentialSubject": cs},
	}
}

func delegOnBehalfOf(ref string) backend.NormalizedCredential {
	return backend.NormalizedCredential{
		Types:     []string{"VerifiableCredential", "DelegatedAccessCredential"},
		SubjectID: "did:example:parent",
		Issuer:    "did:web:registry",
		Format:    "w3c_vcdm_2",
		Raw: map[string]any{
			"credentialSubject": map[string]any{"id": "did:example:parent", "onBehalfOf": map[string]any{"id": ref}},
			"termsOfUse": []any{map[string]any{
				"type": "DelegationCapability", "invocationTarget": ref,
				"delegate": "did:example:parent", "allowedAction": []any{"present"},
			}},
		},
	}
}

// onBehalfOf == the identity's subjectRef → linked.
func TestEvaluate_Linkage_SubjectRefMatch(t *testing.T) {
	creds := []backend.NormalizedCredential{
		petCardSubject(map[string]string{"subjectRef": "urn:pet:bosco", "holderName": "Bosco"}),
		delegOnBehalfOf("urn:pet:bosco"),
	}
	got := Evaluate(context.Background(), creds, parentHolder(), baseOpts())
	if !got.Linkage || !got.Authorized {
		t.Fatalf("subjectRef match should authorize; reason: %s", got.Reason)
	}
}

// onBehalfOf == the identity's DID → linked (no subjectRef needed).
func TestEvaluate_Linkage_DIDMatch(t *testing.T) {
	creds := []backend.NormalizedCredential{
		petCardSubject(map[string]string{"holderName": "Bosco"}),
		delegOnBehalfOf("did:key:zSubjectAbc"),
	}
	got := Evaluate(context.Background(), creds, parentHolder(), baseOpts())
	if !got.Linkage || !got.Authorized {
		t.Fatalf("DID match should authorize; reason: %s", got.Reason)
	}
}

// onBehalfOf == a plain disclosed value (a name), which is NOT the subjectRef or
// DID → DENIED. The mapping point must be a unique identifier.
func TestEvaluate_Linkage_PlainValueDenied(t *testing.T) {
	creds := []backend.NormalizedCredential{
		petCardSubject(map[string]string{"holderName": "Johnte Dohnte", "holderId": "P-99"}),
		delegOnBehalfOf("Johnte Dohnte"),
	}
	got := Evaluate(context.Background(), creds, parentHolder(), baseOpts())
	if got.Linkage || got.Authorized {
		t.Fatalf("a plain name must not link (must be subjectRef, DID, or an identifier field); got authorized=%v", got.Authorized)
	}
}

// onBehalfOf == the value of an IDENTIFIER-named field (testa_id), with no
// subjectRef field present → linked. (The Plain test above uses the NAME value,
// which still must not link.)
func TestEvaluate_Linkage_IdentifierFieldMatch(t *testing.T) {
	creds := []backend.NormalizedCredential{
		petCardSubject(map[string]string{"last_name": "Ndegwa", "testa_id": "33764103"}),
		delegOnBehalfOf("33764103"),
	}
	got := Evaluate(context.Background(), creds, parentHolder(), baseOpts())
	if !got.Linkage || !got.Authorized {
		t.Fatalf("identifier-field (testa_id) match should authorize; reason: %s", got.Reason)
	}
}
