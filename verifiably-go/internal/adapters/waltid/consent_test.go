package waltid

import (
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// describePDCredentials parses EVERY input-descriptor of a presentation-definition
// so the holder consent screen shows one card per requested credential (a
// delegated-access pair = identity + delegation), each with its own claims.
func TestDescribePDCredentials_Pair(t *testing.T) {
	pd := map[string]any{
		"input_descriptors": []any{
			map[string]any{
				"id":     "TestaCardV1",
				"format": map[string]any{"jwt_vc_json": map[string]any{}},
				"constraints": map[string]any{
					"limit_disclosure": "preferred",
					"fields": []any{
						map[string]any{"filter": map[string]any{"pattern": "TestaCardV1"}, "path": []any{"$.vc.type"}},
						map[string]any{"path": []any{"$.vc.credentialSubject.last_name"}},
						map[string]any{"path": []any{"$.vc.credentialSubject.testa_id"}},
					},
				},
			},
			map[string]any{
				"id":     "TestaDelegationV1",
				"format": map[string]any{"jwt_vc_json": map[string]any{}},
				"constraints": map[string]any{
					"fields": []any{
						map[string]any{"filter": map[string]any{"pattern": "TestaDelegationV1"}, "path": []any{"$.vc.type"}},
						map[string]any{"path": []any{"$.vc.credentialSubject.onBehalfOf"}},
					},
				},
			},
		},
	}
	creds := []vctypes.Credential{{Title: "Testa Card V1"}} // de-spaces to match TestaCardV1

	out := describePDCredentials(pd, creds)
	if len(out) != 2 {
		t.Fatalf("expected 2 requested credentials, got %d", len(out))
	}

	id := out[0]
	if id.TypeName != "TestaCardV1" || id.Format != "jwt_vc_json" {
		t.Fatalf("identity card: type=%q format=%q", id.TypeName, id.Format)
	}
	if len(id.Claims) != 2 || id.Claims[0] != "last_name" || id.Claims[1] != "testa_id" {
		t.Fatalf("identity claims = %v (type-filter path must be excluded)", id.Claims)
	}
	if !id.Held {
		t.Fatal("TestaCardV1 should be Held — 'Testa Card V1' is in the wallet")
	}

	del := out[1]
	if del.TypeName != "TestaDelegationV1" || len(del.Claims) != 1 || del.Claims[0] != "onBehalfOf" {
		t.Fatalf("delegation card = %+v", del)
	}
	if del.Held {
		t.Fatal("TestaDelegationV1 is not in the wallet → Held must be false")
	}
}

func TestCredentialIsType_DespacedMatch(t *testing.T) {
	c := vctypes.Credential{Title: "Pet Access Credential"}
	if !credentialIsType(c, "PetAccessCredential") {
		t.Error("de-spaced title should match the PD type")
	}
	if credentialIsType(c, "BirthCertificate") {
		t.Error("unrelated type should not match")
	}
	if credentialIsType(c, "") {
		t.Error("empty type should not match")
	}
}
