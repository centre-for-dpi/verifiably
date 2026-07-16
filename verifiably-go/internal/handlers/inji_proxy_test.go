package handlers

import (
	"reflect"
	"testing"
)

// didDocWith builds a minimal did.json doc whose assertionMethod/authentication
// are the BARE did (the shape Inji's upstream did.json emits) plus one VM per id.
func didDocWith(vmIDs ...string) map[string]any {
	methods := make([]any, 0, len(vmIDs))
	for _, id := range vmIDs {
		methods = append(methods, map[string]any{
			"id":                 id,
			"type":               "Ed25519VerificationKey2020",
			"controller":         "did:web:ex",
			"publicKeyMultibase": "z6MkExampleKeyMaterial",
			"@context":           "https://w3id.org/security/suites/ed25519-2020/v1",
		})
	}
	return map[string]any{
		"id":                 "did:web:ex",
		"assertionMethod":    []any{"did:web:ex"}, // bare DID — upstream form
		"authentication":     []any{"did:web:ex"},
		"verificationMethod": methods,
	}
}

func asStrings(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// patchedDidDoc must rewrite the bare-DID assertionMethod/authentication to the
// FULL verification-method id (did#kid) so strict verifiers accept the proof.
func TestPatchedDidDoc_NormalizesRelationshipsToFullVMIDs(t *testing.T) {
	doc := didDocWith("did:web:ex#k1")
	patchedDidDoc(doc, nil)
	want := []string{"did:web:ex#k1"}
	if got := asStrings(doc["assertionMethod"]); !reflect.DeepEqual(got, want) {
		t.Errorf("assertionMethod = %v, want %v", got, want)
	}
	if got := asStrings(doc["authentication"]); !reflect.DeepEqual(got, want) {
		t.Errorf("authentication = %v, want %v", got, want)
	}
}

// Extra observed kids are cloned into verificationMethod and surfaced in the
// relationships.
func TestPatchedDidDoc_ClonesExtraKids(t *testing.T) {
	doc := didDocWith("did:web:ex#k1")
	patchedDidDoc(doc, []string{"k2"})
	vms, _ := doc["verificationMethod"].([]any)
	if len(vms) != 2 {
		t.Fatalf("verificationMethod len = %d, want 2", len(vms))
	}
	clone, _ := vms[1].(map[string]any)
	if clone["id"] != "did:web:ex#k2" {
		t.Errorf("clone id = %v, want did:web:ex#k2", clone["id"])
	}
	if clone["publicKeyMultibase"] != "z6MkExampleKeyMaterial" {
		t.Error("clone did not copy the template key material")
	}
	want := []string{"did:web:ex#k1", "did:web:ex#k2"}
	if got := asStrings(doc["assertionMethod"]); !reflect.DeepEqual(got, want) {
		t.Errorf("assertionMethod = %v, want %v", got, want)
	}
}

// Already-present kids are not duplicated.
func TestPatchedDidDoc_DedupesExistingKid(t *testing.T) {
	doc := didDocWith("did:web:ex#k1")
	patchedDidDoc(doc, []string{"k1"})
	if vms, _ := doc["verificationMethod"].([]any); len(vms) != 1 {
		t.Errorf("verificationMethod len = %d, want 1 (no dup)", len(vms))
	}
}

// No verification methods → early return, relationships untouched (not added).
func TestPatchedDidDoc_NoVerificationMethodsNoop(t *testing.T) {
	doc := map[string]any{"id": "did:web:ex", "verificationMethod": []any{}}
	patchedDidDoc(doc, []string{"k1"})
	if _, ok := doc["assertionMethod"]; ok {
		t.Error("assertionMethod should not be synthesised when there are no VMs")
	}
}

// Running twice is stable.
func TestPatchedDidDoc_Idempotent(t *testing.T) {
	doc := didDocWith("did:web:ex#k1")
	patchedDidDoc(doc, nil)
	first := asStrings(doc["assertionMethod"])
	patchedDidDoc(doc, nil)
	if got := asStrings(doc["assertionMethod"]); !reflect.DeepEqual(got, first) {
		t.Errorf("not idempotent: %v vs %v", got, first)
	}
}
