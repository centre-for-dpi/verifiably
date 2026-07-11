package handlers

import (
	"encoding/json"
	"testing"
)

const (
	// A W3C identity credential (testa_id + last_name) and a delegation credential
	// (onBehalfOf) — the two halves of a delegated-access pair.
	tIdentityVC   = `{"type":["VerifiableCredential","IdentityCred"],"credentialSubject":{"id":"did:holder:1","testa_id":"5500000005","last_name":"Abdullahi"}}`
	tDelegationVC = `{"type":["VerifiableCredential","DelegationCred"],"credentialSubject":{"id":"did:holder:1","onBehalfOf":"5500000005","role":"Lawyer","allowedAction":"sign"}}`
	tSDJWT        = "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJodHRwczovL3gvdmN0In0.sig~WyJzYWx0IiwiYSIsIjEiXQ~"
)

var (
	dIdentity   = injiDescriptor{ID: "id-desc", Name: "Identity", Format: "ldp_vp", RequestedFields: []string{"testa_id", "last_name"}}
	dDelegation = injiDescriptor{ID: "del-desc", Name: "Delegation", Format: "ldp_vp", RequestedFields: []string{"onBehalfOf"}}
)

// injiDescriptorFits must use W3C field-presence to route each descriptor to the
// right held credential — the crux of auto-matching a delegated pair.
func TestInjiDescriptorFits(t *testing.T) {
	if !injiDescriptorFits(dIdentity, tIdentityVC) {
		t.Error("identity credential should fit the identity descriptor")
	}
	if injiDescriptorFits(dIdentity, tDelegationVC) {
		t.Error("delegation credential must NOT fit the identity descriptor (lacks testa_id/last_name)")
	}
	if !injiDescriptorFits(dDelegation, tDelegationVC) {
		t.Error("delegation credential should fit the delegation descriptor")
	}
	if injiDescriptorFits(dDelegation, tIdentityVC) {
		t.Error("identity credential must NOT fit the delegation descriptor (lacks onBehalfOf)")
	}
	// Format mismatch: an ldp_vp descriptor cannot be satisfied by an SD-JWT.
	if injiDescriptorFits(dIdentity, tSDJWT) {
		t.Error("an SD-JWT must not fit an ldp_vp descriptor")
	}
	// An SD-JWT descriptor with a matching vct fits the SD-JWT.
	dSD := injiDescriptor{Format: "vc+sd-jwt", VctPattern: "https://x/vct"}
	if !injiDescriptorFits(dSD, tSDJWT) {
		t.Error("SD-JWT should fit a vc+sd-jwt descriptor with a matching vct")
	}
}

// injiAutoMatch assigns each descriptor a distinct held credential in order.
func TestInjiAutoMatch(t *testing.T) {
	sess := &Session{InjiClaimedVCs: []string{tIdentityVC, tDelegationVC}}
	jar := injiJAR{Descriptors: []injiDescriptor{dIdentity, dDelegation}}
	h := &H{}
	m := h.injiAutoMatch(sess, jar)
	if len(m) != 2 {
		t.Fatalf("want 2 matches, got %d", len(m))
	}
	if !m[0].Found || m[0].Held != tIdentityVC {
		t.Errorf("descriptor 0 (identity) matched %q found=%v", m[0].Held, m[0].Found)
	}
	if !m[1].Found || m[1].Held != tDelegationVC {
		t.Errorf("descriptor 1 (delegation) matched %q found=%v", m[1].Held, m[1].Found)
	}
	if m[0].CredID == m[1].CredID {
		t.Error("the two descriptors must not share one held credential")
	}

	// The order of the descriptors, not of the held creds, drives assignment.
	jarRev := injiJAR{Descriptors: []injiDescriptor{dDelegation, dIdentity}}
	mr := h.injiAutoMatch(sess, jarRev)
	if mr[0].Held != tDelegationVC || mr[1].Held != tIdentityVC {
		t.Errorf("reversed descriptors mis-matched: %q / %q", mr[0].Held, mr[1].Held)
	}

	// A descriptor with no held match is reported unfound.
	jarMissing := injiJAR{Descriptors: []injiDescriptor{dIdentity, {ID: "x", Format: "ldp_vp", RequestedFields: []string{"nonexistent_field"}}}}
	mm := h.injiAutoMatch(sess, jarMissing)
	if !mm[0].Found || mm[1].Found {
		t.Errorf("expected [found, unfound], got [%v, %v]", mm[0].Found, mm[1].Found)
	}
}

// injiBuildW3CVPTokenMulti wraps N creds in one presentation, preserving order.
func TestInjiBuildW3CVPTokenMulti(t *testing.T) {
	tok, err := injiBuildW3CVPTokenMulti([]string{tIdentityVC, tDelegationVC})
	if err != nil {
		t.Fatal(err)
	}
	var vp map[string]any
	if err := json.Unmarshal([]byte(tok), &vp); err != nil {
		t.Fatal(err)
	}
	vcs, _ := vp["verifiableCredential"].([]any)
	if len(vcs) != 2 {
		t.Fatalf("want 2 credentials in the VP, got %d", len(vcs))
	}
	cs0, _ := vcs[0].(map[string]any)["credentialSubject"].(map[string]any)
	cs1, _ := vcs[1].(map[string]any)["credentialSubject"].(map[string]any)
	if _, ok := cs0["testa_id"]; !ok {
		t.Error("verifiableCredential[0] should be the identity credential (order preserved)")
	}
	if _, ok := cs1["onBehalfOf"]; !ok {
		t.Error("verifiableCredential[1] should be the delegation credential (order preserved)")
	}
	if vp["holder"] != "did:holder:1" {
		t.Errorf("holder = %v, want the first credential's subject id", vp["holder"])
	}
}
