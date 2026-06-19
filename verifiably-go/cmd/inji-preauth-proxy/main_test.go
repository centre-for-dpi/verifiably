package main

import (
	"encoding/json"
	"testing"
)

// keys parses a JSON object body and reports whether each key is present.
func bodyHasKey(t *testing.T, body []byte, key string) bool {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", body, err)
	}
	_, ok := m[key]
	return ok
}

// walt.id echoes the offered config's `display` block into the credential
// REQUEST; Inji rejects unknown fields. It must be stripped.
func TestSanitizeCredentialRequest_StripsDisplay(t *testing.T) {
	in := []byte(`{"format":"vc+sd-jwt","proof":{"proof_type":"jwt","jwt":"x"},"vct":"v","display":[{"name":"X"}]}`)
	out := sanitizeCredentialRequest(in)
	if bodyHasKey(t, out, "display") {
		t.Error("display was not stripped")
	}
	for _, k := range []string{"format", "proof", "vct"} {
		if !bodyHasKey(t, out, k) {
			t.Errorf("required field %q was dropped", k)
		}
	}
}

// An empty credential_definition:{} on a vc+sd-jwt request makes Inji 400; drop it.
func TestSanitizeCredentialRequest_StripsEmptyCredentialDefinition(t *testing.T) {
	in := []byte(`{"format":"vc+sd-jwt","vct":"v","credential_definition":{}}`)
	out := sanitizeCredentialRequest(in)
	if bodyHasKey(t, out, "credential_definition") {
		t.Error("empty credential_definition was not stripped")
	}
}

// A populated credential_definition (ldp_vc) must be preserved for alignment.
func TestSanitizeCredentialRequest_KeepsPopulatedCredentialDefinition(t *testing.T) {
	in := []byte(`{"format":"ldp_vc","credential_definition":{"type":["A","VerifiableCredential"]}}`)
	out := sanitizeCredentialRequest(in)
	if !bodyHasKey(t, out, "credential_definition") {
		t.Error("populated credential_definition was wrongly stripped")
	}
}

// Nothing to strip → return the input bytes unchanged.
func TestSanitizeCredentialRequest_NoChange(t *testing.T) {
	in := []byte(`{"format":"ldp_vc","proof":{"jwt":"x"}}`)
	out := sanitizeCredentialRequest(in)
	if string(out) != string(in) {
		t.Errorf("expected unchanged body, got %s", out)
	}
}

// Non-JSON bodies pass through untouched.
func TestSanitizeCredentialRequest_NonJSON(t *testing.T) {
	in := []byte(`not json`)
	out := sanitizeCredentialRequest(in)
	if string(out) != string(in) {
		t.Errorf("non-JSON should pass through, got %s", out)
	}
}
