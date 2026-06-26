package vp

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// FromVCObject is the normalization the delegation evaluator depends on: it
// flattens credentialSubject into Claims (which is why a JSON-LD capability
// resolves via the flat path) and resolves the subject DID + issuer.
func TestFromVCObject_W3C(t *testing.T) {
	vc := map[string]any{
		"type":   []any{"VerifiableCredential", "PetAccessCredential"},
		"issuer": "did:web:issuer",
		"credentialSubject": map[string]any{
			"id":         "did:key:delegate",
			"onBehalfOf": "urn:pet:bosco",
			"role":       "Owner",
		},
	}
	got := FromVCObject(vc)
	if got.SubjectID != "did:key:delegate" {
		t.Fatalf("SubjectID = %q", got.SubjectID)
	}
	if got.Issuer != "did:web:issuer" {
		t.Fatalf("Issuer = %q", got.Issuer)
	}
	if got.Claims["onBehalfOf"] != "urn:pet:bosco" || got.Claims["role"] != "Owner" {
		t.Fatalf("Claims = %v", got.Claims)
	}
	if _, ok := got.Claims["id"]; ok {
		t.Fatal("credentialSubject.id must be the subject, not a claim")
	}
}

// VC-JWT wraps the credential under "vc" and carries the issuer at the JWT level.
func TestFromVCObject_JWTWrapper(t *testing.T) {
	vc := map[string]any{
		"iss": "did:web:issuer",
		"vc": map[string]any{
			"type":              []any{"VerifiableCredential", "BirthCertificate"},
			"credentialSubject": map[string]any{"id": "did:key:child", "subjectRef": "urn:person:child-1"},
		},
	}
	got := FromVCObject(vc)
	if got.Issuer != "did:web:issuer" {
		t.Fatalf("Issuer = %q (should fall back to JWT iss)", got.Issuer)
	}
	if got.SubjectID != "did:key:child" || got.Claims["subjectRef"] != "urn:person:child-1" {
		t.Fatalf("SubjectID=%q subjectRef=%q", got.SubjectID, got.Claims["subjectRef"])
	}
}

// FromCompactSDJWT decodes the issuer JWT payload + the appended disclosures into
// a single claim set, so the SD-JWT delegation/status claims survive for the
// evaluator.
func TestFromCompactSDJWT(t *testing.T) {
	b64 := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	payload := map[string]any{
		"iss": "did:web:issuer", "sub": "did:key:delegate",
		"vct": "PetAccessCredential", "onBehalfOf": "urn:pet:bosco",
	}
	jwt := b64(map[string]any{"alg": "ES256"}) + "." + b64(payload) + ".sig"
	disclosure := base64.RawURLEncoding.EncodeToString([]byte(`["salt","allowedAction","present"]`))
	tok := jwt + "~" + disclosure + "~"

	got, ok := FromCompactSDJWT(tok)
	if !ok {
		t.Fatal("FromCompactSDJWT returned !ok")
	}
	if got.Format != "vc+sd-jwt" {
		t.Fatalf("Format = %q", got.Format)
	}
	if got.SubjectID != "did:key:delegate" || got.Issuer != "did:web:issuer" {
		t.Fatalf("SubjectID=%q Issuer=%q", got.SubjectID, got.Issuer)
	}
	if got.Claims["onBehalfOf"] != "urn:pet:bosco" {
		t.Fatalf("payload claim onBehalfOf = %q", got.Claims["onBehalfOf"])
	}
	if got.Claims["allowedAction"] != "present" {
		t.Fatalf("disclosed claim allowedAction = %q", got.Claims["allowedAction"])
	}
	if len(got.Types) == 0 || got.Types[0] != "PetAccessCredential" {
		t.Fatalf("Types = %v", got.Types)
	}
}

func TestFromCompactSDJWT_Garbage(t *testing.T) {
	if _, ok := FromCompactSDJWT("not-a-jwt"); ok {
		t.Fatal("garbage token should return ok=false")
	}
}
