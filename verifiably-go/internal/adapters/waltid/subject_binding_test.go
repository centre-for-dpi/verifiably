package waltid

import (
	"encoding/json"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// These tests pin the National ID Nivel 2 subject-binding behaviour: a
// non-empty HolderDID lands as credentialSubject.id (VCDM) / sub (SD-JWT VC),
// and an empty one leaves the credential exactly as the operator pre-auth flow
// has always produced it (no id / sub key at all). See docs/credential-delivery.md.

func TestBuildCredentialData_HolderDID(t *testing.T) {
	schema := vctypes.Schema{ID: "PersonCredential"}
	subject := map[string]string{"given_name": "Ana", "family_name": "Pérez"}

	t.Run("holder DID set → credentialSubject.id present", func(t *testing.T) {
		raw, err := buildCredentialData(schema, subject, nil, "did:example:holder123")
		if err != nil {
			t.Fatalf("buildCredentialData: %v", err)
		}
		cs := credentialSubjectOf(t, raw)
		if cs["id"] != "did:example:holder123" {
			t.Errorf("credentialSubject.id = %v, want did:example:holder123", cs["id"])
		}
		if cs["given_name"] != "Ana" {
			t.Errorf("subject fields lost: given_name = %v", cs["given_name"])
		}
	})

	t.Run("empty holder DID → no id key (operator pre-auth unchanged)", func(t *testing.T) {
		raw, err := buildCredentialData(schema, subject, nil, "")
		if err != nil {
			t.Fatalf("buildCredentialData: %v", err)
		}
		cs := credentialSubjectOf(t, raw)
		if _, ok := cs["id"]; ok {
			t.Errorf("credentialSubject.id present with empty HolderDID: %v", cs["id"])
		}
	})
}

func TestBuildSDJWTCredentialData_HolderDID(t *testing.T) {
	subject := map[string]string{"given_name": "Ana"}

	t.Run("holder DID set → sub present at top level", func(t *testing.T) {
		raw, err := buildSDJWTCredentialData(subject, nil, "did:example:holder123")
		if err != nil {
			t.Fatalf("buildSDJWTCredentialData: %v", err)
		}
		out := decodeObject(t, raw)
		if out["sub"] != "did:example:holder123" {
			t.Errorf("sub = %v, want did:example:holder123", out["sub"])
		}
		if out["given_name"] != "Ana" {
			t.Errorf("subject claim lost: given_name = %v", out["given_name"])
		}
	})

	t.Run("empty holder DID → no sub key", func(t *testing.T) {
		raw, err := buildSDJWTCredentialData(subject, nil, "")
		if err != nil {
			t.Fatalf("buildSDJWTCredentialData: %v", err)
		}
		out := decodeObject(t, raw)
		if _, ok := out["sub"]; ok {
			t.Errorf("sub present with empty HolderDID: %v", out["sub"])
		}
	})
}

func decodeObject(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal credentialData: %v", err)
	}
	return m
}

func credentialSubjectOf(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	doc := decodeObject(t, raw)
	cs, ok := doc["credentialSubject"].(map[string]any)
	if !ok {
		t.Fatalf("credentialSubject missing or wrong type in %s", string(raw))
	}
	return cs
}
