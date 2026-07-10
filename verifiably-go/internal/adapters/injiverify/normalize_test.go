package injiverify

import (
	"encoding/json"
	"testing"
)

// F25 combine: Inji Verify 0.16 returns each per-credential result's `vc` as a
// JSON *string* holding the JSON-LD (ldp_vc) credential — NOT a parsed object.
// normalizeInjiCredentials must parse that string form so the delegated-access
// evaluator can read credentialSubject claims (onBehalfOf/subjectRef/…). Without
// this the delegation credential yields no claims and the pair can't be
// evaluated. This is the exact form observed live (a subject leg + a delegation
// leg, the delegation flagged INVALID only because Inji Verify can't read
// verifiably's bitstring status list).
func TestNormalizeInjiCredentials_VCStringForm(t *testing.T) {
	subjectInner := `{"type":["VerifiableCredential","SubjectId"],"credentialSubject":{"id":"did:jwk:subj","givenName":"Maria","subjectRef":"5559990002"}}`
	delegInner := `{"type":["VerifiableCredential","DelegationPreLdp"],"credentialSubject":{"id":"did:jwk:subj","onBehalfOf":"5559990002","role":"Mother","statusType":"bitstring"}}`

	items := []vcResultItem{
		{VC: jsonString(t, subjectInner), VerificationStatus: "SUCCESS"},
		{VC: jsonString(t, delegInner), VerificationStatus: "INVALID"},
	}

	creds, hb := normalizeInjiCredentials(items)
	if len(creds) != 2 {
		t.Fatalf("normalized %d credentials, want 2", len(creds))
	}
	if hb == nil || !hb.Confirmed {
		t.Fatalf("holder binding = %+v, want Confirmed", hb)
	}
	if got := creds[0].Claims["subjectRef"]; got != "5559990002" {
		t.Errorf("subject leg subjectRef = %q, want 5559990002 (claims=%v)", got, creds[0].Claims)
	}
	if got := creds[1].Claims["onBehalfOf"]; got != "5559990002" {
		t.Errorf("delegation leg onBehalfOf = %q, want 5559990002 (claims=%v)", got, creds[1].Claims)
	}
	if got := creds[1].Claims["role"]; got != "Mother" {
		t.Errorf("delegation leg role = %q, want Mother", got)
	}
}

// A `vc` returned as a direct JSON object (rather than a string) is also parsed.
func TestNormalizeInjiCredentials_VCObjectForm(t *testing.T) {
	obj := `{"type":["VerifiableCredential","DelegationPreLdp"],"credentialSubject":{"id":"did:jwk:x","onBehalfOf":"42"}}`
	creds, _ := normalizeInjiCredentials([]vcResultItem{{VC: json.RawMessage(obj), VerificationStatus: "SUCCESS"}})
	if len(creds) != 1 || creds[0].Claims["onBehalfOf"] != "42" {
		t.Fatalf("object form not parsed: %+v", creds)
	}
}

// Empty / absent vc results yield no credentials and no holder binding.
func TestNormalizeInjiCredentials_Empty(t *testing.T) {
	creds, hb := normalizeInjiCredentials([]vcResultItem{{VC: nil}, {VC: json.RawMessage(`""`)}})
	if len(creds) != 0 || hb != nil {
		t.Fatalf("expected no credentials/binding, got creds=%v hb=%v", creds, hb)
	}
}

// jsonString wraps a JSON document as a JSON *string* value — the exact wire
// shape Inji Verify uses for vcResults[].vc (a quoted, escaped JSON-LD VC).
func jsonString(t *testing.T, doc string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
