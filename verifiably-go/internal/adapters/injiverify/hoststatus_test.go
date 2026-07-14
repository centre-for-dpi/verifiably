package injiverify

import (
	"encoding/json"
	"testing"
)

// normalizeInjiCredentials must retain Inji Verify's PER-credential verdict
// (vcResults[].verificationStatus) on each NormalizedCredential so a combined
// result can show each credential's own host outcome.
func TestNormalizeInjiCredentials_RetainsHostStatus(t *testing.T) {
	mk := func(inner string) json.RawMessage {
		b, _ := json.Marshal(inner) // JSON *string* holding the VC — Inji's wire form
		return b
	}
	items := []vcResultItem{
		{VC: mk(`{"type":["VerifiableCredential","SubjectId"],"credentialSubject":{"subjectRef":"1"}}`), VerificationStatus: "SUCCESS"},
		{VC: mk(`{"type":["VerifiableCredential","DelegationPreLdp"],"credentialSubject":{"onBehalfOf":"1"}}`), VerificationStatus: "INVALID"},
	}
	creds, hb := normalizeInjiCredentials(items)
	if len(creds) != 2 {
		t.Fatalf("got %d creds, want 2", len(creds))
	}
	if creds[0].HostStatus != "SUCCESS" {
		t.Errorf("creds[0].HostStatus = %q, want SUCCESS", creds[0].HostStatus)
	}
	if creds[1].HostStatus != "INVALID" {
		t.Errorf("creds[1].HostStatus = %q, want INVALID", creds[1].HostStatus)
	}
	if hb == nil || !hb.Confirmed {
		t.Errorf("holder binding = %v, want Confirmed", hb)
	}
}
