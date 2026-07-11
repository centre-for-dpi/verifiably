package handlers

import (
	"context"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/statuslistcache"
)

// fakeStatusCache returns one fixed status-list document for any URL.
type fakeStatusCache struct{ raw string }

func (f fakeStatusCache) Fetch(_ context.Context, _, _ string) (statuslistcache.Result, error) {
	return statuslistcache.Result{RawJWT: f.raw, Source: "live"}, nil
}

func checkStatus(v backend.CredentialView, label string) string {
	for _, c := range v.Checks {
		if c.Label == label {
			return c.Status
		}
	}
	return "<absent>"
}

// buildDelegationCredentialViews must produce one card per presented credential,
// with the correct role, the disclosed claims, and every check attributed to the
// credential it concerns: external verifier + validity + revocation per card, and
// the delegation sub-checks (Linkage/Invocation/Capability on the delegation,
// Linkage on the subject).
func TestBuildDelegationCredentialViews(t *testing.T) {
	revokedList := `{"credentialSubject":{"type":"BitstringStatusList","statusPurpose":"revocation","encodedList":"` +
		encodedListWithBit(t, 5) + `"}}`

	subject := backend.NormalizedCredential{
		Types:      []string{"VerifiableCredential", "BirthCertificate"},
		Issuer:     "did:web:issuer",
		Format:     "w3c_vcdm_2",
		Claims:     map[string]string{"subjectRef": "5559990002", "givenName": "Maria"},
		HostStatus: "SUCCESS",
		Raw:        map[string]any{}, // no status reference → revocation n/a
	}
	deleg := backend.NormalizedCredential{
		Types:      []string{"VerifiableCredential", "DelegationCredential"},
		Issuer:     "did:web:issuer",
		Format:     "w3c_vcdm_2",
		Claims:     map[string]string{"onBehalfOf": "5559990002", "role": "Mother"},
		HostStatus: "INVALID", // external verifier flagged it (bitstring status)
		Raw: map[string]any{
			"credentialStatus": map[string]any{
				"type":                 "BitstringStatusListEntry",
				"statusListCredential": "https://issuer/status",
				"statusListIndex":      float64(5), // revoked bit
			},
		},
	}
	res := &backend.VerificationResult{
		Credentials: []backend.NormalizedCredential{subject, deleg},
		Delegation: &backend.DelegationResult{
			Evaluated: true, Authorized: true,
			Linkage: true, Invocation: true, Capability: true, NotRevoked: false,
			SubjectIndex: 0, DelegationIndex: 1,
		},
	}
	h := &H{StatusListCache: fakeStatusCache{raw: revokedList}}
	h.buildDelegationCredentialViews(context.Background(), res)

	if len(res.CredentialViews) != 2 {
		t.Fatalf("CredentialViews = %d, want 2", len(res.CredentialViews))
	}
	sv, dv := res.CredentialViews[0], res.CredentialViews[1]

	if sv.Role != "subject" || dv.Role != "delegation" {
		t.Fatalf("roles = %q / %q, want subject / delegation", sv.Role, dv.Role)
	}
	if sv.Claims["subjectRef"] != "5559990002" || dv.Claims["onBehalfOf"] != "5559990002" {
		t.Errorf("claims not carried: %v / %v", sv.Claims, dv.Claims)
	}

	// Subject card: external verifier pass, within validity pass, revocation n/a
	// (no status ref), linkage pass; NO invocation/capability.
	if got := checkStatus(sv, "External verifier"); got != "pass" {
		t.Errorf("subject External verifier = %q, want pass", got)
	}
	if got := checkStatus(sv, "Within validity"); got != "pass" {
		t.Errorf("subject Within validity = %q, want pass", got)
	}
	if got := checkStatus(sv, "Not revoked"); got != "na" {
		t.Errorf("subject Not revoked = %q, want na", got)
	}
	if got := checkStatus(sv, "Linkage"); got != "pass" {
		t.Errorf("subject Linkage = %q, want pass", got)
	}
	if got := checkStatus(sv, "Invocation"); got != "<absent>" {
		t.Errorf("subject should not carry Invocation, got %q", got)
	}

	// Delegation card: external verifier fail (INVALID), within validity pass,
	// NOT revoked fail (bit 5 set), linkage/invocation/capability pass.
	if got := checkStatus(dv, "External verifier"); got != "fail" {
		t.Errorf("delegation External verifier = %q, want fail", got)
	}
	if got := checkStatus(dv, "Not revoked"); got != "fail" {
		t.Errorf("delegation Not revoked = %q, want fail (index 5 revoked)", got)
	}
	for _, lbl := range []string{"Linkage", "Invocation", "Capability"} {
		if got := checkStatus(dv, lbl); got != "pass" {
			t.Errorf("delegation %s = %q, want pass", lbl, got)
		}
	}
}

// A single-credential verify produces no CredentialViews (keeps the flat card).
func TestBuildDelegationCredentialViews_SingleNoViews(t *testing.T) {
	res := &backend.VerificationResult{
		Credentials: []backend.NormalizedCredential{{Types: []string{"BirthCertificate"}}},
	}
	h := &H{}
	h.buildDelegationCredentialViews(context.Background(), res)
	if res.CredentialViews != nil {
		t.Fatalf("single-credential verify should yield no views, got %v", res.CredentialViews)
	}
}
