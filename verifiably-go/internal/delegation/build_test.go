package delegation

import (
	"context"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/vp"
)

// TestBuildAndEvaluate_RoundTrip proves the issuance-side construction and the
// verification-side evaluator share one contract: a built credential pair, after
// passing through the SAME per-credential normalizer the verifier adapters use,
// is authorised — and denied once the delegation's status bit is set.
func TestBuildAndEvaluate_RoundTrip(t *testing.T) {
	const (
		ctxURL   = "https://verifiably.test/static/contexts/delegated-access-v1.jsonld"
		issuer   = "did:web:registry"
		childRef = "urn:person:child-1"
		parent   = "did:example:parent"
		until    = "2033-03-10T00:00:00Z"
	)
	delegStatus := &StatusEntry{PublishURL: "https://registry.example/status/1", Index: 5}

	birth := BuildSubjectCredential(SubjectCredentialSpec{
		ContextURL: ctxURL, Issuer: issuer, SubjectDID: "did:example:child",
		SubjectRef: childRef, Type: "BirthCertificate",
		Claims: map[string]string{"givenName": "Maria"}, ValidUntil: until,
	})
	deleg := BuildDelegationCredential(DelegationCredentialSpec{
		ContextURL: ctxURL, Issuer: issuer, DelegateID: parent, OnBehalfOf: childRef,
		Role: "Mother", AllowedAction: []string{"present", "consent:disclose"},
		ValidUntil: until, Status: delegStatus,
	})

	// Normalize exactly as the verifier adapters do (shared internal/vp parser).
	creds := []backend.NormalizedCredential{vp.FromVCObject(birth), vp.FromVCObject(deleg)}
	holder := &backend.HolderBinding{ID: parent, Confirmed: true}
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)

	// Sanity: the built bodies carry the structures the evaluator needs.
	if creds[1].Raw["termsOfUse"] == nil {
		t.Fatalf("delegation credential missing termsOfUse: %+v", creds[1].Raw)
	}
	if subjectAnchor(creds[0]) != childRef {
		t.Fatalf("subject anchor = %q, want %q", subjectAnchor(creds[0]), childRef)
	}

	// Not revoked → authorised.
	ok := Evaluate(context.Background(), creds, holder, Options{
		Now: now, RequestedAction: "present",
		Status: func(context.Context, StatusRef) (bool, error) { return false, nil },
		Trust:  func(context.Context, string, string) error { return nil },
		FailClosed: true,
	})
	if !ok.Authorized {
		t.Fatalf("expected authorised for a freshly issued pair, got %+v", ok)
	}

	// Delegation's bit (index 5) set → denied. The checker keys on the
	// delegation's allocated index, proving the status pointer round-trips.
	denied := Evaluate(context.Background(), creds, holder, Options{
		Now: now, RequestedAction: "present",
		Status: func(_ context.Context, ref StatusRef) (bool, error) { return ref.Index == int64(delegStatus.Index), nil },
		Trust:  func(context.Context, string, string) error { return nil },
		FailClosed: true,
	})
	if denied.Authorized {
		t.Fatalf("expected denial after revoking the delegation, got %+v", denied)
	}
	if denied.NotRevoked {
		t.Errorf("expected NotRevoked=false after revocation, got %+v", denied)
	}
}
