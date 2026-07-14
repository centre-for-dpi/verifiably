package registry

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// stub is a minimal verifier adapter that records the state and templateKey it
// receives, and echoes the vendor name in its returned State so tests can assert
// that the correct adapter was called and that the registry strips/restores the
// "dpg|<vendor>|" prefix correctly.
type stubVerifier struct {
	vendor      string
	templates   map[string]vctypes.OID4VPTemplate
	gotState    string
	gotTemplate string
}

func (s *stubVerifier) RequestPresentation(_ context.Context, req backend.PresentationRequest) (backend.PresentationRequestResult, error) {
	if _, ok := s.templates[req.TemplateKey]; !ok {
		return backend.PresentationRequestResult{}, errors.New("unknown template: " + req.TemplateKey)
	}
	return backend.PresentationRequestResult{
		State:    "inner-" + s.vendor,
		Template: s.templates[req.TemplateKey],
	}, nil
}

func (s *stubVerifier) FetchPresentationResult(_ context.Context, state, templateKey string) (backend.VerificationResult, error) {
	s.gotState = state
	s.gotTemplate = templateKey
	return backend.VerificationResult{Valid: true, Method: s.vendor}, nil
}

// Satisfy the full backend.Adapter interface with no-op stubs for everything
// that the routing tests don't exercise.
func (s *stubVerifier) ListIssuerDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}
func (s *stubVerifier) ListHolderDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return nil, nil
}
func (s *stubVerifier) ListVerifierDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return map[string]vctypes.DPG{s.vendor: {}}, nil
}
func (s *stubVerifier) ListSchemas(context.Context, string) ([]vctypes.Schema, error) {
	return nil, nil
}
func (s *stubVerifier) ListAllSchemas(context.Context) ([]vctypes.Schema, error) {
	return nil, nil
}
func (s *stubVerifier) GetIssuerMetadata(context.Context) (backend.IssuerMetadata, error) {
	return backend.IssuerMetadata{}, backend.ErrNotSupported
}
func (s *stubVerifier) SaveCustomSchema(context.Context, vctypes.Schema) error { return nil }
func (s *stubVerifier) DeleteCustomSchema(context.Context, string) error       { return nil }
func (s *stubVerifier) PrefillSubjectFields(context.Context, vctypes.Schema) (map[string]string, error) {
	return nil, nil
}
func (s *stubVerifier) IssueToWallet(context.Context, backend.IssueRequest) (backend.IssueToWalletResult, error) {
	return backend.IssueToWalletResult{}, nil
}
func (s *stubVerifier) IssueAsPDF(context.Context, backend.IssueRequest) (backend.IssueAsPDFResult, error) {
	return backend.IssueAsPDFResult{}, nil
}
func (s *stubVerifier) IssueBulk(context.Context, backend.IssueBulkRequest) (backend.IssueBulkResult, error) {
	return backend.IssueBulkResult{}, nil
}
func (s *stubVerifier) ListWalletCredentials(context.Context) ([]vctypes.Credential, error) {
	return nil, nil
}
func (s *stubVerifier) DeleteWalletCredential(context.Context, string) error { return nil }
func (s *stubVerifier) ListExampleOffers(context.Context) ([]string, error)   { return nil, nil }
func (s *stubVerifier) BootstrapOffers(context.Context) ([]string, error)     { return nil, nil }
func (s *stubVerifier) ListOID4VPTemplates(context.Context) (map[string]vctypes.OID4VPTemplate, error) {
	return s.templates, nil
}
func (s *stubVerifier) ParseOffer(context.Context, string) (vctypes.Credential, error) {
	return vctypes.Credential{}, nil
}
func (s *stubVerifier) ClaimCredential(context.Context, vctypes.Credential) (vctypes.Credential, error) {
	return vctypes.Credential{}, nil
}
func (s *stubVerifier) PresentCredential(context.Context, backend.PresentCredentialRequest) (backend.PresentCredentialResult, error) {
	return backend.PresentCredentialResult{}, nil
}
func (s *stubVerifier) VerifyDirect(context.Context, backend.DirectVerifyRequest) (backend.VerificationResult, error) {
	return backend.VerificationResult{}, nil
}
// newDualVerifierRegistry builds a Registry with two verifier adapters, each
// exposing one distinct template. Returns the registry and both stubs.
func newDualVerifierRegistry() (*Registry, *stubVerifier, *stubVerifier) {
	waltTpl := vctypes.OID4VPTemplate{Title: "Age Verification", Disclosure: "selective"}
	credeblTpl := vctypes.OID4VPTemplate{Title: "ID Check", Disclosure: "selective"}

	walt := &stubVerifier{vendor: "waltid", templates: map[string]vctypes.OID4VPTemplate{"age": waltTpl}}
	cred := &stubVerifier{vendor: "credebl", templates: map[string]vctypes.OID4VPTemplate{"id": credeblTpl}}

	reg := New()
	reg.verifiers["waltid"] = walt
	reg.verifierDPGs["waltid"] = vctypes.DPG{}
	reg.verifiers["credebl"] = cred
	reg.verifierDPGs["credebl"] = vctypes.DPG{}
	return reg, walt, cred
}

// TestMultiVerifierTemplateNamespacing ensures that ListOID4VPTemplates merges
// templates from both adapters and namespaces each key as "vendor:template".
func TestMultiVerifierTemplateNamespacing(t *testing.T) {
	reg, _, _ := newDualVerifierRegistry()

	tpls, err := reg.ListOID4VPTemplates(context.Background())
	if err != nil {
		t.Fatalf("ListOID4VPTemplates: %v", err)
	}
	if _, ok := tpls["waltid:age"]; !ok {
		t.Error("expected waltid:age in merged templates")
	}
	if _, ok := tpls["credebl:id"]; !ok {
		t.Error("expected credebl:id in merged templates")
	}
	// Raw keys without vendor prefix must NOT appear.
	if _, ok := tpls["age"]; ok {
		t.Error("raw key 'age' must not appear in merged output")
	}
	if _, ok := tpls["id"]; ok {
		t.Error("raw key 'id' must not appear in merged output")
	}
}

// TestMultiVerifierRequestRouting verifies that RequestPresentation:
//   - strips the "vendor:" prefix before forwarding to the adapter, and
//   - wraps the adapter's returned State with "dpg|<vendor>|<inner>" so
//     FetchPresentationResult can route deterministically.
func TestMultiVerifierRequestRouting(t *testing.T) {
	reg, _, cred := newDualVerifierRegistry()
	ctx := context.Background()

	// Caller passes back the registry's namespaced key ("credebl:id").
	req := backend.PresentationRequest{
		VerifierDpg: "credebl",
		TemplateKey: "credebl:id",
	}
	res, err := reg.RequestPresentation(ctx, req)
	if err != nil {
		t.Fatalf("RequestPresentation: %v", err)
	}

	// State must be tagged for deterministic routing.
	wantStatePrefix := "dpg|credebl|"
	if !strings.HasPrefix(res.State, wantStatePrefix) {
		t.Errorf("State = %q; want prefix %q", res.State, wantStatePrefix)
	}

	// The adapter should have been called with the bare key ("id"), not the
	// namespaced one. We verify indirectly: the stub returns "inner-credebl"
	// as its State, so the tagged state should be "dpg|credebl|inner-credebl".
	want := "dpg|credebl|inner-" + cred.vendor
	if res.State != want {
		t.Errorf("State = %q; want %q", res.State, want)
	}
}

// TestMultiVerifierFetchRouting ensures FetchPresentationResult routes a
// tagged state to the correct adapter, passing it the inner (untagged) state.
func TestMultiVerifierFetchRouting(t *testing.T) {
	reg, walt, cred := newDualVerifierRegistry()
	ctx := context.Background()

	// Simulate a session originated from the credebl verifier.
	taggedState := "dpg|credebl|session-abc"
	result, err := reg.FetchPresentationResult(ctx, taggedState, "id")
	if err != nil {
		t.Fatalf("FetchPresentationResult(credebl): %v", err)
	}
	if result.Method != "credebl" {
		t.Errorf("routed to wrong adapter: Method = %q", result.Method)
	}
	if cred.gotState != "session-abc" {
		t.Errorf("inner state not stripped: got %q, want %q", cred.gotState, "session-abc")
	}

	// Simulate a session originated from waltid.
	taggedState = "dpg|waltid|session-xyz"
	result, err = reg.FetchPresentationResult(ctx, taggedState, "age")
	if err != nil {
		t.Fatalf("FetchPresentationResult(waltid): %v", err)
	}
	if result.Method != "waltid" {
		t.Errorf("routed to wrong adapter: Method = %q", result.Method)
	}
	if walt.gotState != "session-xyz" {
		t.Errorf("inner state not stripped: got %q, want %q", walt.gotState, "session-xyz")
	}
}

// TestMultiVerifierLegacyStateFails asserts that an untagged (legacy) state is
// rejected when multiple verifiers are registered, rather than silently picking
// a random adapter.
func TestMultiVerifierLegacyStateFails(t *testing.T) {
	reg, _, _ := newDualVerifierRegistry()

	_, err := reg.FetchPresentationResult(context.Background(), "untagged-session", "age")
	if err == nil {
		t.Fatal("expected error for untagged state with two verifiers, got nil")
	}
	if !strings.Contains(err.Error(), "re-initiate") {
		t.Errorf("expected actionable error message mentioning re-initiate; got %q", err.Error())
	}
}

// TestSingleVerifierLegacyStatePassthrough confirms that a deployment with one
// verifier still handles untagged sessions (no-tag legacy fallback path).
func TestSingleVerifierLegacyStatePassthrough(t *testing.T) {
	waltTpl := vctypes.OID4VPTemplate{Title: "Age Verification", Disclosure: "selective"}
	walt := &stubVerifier{vendor: "waltid", templates: map[string]vctypes.OID4VPTemplate{"age": waltTpl}}

	reg := New()
	reg.verifiers["waltid"] = walt
	reg.verifierDPGs["waltid"] = vctypes.DPG{}

	result, err := reg.FetchPresentationResult(context.Background(), "legacy-session", "age")
	if err != nil {
		t.Fatalf("single-verifier legacy path: %v", err)
	}
	if result.Method != "waltid" {
		t.Errorf("unexpected method: %q", result.Method)
	}
}
