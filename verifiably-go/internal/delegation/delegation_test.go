package delegation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/backend"
)

var fixedNow = time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)

// identityCred is a birth-certificate-style subject credential anchored on a
// stable registry id (subjectRef), per ADR Q6.
func identityCred() backend.NormalizedCredential {
	return backend.NormalizedCredential{
		Types:     []string{"VerifiableCredential", "BirthCertificate"},
		SubjectID: "did:example:child",
		Issuer:    "did:web:registry",
		Format:    "w3c_vcdm_2",
		Raw: map[string]any{
			"type":   []any{"VerifiableCredential", "BirthCertificate"},
			"issuer": "did:web:registry",
			"credentialSubject": map[string]any{
				"id":         "did:example:child",
				"subjectRef": "urn:person:child-1",
			},
		},
	}
}

// delegationCredJSONLD is a §6 JSON-LD delegation credential: delegate as
// subject, onBehalfOf the child, capability in termsOfUse, status entry.
func delegationCredJSONLD() backend.NormalizedCredential {
	return backend.NormalizedCredential{
		Types:     []string{"VerifiableCredential", "DelegatedAccessCredential"},
		SubjectID: "did:example:parent",
		Issuer:    "did:web:registry",
		Format:    "w3c_vcdm_2",
		Raw: map[string]any{
			"type":   []any{"VerifiableCredential", "DelegatedAccessCredential"},
			"issuer": "did:web:registry",
			"credentialSubject": map[string]any{
				"id":         "did:example:parent",
				"onBehalfOf": map[string]any{"id": "urn:person:child-1"},
			},
			"termsOfUse": []any{map[string]any{
				"type":             "DelegationCapability",
				"controller":       "did:web:registry",
				"invocationTarget": "urn:person:child-1",
				"delegate":         "did:example:parent",
				"allowedAction":    []any{"present", "consent:disclose"},
				"caveat":           []any{map[string]any{"type": "ValidWhile", "validUntil": "2033-03-10T00:00:00Z"}},
			}},
			"credentialStatus": map[string]any{
				"type":                 "BitstringStatusListEntry",
				"statusPurpose":        "revocation",
				"statusListIndex":      "94567",
				"statusListCredential": "https://registry.example.gov/status/3",
			},
		},
	}
}

func parentHolder() *backend.HolderBinding {
	return &backend.HolderBinding{ID: "did:example:parent", Confirmed: true}
}

// notRevoked / revoked status checkers.
func notRevoked(context.Context, StatusRef) (bool, error) { return false, nil }
func revoked(context.Context, StatusRef) (bool, error)    { return true, nil }
func statusErr(context.Context, StatusRef) (bool, error)  { return false, errors.New("unreachable") }

// trustAll / trustNone.
func trustAll(context.Context, string, string) error { return nil }
func trustNone(_ context.Context, did, _ string) error {
	return errors.New("not in registry")
}

func baseOpts() Options {
	return Options{Now: fixedNow, RequestedAction: "present", Status: notRevoked, Trust: trustAll, FailClosed: true}
}

func TestEvaluate_NotADelegationPresentation(t *testing.T) {
	got := Evaluate(context.Background(), []backend.NormalizedCredential{identityCred()}, nil, baseOpts())
	if got.Evaluated {
		t.Fatalf("expected Evaluated=false for a presentation without a delegation credential, got %+v", got)
	}
}

func TestEvaluate_HappyPath_JSONLD(t *testing.T) {
	creds := []backend.NormalizedCredential{identityCred(), delegationCredJSONLD()}
	got := Evaluate(context.Background(), creds, parentHolder(), baseOpts())
	if !got.Authorized {
		t.Fatalf("expected Authorized, got %+v", got)
	}
	for name, ok := range map[string]bool{"Linkage": got.Linkage, "Invocation": got.Invocation, "Capability": got.Capability, "NotRevoked": got.NotRevoked, "Trusted": got.Trusted} {
		if !ok {
			t.Errorf("expected %s=true, got %+v", name, got)
		}
	}
}

func TestEvaluate_HappyPath_SDJWT(t *testing.T) {
	identity := backend.NormalizedCredential{
		Types: []string{"BirthCertificate"}, SubjectID: "urn:person:child-1", Issuer: "did:web:registry", Format: "vc+sd-jwt",
		Raw: map[string]any{"vct": "BirthCertificate", "iss": "did:web:registry", "sub": "urn:person:child-1"},
	}
	deleg := backend.NormalizedCredential{
		Types: []string{"DelegationCredential"}, SubjectID: "did:example:parent", Issuer: "did:web:registry", Format: "vc+sd-jwt",
		Raw: map[string]any{
			"vct": "DelegationCredential", "iss": "did:web:registry", "sub": "did:example:parent",
			"delegation": map[string]any{
				"on_behalf_of":   "urn:person:child-1",
				"delegate":       "did:example:parent",
				"allowed_action": []any{"present"},
				"valid_until":    "2033-03-10T00:00:00Z",
			},
			"status": map[string]any{"status_list": map[string]any{"uri": "https://r/sl/1", "idx": float64(88231)}},
		},
	}
	got := Evaluate(context.Background(), []backend.NormalizedCredential{identity, deleg}, parentHolder(), baseOpts())
	if !got.Authorized {
		t.Fatalf("expected Authorized for SD-JWT delegation, got %+v", got)
	}
}

func TestEvaluate_Failures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(creds []backend.NormalizedCredential, opts *Options, holder **backend.HolderBinding)
		field  string // sub-flag expected false (informational)
	}{
		{"linkage mismatch", func(creds []backend.NormalizedCredential, _ *Options, _ **backend.HolderBinding) {
			creds[0].Raw["credentialSubject"].(map[string]any)["subjectRef"] = "urn:person:someone-else"
		}, "Linkage"},
		{"expired", func(creds []backend.NormalizedCredential, _ *Options, _ **backend.HolderBinding) {
			tou := creds[1].Raw["termsOfUse"].([]any)[0].(map[string]any)
			tou["caveat"] = []any{map[string]any{"validUntil": "2020-01-01T00:00:00Z"}}
		}, "Capability"},
		{"action not allowed", func(_ []backend.NormalizedCredential, opts *Options, _ **backend.HolderBinding) {
			opts.RequestedAction = "delete"
		}, "Capability"},
		{"revoked", func(_ []backend.NormalizedCredential, opts *Options, _ **backend.HolderBinding) {
			opts.Status = revoked
		}, "NotRevoked"},
		{"untrusted", func(_ []backend.NormalizedCredential, opts *Options, _ **backend.HolderBinding) {
			opts.Trust = trustNone
		}, "Trusted"},
		{"controller not issuer", func(creds []backend.NormalizedCredential, _ *Options, _ **backend.HolderBinding) {
			creds[1].Raw["termsOfUse"].([]any)[0].(map[string]any)["controller"] = "did:web:attacker"
		}, "Capability"},
		{"presenter not delegate", func(_ []backend.NormalizedCredential, _ *Options, holder **backend.HolderBinding) {
			*holder = &backend.HolderBinding{ID: "did:example:imposter", Confirmed: true}
		}, "Invocation"},
		{"status unavailable fail-closed", func(_ []backend.NormalizedCredential, opts *Options, _ **backend.HolderBinding) {
			opts.Status = statusErr
		}, "NotRevoked"},
		{"re-delegation chain rejected", func(creds []backend.NormalizedCredential, _ *Options, _ **backend.HolderBinding) {
			creds[1].Raw["termsOfUse"].([]any)[0].(map[string]any)["parentCapability"] = "urn:cap:root"
		}, "Capability"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			creds := []backend.NormalizedCredential{identityCred(), delegationCredJSONLD()}
			opts := baseOpts()
			holder := parentHolder()
			tc.mutate(creds, &opts, &holder)
			got := Evaluate(context.Background(), creds, holder, opts)
			if got.Authorized {
				t.Fatalf("expected NOT authorized for %q, got %+v", tc.name, got)
			}
			if !got.Evaluated {
				t.Fatalf("expected Evaluated=true (a delegation cred was present) for %q", tc.name)
			}
			if got.Reason == "" {
				t.Errorf("expected a Reason for %q", tc.name)
			}
		})
	}
}
