// SPDX-License-Identifier: Apache-2.0

package delegation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

var fixedNow = time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)

func identityCred() vc.Credential {
	return vc.Credential{
		Types: []string{"VerifiableCredential", "BirthCertificate"}, SubjectID: "did:example:child",
		Issuer: "did:web:registry", Format: vc.ModelVCDM2,
		Raw: map[string]any{
			"type": []any{"VerifiableCredential", "BirthCertificate"}, "issuer": "did:web:registry",
			"credentialSubject": map[string]any{"id": "did:example:child", "subjectRef": "urn:person:child-1"},
		},
	}
}

func delegationCredJSONLD() vc.Credential {
	return vc.Credential{
		Types: []string{"VerifiableCredential", "DelegatedAccessCredential"}, SubjectID: "did:example:parent",
		Issuer: "did:web:registry", Format: vc.ModelVCDM2,
		Raw: map[string]any{
			"type": []any{"VerifiableCredential", "DelegatedAccessCredential"}, "issuer": "did:web:registry",
			"credentialSubject": map[string]any{
				"id": "did:example:parent", "onBehalfOf": map[string]any{"id": "urn:person:child-1"},
			},
			"termsOfUse": []any{map[string]any{
				"type": "DelegationCapability", "controller": "did:web:registry",
				"invocationTarget": "urn:person:child-1", "delegate": "did:example:parent",
				"allowedAction": []any{"present", "consent:disclose"},
				"caveat":        []any{map[string]any{"type": "ValidWhile", "validUntil": "2033-03-10T00:00:00Z"}},
			}},
			"credentialStatus": map[string]any{
				"type": "BitstringStatusListEntry", "statusPurpose": "revocation",
				"statusListIndex": "94567", "statusListCredential": "https://registry.example.gov/status/3",
			},
		},
	}
}

func parentHolder() *vc.HolderBinding {
	return &vc.HolderBinding{ID: "did:example:parent", Confirmed: true}
}

func notRevoked(context.Context, StatusRef) (bool, error) { return false, nil }
func revoked(context.Context, StatusRef) (bool, error)    { return true, nil }
func statusErr(context.Context, StatusRef) (bool, error)  { return false, errors.New("unreachable") }
func trustAll(context.Context, string, string) error      { return nil }
func trustNone(context.Context, string, string) error     { return errors.New("not in registry") }

func baseOpts() Options {
	return Options{Now: fixedNow, RequestedAction: "present", Status: notRevoked, Trust: trustAll, FailClosed: true}
}

func tou(c vc.Credential) map[string]any {
	return c.Raw["termsOfUse"].([]any)[0].(map[string]any)
}

func TestEvaluateNotADelegationPresentation(t *testing.T) {
	got := Evaluate(context.Background(), []vc.Credential{identityCred()}, nil, baseOpts())
	if got.Evaluated || got.DelegationIndex != -1 || got.SubjectIndex != -1 {
		t.Fatalf("got %+v", got)
	}
}

func TestEvaluateHappyPathJSONLD(t *testing.T) {
	got := Evaluate(context.Background(), []vc.Credential{identityCred(), delegationCredJSONLD()}, parentHolder(), baseOpts())
	if !got.Authorized || !got.Linkage || !got.Invocation || !got.Capability || !got.NotRevoked || !got.Trusted {
		t.Fatalf("got %+v", got)
	}
	if got.DelegationIndex != 1 || got.SubjectIndex != 0 {
		t.Fatalf("indices = %d/%d", got.DelegationIndex, got.SubjectIndex)
	}
}

func TestEvaluateHappyPathSDJWT(t *testing.T) {
	identity := vc.Credential{
		Types: []string{"BirthCertificate"}, SubjectID: "urn:person:child-1", Issuer: "did:web:registry",
		Raw: map[string]any{"vct": "BirthCertificate", "iss": "did:web:registry", "sub": "urn:person:child-1"},
	}
	deleg := vc.Credential{
		Types: []string{"DelegationCredential"}, SubjectID: "did:example:parent", Issuer: "did:web:registry",
		Raw: map[string]any{
			"vct": "DelegationCredential", "iss": "did:web:registry", "sub": "did:example:parent",
			"delegation": map[string]any{
				"on_behalf_of": "urn:person:child-1", "delegate": "did:example:parent",
				"allowed_action": []any{"present"}, "valid_until": "2033-03-10T00:00:00Z",
			},
			"status": map[string]any{"status_list": map[string]any{"uri": "https://r/sl/1", "idx": float64(88231)}},
		},
	}
	var seen StatusRef
	opts := baseOpts()
	opts.Status = func(_ context.Context, ref StatusRef) (bool, error) { seen = ref; return false, nil }
	got := Evaluate(context.Background(), []vc.Credential{identity, deleg}, parentHolder(), opts)
	if !got.Authorized {
		t.Fatalf("got %+v", got)
	}
	if seen.Type != "TokenStatusList" || seen.Index != 88231 || seen.URI != "https://r/sl/1" {
		t.Fatalf("status ref = %+v", seen)
	}
	// Delegation as a JSON string claim (selective disclosure stringifies objects).
	deleg.Raw["delegation"] = `{"on_behalf_of":"urn:person:child-1","allowed_action":"present"}`
	if got := Evaluate(context.Background(), []vc.Credential{identity, deleg}, parentHolder(), opts); !got.Authorized {
		t.Fatalf("string delegation: %+v", got)
	}
}

func TestEvaluateUntrustedIssuerIsAdvisory(t *testing.T) {
	opts := baseOpts()
	opts.Trust = trustNone
	got := Evaluate(context.Background(), []vc.Credential{identityCred(), delegationCredJSONLD()}, parentHolder(), opts)
	if !got.Authorized || got.Trusted {
		t.Fatalf("got %+v", got)
	}
	opts.Trust = nil
	if got := Evaluate(context.Background(), []vc.Credential{identityCred(), delegationCredJSONLD()}, parentHolder(), opts); !got.Authorized || got.Trusted {
		t.Fatalf("nil trust: %+v", got)
	}
}

func TestEvaluateFailures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(creds []vc.Credential, opts *Options, holder **vc.HolderBinding)
		reason string
	}{
		{"linkage mismatch", func(c []vc.Credential, _ *Options, _ **vc.HolderBinding) {
			c[0].Raw["credentialSubject"].(map[string]any)["subjectRef"] = "urn:person:someone-else"
		}, "linkage failed"},
		{"empty onBehalfOf", func(c []vc.Credential, _ *Options, _ **vc.HolderBinding) {
			tou(c[1])["invocationTarget"] = ""
			c[1].Raw["credentialSubject"].(map[string]any)["onBehalfOf"] = map[string]any{}
		}, "linkage failed"},
		{"expired caveat", func(c []vc.Credential, _ *Options, _ **vc.HolderBinding) {
			tou(c[1])["caveat"] = []any{map[string]any{"validUntil": "2020-01-01T00:00:00Z"}}
		}, "delegation expired"},
		{"bad caveat", func(c []vc.Credential, _ *Options, _ **vc.HolderBinding) {
			tou(c[1])["caveat"] = []any{map[string]any{"validUntil": "soon"}}
		}, "not a valid timestamp"},
		{"action not allowed", func(_ []vc.Credential, o *Options, _ **vc.HolderBinding) {
			o.RequestedAction = "delete"
		}, "not permitted"},
		{"revoked", func(_ []vc.Credential, o *Options, _ **vc.HolderBinding) { o.Status = revoked }, "revoked"},
		{"controller not issuer", func(c []vc.Credential, _ *Options, _ **vc.HolderBinding) {
			tou(c[1])["controller"] = "did:web:attacker"
		}, "controller"},
		{"presenter not delegate", func(_ []vc.Credential, _ *Options, h **vc.HolderBinding) {
			*h = &vc.HolderBinding{ID: "did:example:imposter", Confirmed: true}
		}, "invocation failed"},
		{"presenter thumbprint not delegate", func(_ []vc.Credential, _ *Options, h **vc.HolderBinding) {
			*h = &vc.HolderBinding{KeyThumbprint: "abc", Confirmed: true}
		}, "invocation failed"},
		{"status unavailable fail-closed", func(_ []vc.Credential, o *Options, _ **vc.HolderBinding) {
			o.Status = statusErr
		}, "unavailable"},
		{"no status checker fail-closed", func(_ []vc.Credential, o *Options, _ **vc.HolderBinding) {
			o.Status = nil
		}, "no status checker"},
		{"chain rejected", func(c []vc.Credential, _ *Options, _ **vc.HolderBinding) {
			tou(c[1])["parentCapability"] = "urn:cap:root"
		}, "not allowed"},
		{"chain with further delegation", func(c []vc.Credential, _ *Options, _ **vc.HolderBinding) {
			tou(c[1])["parentCapability"] = "urn:cap:root"
			tou(c[1])["allowFurtherDelegation"] = true
		}, "not supported"},
		{"no delegate and no holder", func(c []vc.Credential, _ *Options, h **vc.HolderBinding) {
			c[1].SubjectID = ""
			delete(tou(c[1]), "delegate")
			*h = nil
		}, "names no delegate"},
		{"identity missing", func(c []vc.Credential, _ *Options, _ **vc.HolderBinding) {
			c[0] = c[1]
		}, "no subject identity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			creds := []vc.Credential{identityCred(), delegationCredJSONLD()}
			opts := baseOpts()
			holder := parentHolder()
			tc.mutate(creds, &opts, &holder)
			if tc.name == "identity missing" {
				creds = creds[1:]
			}
			got := Evaluate(context.Background(), creds, holder, opts)
			if got.Authorized || !got.Evaluated || !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestEvaluateFailOpenAndAnonymousHolder(t *testing.T) {
	creds := []vc.Credential{identityCred(), delegationCredJSONLD()}
	opts := baseOpts()
	opts.FailClosed = false
	opts.Status = statusErr
	if got := Evaluate(context.Background(), creds, parentHolder(), opts); !got.Authorized {
		t.Fatalf("fail-open with status error: %+v", got)
	}
	opts.Status = nil
	if got := Evaluate(context.Background(), creds, parentHolder(), opts); !got.Authorized {
		t.Fatalf("fail-open without checker: %+v", got)
	}
	// A confirmed but anonymous holder satisfies invocation when no delegate is named.
	deleg := delegationCredJSONLD()
	deleg.SubjectID = ""
	delete(tou(deleg), "delegate")
	got := Evaluate(context.Background(), []vc.Credential{identityCred(), deleg}, &vc.HolderBinding{Confirmed: true}, baseOpts())
	if !got.Authorized {
		t.Fatalf("anonymous holder: %+v", got)
	}
	// Unconfirmed holder with a named delegate is not checked for equality.
	got = Evaluate(context.Background(), creds, &vc.HolderBinding{ID: "did:example:other"}, baseOpts())
	if !got.Authorized {
		t.Fatalf("unconfirmed holder: %+v", got)
	}
	// Zero Now uses the wall clock.
	opts = baseOpts()
	opts.Now = time.Time{}
	if got := Evaluate(context.Background(), creds, parentHolder(), opts); !got.Authorized {
		t.Fatalf("wall clock: %+v", got)
	}
}

// Regression: legacy temporal_test.go (B7 fix).
func TestEvaluateTemporal(t *testing.T) {
	id := identityCred()
	id.Raw["validUntil"] = "2026-06-24T00:00:00Z"
	got := Evaluate(context.Background(), []vc.Credential{id, delegationCredJSONLD()}, parentHolder(), baseOpts())
	if got.Authorized || !strings.Contains(got.Reason, "expired") || got.Capability {
		t.Fatalf("expired: %+v", got)
	}
	deleg := delegationCredJSONLD()
	deleg.Raw["validFrom"] = "2026-07-01T00:00:00Z"
	got = Evaluate(context.Background(), []vc.Credential{identityCred(), deleg}, parentHolder(), baseOpts())
	if got.Authorized || !strings.Contains(got.Reason, "not yet valid") {
		t.Fatalf("not yet valid: %+v", got)
	}
	id = identityCred()
	id.Raw["validFrom"] = "2020-01-01T00:00:00Z"
	id.Raw["validUntil"] = "2030-01-01T00:00:00Z"
	if got := Evaluate(context.Background(), []vc.Credential{id, delegationCredJSONLD()}, parentHolder(), baseOpts()); !got.Authorized {
		t.Fatalf("within window: %+v", got)
	}
}

// Regression: legacy linkage_anchor_test.go.
func petCardSubject(fields map[string]string) vc.Credential {
	cs := map[string]any{"id": "did:key:zSubjectAbc"}
	claims := map[string]string{}
	for k, v := range fields {
		cs[k] = v
		claims[k] = v
	}
	return vc.Credential{
		Types: []string{"VerifiableCredential", "PetCard"}, SubjectID: "did:key:zSubjectAbc",
		Issuer: "did:web:registry", Claims: claims, Raw: map[string]any{"credentialSubject": cs},
	}
}

func delegOnBehalfOf(ref string) vc.Credential {
	return vc.Credential{
		Types: []string{"VerifiableCredential", "DelegatedAccessCredential"}, SubjectID: "did:example:parent",
		Issuer: "did:web:registry",
		Raw: map[string]any{
			"credentialSubject": map[string]any{"id": "did:example:parent", "onBehalfOf": map[string]any{"id": ref}},
			"termsOfUse": []any{map[string]any{
				"type": "DelegationCapability", "invocationTarget": ref,
				"delegate": "did:example:parent", "allowedAction": []any{"present"},
			}},
		},
	}
}

func TestEvaluateLinkage(t *testing.T) {
	cases := []struct {
		name   string
		fields map[string]string
		ref    string
		want   bool
	}{
		{"subjectRef match", map[string]string{"subjectRef": "urn:pet:bosco", "holderName": "Bosco"}, "urn:pet:bosco", true},
		{"DID match", map[string]string{"holderName": "Bosco"}, "did:key:zSubjectAbc", true},
		{"plain value denied", map[string]string{"holderName": "Johnte Dohnte", "holderId": "P-99"}, "Johnte Dohnte", false},
		{"identifier field match", map[string]string{"last_name": "Ndegwa", "testa_id": "33764103"}, "33764103", true},
		{"number suffix match", map[string]string{"passportNumber": "X1"}, "X1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			creds := []vc.Credential{petCardSubject(tc.fields), delegOnBehalfOf(tc.ref)}
			got := Evaluate(context.Background(), creds, parentHolder(), baseOpts())
			if got.Linkage != tc.want || got.Authorized != tc.want {
				t.Fatalf("got %+v", got)
			}
		})
	}
	// The identity whose anchor matches is chosen even when it is not first.
	other := petCardSubject(map[string]string{"subjectRef": "urn:pet:other"})
	creds := []vc.Credential{other, petCardSubject(map[string]string{"subjectRef": "urn:pet:bosco"}), delegOnBehalfOf("urn:pet:bosco")}
	got := Evaluate(context.Background(), creds, parentHolder(), baseOpts())
	if !got.Authorized || got.SubjectIndex != 1 || got.DelegationIndex != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestExtractCapabilityForms(t *testing.T) {
	flat := vc.Credential{
		Issuer: "did:web:i", SubjectID: "did:key:d",
		Claims: map[string]string{"allowedAction": "present, consent", "onBehalfOf": "urn:p", "validUntil": "2033-01-01"},
	}
	cap, ok := ExtractCapability(flat)
	if !ok || len(cap.AllowedAction) != 2 || cap.OnBehalfOf != "urn:p" || cap.Controller != "did:web:i" || cap.ValidUntil != "2033-01-01" {
		t.Fatalf("flat = %+v %v", cap, ok)
	}
	flatRaw := vc.Credential{Raw: map[string]any{"allowed_action": "present", "credentialSubject": map[string]any{"onBehalfOf": "urn:q"}}}
	if cap, ok := ExtractCapability(flatRaw); !ok || cap.OnBehalfOf != "urn:q" {
		t.Fatalf("flat raw = %+v %v", cap, ok)
	}
	none := vc.Credential{Raw: map[string]any{"termsOfUse": []any{map[string]any{"type": "Other"}, "x"}, "delegation": "not json"}}
	if _, ok := ExtractCapability(none); ok {
		t.Fatal("no capability expected")
	}
	single := vc.Credential{Raw: map[string]any{"termsOfUse": map[string]any{"type": []any{"DelegationCapability"}, "onBehalfOf": "urn:s", "validUntil": "2030-01-01", "allowFurtherDelegation": true}}}
	cap, ok = ExtractCapability(single)
	if !ok || cap.OnBehalfOf != "urn:s" || cap.ValidUntil != "2030-01-01" || !cap.AllowFurtherDelegation || cap.HasChain {
		t.Fatalf("single termsOfUse = %+v", cap)
	}
	sd := vc.Credential{Raw: map[string]any{"delegation": map[string]any{
		"onBehalfOf": "urn:c", "validUntil": "2031-01-01", "allowedAction": "present",
		"allowFurtherDelegation": true, "parent_capability": "urn:cap",
	}}}
	cap, ok = ExtractCapability(sd)
	if !ok || cap.OnBehalfOf != "urn:c" || cap.ValidUntil != "2031-01-01" || !cap.AllowFurtherDelegation || !cap.HasChain || cap.AllowedAction[0] != "present" {
		t.Fatalf("sd camel = %+v", cap)
	}
}

func TestStatusRefOf(t *testing.T) {
	flat := vc.Credential{Issuer: "i", Claims: map[string]string{"statusUri": "https://s", "statusIdx": "7", "statusType": "BitstringStatusListEntry"}}
	ref, ok := StatusRefOf(flat)
	if !ok || ref.Type != "BitstringStatusListEntry" || ref.Index != 7 || ref.Issuer != "i" {
		t.Fatalf("flat = %+v", ref)
	}
	tokenFlat := vc.Credential{Raw: map[string]any{"statusUri": "https://s"}}
	if ref, _ := StatusRefOf(tokenFlat); ref.Type != "TokenStatusList" || ref.Index != 0 {
		t.Fatalf("token flat = %+v", ref)
	}
	ld := vc.Credential{Raw: map[string]any{"credentialStatus": map[string]any{"statusListCredential": "https://l", "statusListIndex": float64(3)}}}
	if ref, _ := StatusRefOf(ld); ref.Type != "BitstringStatusListEntry" || ref.Index != 3 || ref.Purpose != "revocation" {
		t.Fatalf("ld = %+v", ref)
	}
	if _, ok := StatusRefOf(vc.Credential{Raw: map[string]any{"status": map[string]any{}}}); ok {
		t.Fatal("status without status_list must not match")
	}
	if _, ok := StatusRefOf(vc.Credential{}); ok {
		t.Fatal("empty must not match")
	}
	if mapInt(map[string]any{"i": true}, "i") != 0 {
		t.Fatal("mapInt non-number")
	}
}

func TestHelpers(t *testing.T) {
	if _, err := parseTime("nope"); err == nil {
		t.Fatal("parseTime")
	}
	if ts, err := parseTime("2030-01-02"); err != nil || ts.Year() != 2030 {
		t.Fatal("parseTime date")
	}
	if refID("x", "f") != "" || refID(map[string]any{"f": 1}, "f") != "" || refID(map[string]any{"f": "v"}, "f") != "v" {
		t.Fatal("refID")
	}
	if caveatValidUntil([]any{"x", map[string]any{}}) != "" {
		t.Fatal("caveatValidUntil")
	}
	if asSlice(1) != nil {
		t.Fatal("asSlice")
	}
	if _, ok := asMapOrJSON("null"); ok {
		t.Fatal("asMapOrJSON null")
	}
	if _, ok := asMapOrJSON(1); ok {
		t.Fatal("asMapOrJSON int")
	}
	if mapStrSlice(map[string]any{}, "a") != nil {
		t.Fatal("mapStrSlice")
	}
	if !isIdentifierFieldName("UIN") || isIdentifierFieldName("given_name") {
		t.Fatal("isIdentifierFieldName")
	}
	if subjectAnchor(vc.Credential{Raw: map[string]any{"subjectRef": "r"}}) != "r" {
		t.Fatal("subjectAnchor raw")
	}
	if subjectAnchor(vc.Credential{Claims: map[string]string{"subjectRef": "c"}}) != "c" {
		t.Fatal("subjectAnchor claims")
	}
}

// Regression: legacy TestBuildAndEvaluate_RoundTrip.
func TestBuildAndEvaluateRoundTrip(t *testing.T) {
	const (
		ctxURL   = "https://verifiably.test/static/contexts/delegated-access-v1.jsonld"
		issuer   = "did:web:registry"
		childRef = "urn:person:child-1"
		parent   = "did:example:parent"
		until    = "2033-03-10T00:00:00Z"
	)
	delegStatus := &StatusEntry{PublishURL: "https://registry.example/status/1", Index: 5}
	birth := BuildSubjectCredential(SubjectSpec{
		ContextURL: ctxURL, Issuer: issuer, SubjectDID: "did:example:child", SubjectRef: childRef,
		Type: "BirthCertificate", Claims: map[string]string{"givenName": "Maria"}, ValidUntil: until,
		Status: &StatusEntry{PublishURL: "https://registry.example/status/0", Index: 1},
	})
	deleg := BuildDelegationCredential(DelegationSpec{
		ContextURL: ctxURL, Issuer: issuer, DelegateID: parent, OnBehalfOf: childRef, Role: "Mother",
		AllowedAction: []string{"present", "consent:disclose"}, ValidUntil: until, Status: delegStatus, Type: "PowerOfAttorney",
	})
	if deleg["type"].([]string)[2] != "PowerOfAttorney" || deleg["validUntil"] != until {
		t.Fatalf("deleg = %v", deleg)
	}
	creds := []vc.Credential{vc.FromObject(birth), vc.FromObject(deleg)}
	holder := &vc.HolderBinding{ID: parent, Confirmed: true}
	if subjectAnchor(creds[0]) != childRef {
		t.Fatalf("anchor = %q", subjectAnchor(creds[0]))
	}
	ok := Evaluate(context.Background(), creds, holder, Options{Now: fixedNow, RequestedAction: "present", Status: notRevoked, Trust: trustAll, FailClosed: true})
	if !ok.Authorized {
		t.Fatalf("expected authorised, got %+v", ok)
	}
	denied := Evaluate(context.Background(), creds, holder, Options{
		Now: fixedNow, RequestedAction: "present", FailClosed: true, Trust: trustAll,
		Status: func(_ context.Context, ref StatusRef) (bool, error) {
			return ref.Index == int64(delegStatus.Index), nil
		},
	})
	if denied.Authorized || denied.NotRevoked {
		t.Fatalf("expected denial, got %+v", denied)
	}
}

func TestBuildVariants(t *testing.T) {
	v1 := BuildSubjectCredential(SubjectSpec{DataModel: vc.ModelVCDM1, ValidFrom: "2020-01-01T00:00:00Z", ValidUntil: "2030-01-01T00:00:00Z"})
	if v1["@context"].([]string)[0] != ContextVCDM1 || v1["issuanceDate"] != "2020-01-01T00:00:00Z" || v1["expirationDate"] != "2030-01-01T00:00:00Z" {
		t.Fatalf("v1 = %v", v1)
	}
	if v1["type"].([]string)[1] != "IdentityCredential" {
		t.Fatalf("default type: %v", v1["type"])
	}
	if _, ok := v1["issuer"]; ok {
		t.Fatal("issuer must be omitted when empty")
	}
	d := BuildDelegationCredential(DelegationSpec{OnBehalfOf: "urn:x", Type: "DelegatedAccessCredential", ValidFrom: "2020-01-01T00:00:00Z"})
	if len(d["type"].([]string)) != 2 || d["validFrom"] != "2020-01-01T00:00:00Z" {
		t.Fatalf("d = %v", d)
	}
	capability := d["termsOfUse"].([]any)[0].(map[string]any)
	for _, k := range []string{"delegate", "controller", "allowedAction", "caveat"} {
		if _, ok := capability[k]; ok {
			t.Fatalf("%s must be omitted", k)
		}
	}
	sc := SubjectClaims(SubjectSpec{SubjectRef: "urn:s", Claims: map[string]string{"a": "b"}})
	if sc["subjectRef"] != "urn:s" || sc["a"] != "b" || len(SubjectClaims(SubjectSpec{})) != 0 {
		t.Fatalf("SubjectClaims = %v", sc)
	}
	dc := DelegationClaims(DelegationSpec{OnBehalfOf: "urn:s", Role: "Mother", DelegateID: "did:d", Issuer: "did:i", AllowedAction: []string{"present"}, ValidUntil: "2033-01-01T00:00:00Z"})
	if dc["role"] != "Mother" || dc["onBehalfOf"] != "urn:s" {
		t.Fatalf("DelegationClaims = %v", dc)
	}
	cred := vc.Credential{Issuer: "did:i", SubjectID: "did:d", Raw: map[string]any{"delegation": dc["delegation"]}}
	cap, ok := ExtractCapability(cred)
	if !ok || cap.Controller != "did:i" || cap.Delegate != "did:d" || cap.ValidUntil != "2033-01-01T00:00:00Z" || cap.AllowedAction[0] != "present" {
		t.Fatalf("round trip capability = %+v", cap)
	}
	minimal := DelegationClaims(DelegationSpec{OnBehalfOf: "urn:s"})
	if _, ok := minimal["role"]; ok || !strings.Contains(minimal["delegation"], "on_behalf_of") {
		t.Fatalf("minimal = %v", minimal)
	}
}

func FuzzParseCapability(f *testing.F) {
	f.Add([]byte(`{"delegation":{"on_behalf_of":"urn:p","allowed_action":["present"]}}`))
	f.Add([]byte(`{"termsOfUse":[{"type":"DelegationCapability","invocationTarget":"urn:p"}],"credentialStatus":{"statusListIndex":"3"}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var raw map[string]any
		if json.Unmarshal(data, &raw) != nil {
			return
		}
		c := vc.FromObject(raw)
		_, _ = ExtractCapability(c)
		_, _ = StatusRefOf(c)
		_ = Evaluate(context.Background(), []vc.Credential{identityCred(), c}, parentHolder(), baseOpts())
	})
}
