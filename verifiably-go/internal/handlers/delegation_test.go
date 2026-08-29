package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/delegation"
	"github.com/verifiably/verifiably-go/internal/statuslist"
	"github.com/verifiably/verifiably-go/internal/statuslistcache"
	"github.com/verifiably/verifiably-go/internal/trust"
	"github.com/verifiably/verifiably-go/vctypes"
)

// delegStatusCache is a status-list cache fake that can fail or serve any raw doc.
type delegStatusCache struct {
	raw   string
	err   error
	calls int
}

func (f *delegStatusCache) Fetch(_ context.Context, _, _ string) (statuslistcache.Result, error) {
	f.calls++
	if f.err != nil {
		return statuslistcache.Result{}, f.err
	}
	return statuslistcache.Result{RawJWT: f.raw, Source: "live"}, nil
}

// delegTrustRegistry trusts every issuer; only IsTrusted is reached here.
type delegTrustRegistry struct{ calls int }

func (r *delegTrustRegistry) IsTrusted(_ context.Context, _, _ string) error { r.calls++; return nil }
func (r *delegTrustRegistry) TrustedIssuers(context.Context) ([]trust.TrustedIssuer, error) {
	return nil, nil
}
func (r *delegTrustRegistry) Add(context.Context, trust.TrustedIssuer) error { return nil }
func (r *delegTrustRegistry) Remove(context.Context, string) error           { return nil }

// delegPair returns a subject identity credential + a JSON-LD delegation
// credential about it (termsOfUse DelegationCapability), with the delegation
// carrying a bitstring status reference at index idx.
func delegPair(idx int) []backend.NormalizedCredential {
	subject := backend.NormalizedCredential{
		Types: []string{"VerifiableCredential", "Person"}, Issuer: "did:web:issuer.example", Format: "w3c_vcdm_2",
		Claims: map[string]string{"subjectRef": "urn:person:1"},
		Raw:    map[string]any{"credentialSubject": map[string]any{"subjectRef": "urn:person:1"}},
	}
	deleg := backend.NormalizedCredential{
		Types: []string{"VerifiableCredential", "DelegatedAccessCredential"}, Issuer: "did:web:issuer.example", Format: "w3c_vcdm_2",
		SubjectID: "did:example:delegate",
		Claims:    map[string]string{"onBehalfOf": "urn:person:1"},
		Raw: map[string]any{
			"credentialSubject": map[string]any{"id": "did:example:delegate", "onBehalfOf": "urn:person:1"},
			"termsOfUse": []any{map[string]any{
				"type": "DelegationCapability", "controller": "did:web:issuer.example",
				"onBehalfOf": "urn:person:1", "delegate": "did:example:delegate", "allowedAction": []any{"present"},
			}},
			"credentialStatus": map[string]any{
				"type": "BitstringStatusListEntry", "statusListCredential": "https://issuer.example/status/1",
				"statusListIndex": float64(idx),
			},
		},
	}
	return []backend.NormalizedCredential{subject, deleg}
}

func delegBitstringDoc(t *testing.T, revokedIdx int) string {
	t.Helper()
	return `{"credentialSubject":{"type":"BitstringStatusList","encodedList":"` + encodedListWithBit(t, revokedIdx) + `"}}`
}

func delegTokenListDoc(t *testing.T, revokedIdx int) string {
	t.Helper()
	bs := statuslist.NewIETF(statuslist.DefaultBits)
	if err := bs.Set(revokedIdx, true); err != nil {
		t.Fatal(err)
	}
	lst, err := bs.EncodeZlibBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	return `{"status_list":{"lst":"` + lst + `"}}`
}

func delegJWS(payload string) string {
	return "eyJhbGciOiJFUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
}

func TestAttachDelegationVerdict_NoopWithoutCredentials(t *testing.T) {
	h := &H{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	h.attachDelegationVerdict(r, nil)
	res := &backend.VerificationResult{Valid: true}
	h.attachDelegationVerdict(r, res)
	if !res.Valid || res.Delegation != nil || res.CredentialViews != nil {
		t.Errorf("empty result must be untouched: %+v", res)
	}
}

func TestAttachDelegationVerdict_AuthorisedPairBuildsViews(t *testing.T) {
	cache := &delegStatusCache{raw: delegBitstringDoc(t, 9)} // idx 3 not revoked
	reg := &delegTrustRegistry{}
	ad := &testAdapter{schemas: []vctypes.Schema{{ID: "da-person", Name: "Person Card", AdditionalTypes: []string{"Person"}}}}
	h := &H{Adapter: ad, StatusListCache: cache, TrustRegistry: reg}
	res := &backend.VerificationResult{Valid: true, Method: "OID4VP", Credentials: delegPair(3),
		HolderBinding: &backend.HolderBinding{ID: "did:example:delegate", Confirmed: true}}
	h.attachDelegationVerdict(httptest.NewRequest(http.MethodGet, "/", nil), res)

	if res.Delegation == nil || !res.Delegation.Evaluated {
		t.Fatalf("delegation not evaluated: %+v", res.Delegation)
	}
	if !res.Delegation.Authorized || !res.Valid {
		t.Errorf("expected authorised pair, got %+v (method=%q)", res.Delegation, res.Method)
	}
	if reg.calls == 0 {
		t.Error("trust registry must be consulted when configured")
	}
	if !res.CheckedRevocation {
		t.Error("CheckedRevocation must be set once a status list resolved")
	}
	if len(res.CredentialViews) != 2 || res.CredentialViews[0].Role != "subject" || res.CredentialViews[1].Role != "delegation" {
		t.Fatalf("views = %+v", res.CredentialViews)
	}
	if checkStatus(res.CredentialViews[1], "Not revoked") != "pass" || checkStatus(res.CredentialViews[1], "Capability") != "pass" {
		t.Errorf("delegation card checks = %+v", res.CredentialViews[1].Checks)
	}
}

func TestAttachDelegationVerdict_DeniedAppendsReason(t *testing.T) {
	// No status cache: FailClosed evaluator denies (status cannot be checked).
	for _, method := range []string{"", "OID4VP"} {
		h := &H{}
		res := &backend.VerificationResult{Valid: true, Method: method, Credentials: delegPair(3),
			HolderBinding: &backend.HolderBinding{ID: "did:example:delegate", Confirmed: true}}
		h.attachDelegationVerdict(httptest.NewRequest(http.MethodGet, "/", nil), res)
		if res.Delegation == nil || !res.Delegation.Evaluated || res.Delegation.Authorized {
			t.Fatalf("method=%q: expected evaluated+denied, got %+v", method, res.Delegation)
		}
		if res.Valid {
			t.Errorf("method=%q: Valid must be downgraded", method)
		}
		want := "delegation: " + res.Delegation.Reason
		if method != "" {
			want = method + " · " + want
		}
		if res.Method != want {
			t.Errorf("method=%q: Method = %q, want %q", method, res.Method, want)
		}
		if checkStatus(res.CredentialViews[1], "Not revoked") != "na" {
			t.Errorf("no cache: revocation check should be na, got %+v", res.CredentialViews[1].Checks)
		}
	}
}

func TestPresentedSchemasSafe(t *testing.T) {
	if got := (&H{}).presentedSchemasSafe(context.Background()); got != nil {
		t.Errorf("nil adapter: got %v", got)
	}
	if got := (&H{Adapter: &testAdapter{schemasErr: errors.New("down")}}).presentedSchemasSafe(context.Background()); got != nil {
		t.Errorf("adapter error: got %v", got)
	}
	want := []vctypes.Schema{{ID: "a"}}
	if got := (&H{Adapter: &testAdapter{schemas: want}}).presentedSchemasSafe(context.Background()); len(got) != 1 || got[0].ID != "a" {
		t.Errorf("got %v", got)
	}
}

func TestBuildDelegationCredentialViews_SingleCredentialKeepsFlatCard(t *testing.T) {
	res := &backend.VerificationResult{Credentials: delegPair(1)[:1]}
	(&H{}).buildDelegationCredentialViews(context.Background(), res, nil)
	if res.CredentialViews != nil {
		t.Errorf("single credential must not produce views: %+v", res.CredentialViews)
	}
	(&H{}).buildDelegationCredentialViews(context.Background(), nil, nil) // nil-safe
}

func TestCredTemporalCheck(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(from, until string) backend.NormalizedCredential {
		raw := map[string]any{}
		if from != "" {
			raw["validFrom"] = from
		}
		if until != "" {
			raw["validUntil"] = until
		}
		return backend.NormalizedCredential{Raw: raw}
	}
	cases := []struct {
		name       string
		c          backend.NormalizedCredential
		status     string
		noteSubstr string
	}{
		{"not yet valid", mk("2031-01-01T00:00:00Z", ""), "fail", "not yet valid (from 2031-01-01T00:00:00Z)"},
		{"expired", mk("", "2029-01-01T00:00:00Z"), "fail", "expired (2029-01-01T00:00:00Z)"},
		{"no window", mk("", ""), "pass", "does not expire"},
		{"within", mk("2029-01-01T00:00:00Z", "2031-01-01T00:00:00Z"), "pass", "within its validity window"},
	}
	for _, c := range cases {
		got := credTemporalCheck(c.c, now)
		if got.Label != "Within validity" || got.Status != c.status || !strings.Contains(got.Note, c.noteSubstr) {
			t.Errorf("%s: got %+v", c.name, got)
		}
	}
}

func TestCredRevocationCheck(t *testing.T) {
	withRef := delegPair(3)[1]
	noRef := delegPair(3)[0]
	ctx := context.Background()

	if got := (&H{}).credRevocationCheck(ctx, noRef); got.Status != "na" || got.Note != "carries no status list" {
		t.Errorf("no ref: %+v", got)
	}
	if got := (&H{}).credRevocationCheck(ctx, withRef); got.Status != "na" || got.Note != "status list not checked" {
		t.Errorf("no cache: %+v", got)
	}
	h := &H{StatusListCache: &delegStatusCache{err: errors.New("offline")}}
	if got := h.credRevocationCheck(ctx, withRef); got.Status != "na" || !strings.Contains(got.Note, "status could not be checked: status-list fetch: offline") {
		t.Errorf("fetch error: %+v", got)
	}
	h = &H{StatusListCache: &delegStatusCache{raw: delegBitstringDoc(t, 3)}}
	if got := h.credRevocationCheck(ctx, withRef); got.Status != "fail" || got.Note != "revoked on the issuer's status list" {
		t.Errorf("revoked: %+v", got)
	}
	h = &H{StatusListCache: &delegStatusCache{raw: delegBitstringDoc(t, 4)}}
	if got := h.credRevocationCheck(ctx, withRef); got.Status != "pass" || got.Note != "not revoked on the issuer's status list" {
		t.Errorf("not revoked: %+v", got)
	}
}

func TestDelegCheck(t *testing.T) {
	if got := delegCheck("Linkage", true, "n"); got != (backend.CredCheck{Label: "Linkage", Status: "pass", Note: "n"}) {
		t.Errorf("pass: %+v", got)
	}
	if got := delegCheck("Linkage", false, "n"); got != (backend.CredCheck{Label: "Linkage", Status: "fail", Note: "n"}) {
		t.Errorf("fail: %+v", got)
	}
}

func TestAttachRevocationVerdict(t *testing.T) {
	ctx := context.Background()
	// No cache / nil / empty: untouched.
	(&H{}).attachRevocationVerdict(ctx, nil)
	res := &backend.VerificationResult{Valid: true, Credentials: delegPair(3)}
	(&H{}).attachRevocationVerdict(ctx, res)
	if !res.Valid || res.CheckedRevocation {
		t.Errorf("no cache: %+v", res)
	}

	// Only credentials without a status ref: nothing resolved.
	cache := &delegStatusCache{raw: delegBitstringDoc(t, 3)}
	res = &backend.VerificationResult{Valid: true, Credentials: delegPair(3)[:1]}
	(&H{StatusListCache: cache}).attachRevocationVerdict(ctx, res)
	if !res.Valid || res.CheckedRevocation || cache.calls != 0 {
		t.Errorf("no refs: %+v calls=%d", res, cache.calls)
	}

	// Fetch error: fail closed.
	res = &backend.VerificationResult{Valid: true, Method: "m", Credentials: delegPair(3)}
	(&H{StatusListCache: &delegStatusCache{err: errors.New("offline")}}).attachRevocationVerdict(ctx, res)
	if res.Valid || res.Method != "m · revocation status could not be checked (status-list fetch: offline)" {
		t.Errorf("fetch error: %+v", res)
	}

	// Revoked bit set.
	res = &backend.VerificationResult{Valid: true, Credentials: delegPair(3)}
	(&H{StatusListCache: cache}).attachRevocationVerdict(ctx, res)
	if res.Valid || res.Method != "a presented credential has been revoked" {
		t.Errorf("revoked: %+v", res)
	}

	// Not revoked: Valid stays, CheckedRevocation becomes truthful.
	res = &backend.VerificationResult{Valid: true, Credentials: delegPair(7)}
	(&H{StatusListCache: cache}).attachRevocationVerdict(ctx, res)
	if !res.Valid || !res.CheckedRevocation || res.Method != "" {
		t.Errorf("not revoked: %+v", res)
	}
}

func TestRevocationDowngrade(t *testing.T) {
	res := &backend.VerificationResult{Valid: true}
	revocationDowngrade(res, "why")
	if res.Valid || res.Method != "why" {
		t.Errorf("empty method: %+v", res)
	}
	res = &backend.VerificationResult{Valid: true, Method: "OID4VP"}
	revocationDowngrade(res, "why")
	if res.Method != "OID4VP · why" {
		t.Errorf("appended method: %q", res.Method)
	}
}

func TestDelegationStatusChecker(t *testing.T) {
	ctx := context.Background()
	ref := delegation.StatusRef{Type: "BitstringStatusListEntry", URI: "https://issuer.example/status/1", Index: 3, Issuer: "did:web:issuer.example"}

	_, err := (&H{}).delegationStatusChecker()(ctx, ref)
	if err == nil || !strings.Contains(err.Error(), "no status-list cache configured") {
		t.Errorf("nil cache: %v", err)
	}
	cache := &delegStatusCache{raw: delegBitstringDoc(t, 3)}
	_, err = (&H{StatusListCache: cache}).delegationStatusChecker()(ctx, delegation.StatusRef{})
	if err == nil || !strings.Contains(err.Error(), "carries no status-list URL") || cache.calls != 0 {
		t.Errorf("empty URI: %v (calls=%d)", err, cache.calls)
	}
	_, err = (&H{StatusListCache: &delegStatusCache{err: errors.New("offline")}}).delegationStatusChecker()(ctx, ref)
	if err == nil || err.Error() != "status-list fetch: offline" {
		t.Errorf("fetch error: %v", err)
	}
	_, err = (&H{StatusListCache: &delegStatusCache{}}).delegationStatusChecker()(ctx, ref)
	if err == nil || !strings.Contains(err.Error(), "status-list unavailable for https://issuer.example/status/1") {
		t.Errorf("empty RawJWT: %v", err)
	}
	revoked, err := (&H{StatusListCache: cache}).delegationStatusChecker()(ctx, ref)
	if err != nil || !revoked {
		t.Errorf("revoked bit: %v %v", revoked, err)
	}
}

func TestStatusBitRevoked(t *testing.T) {
	bitRef := delegation.StatusRef{Type: "BitstringStatusListEntry", Index: 5}
	tokRef := delegation.StatusRef{Type: "TokenStatusList", Index: 5}

	if _, err := statusBitRevoked("not.a.jwt", bitRef); err == nil {
		t.Error("claims parse error must propagate")
	}
	// Token status list.
	if _, err := statusBitRevoked(`{"status_list":{}}`, tokRef); err == nil || !strings.Contains(err.Error(), "missing lst") {
		t.Errorf("missing lst: %v", err)
	}
	if _, err := statusBitRevoked(`{"status_list":{"lst":"!!!"}}`, tokRef); err == nil {
		t.Error("undecodable lst must fail")
	}
	if r, err := statusBitRevoked(delegTokenListDoc(t, 5), tokRef); err != nil || !r {
		t.Errorf("token revoked: %v %v", r, err)
	}
	if r, err := statusBitRevoked(delegJWS(delegTokenListDoc(t, 5)), delegation.StatusRef{Type: "tokenstatuslist", Index: 6}); err != nil || r {
		t.Errorf("token not revoked (JWS form, case-insensitive type): %v %v", r, err)
	}
	// W3C bitstring: nested vc (JWT-VC form) and bare JSON-LD form.
	if _, err := statusBitRevoked(`{"vc":{"credentialSubject":{}}}`, bitRef); err == nil || !strings.Contains(err.Error(), "missing encodedList") {
		t.Errorf("missing encodedList: %v", err)
	}
	if _, err := statusBitRevoked(`{"credentialSubject":{"encodedList":"u!!!"}}`, bitRef); err == nil {
		t.Error("undecodable encodedList must fail")
	}
	if r, err := statusBitRevoked(delegJWS(`{"vc":`+delegBitstringDoc(t, 5)+`}`), bitRef); err != nil || !r {
		t.Errorf("nested vc revoked: %v %v", r, err)
	}
	if r, err := statusBitRevoked(delegBitstringDoc(t, 4), bitRef); err != nil || r {
		t.Errorf("bare not revoked: %v %v", r, err)
	}
}

func TestStatusListClaimsAndJWTPayloadClaims(t *testing.T) {
	if m, err := statusListClaims(`  {"a":1} `); err != nil || m["a"] != float64(1) {
		t.Errorf("bare JSON: %v %v", m, err)
	}
	if _, err := statusListClaims(`{bad`); err == nil || !strings.Contains(err.Error(), "status-list JSON") {
		t.Errorf("bad JSON: %v", err)
	}
	if m, err := statusListClaims(delegJWS(`{"iss":"x"}`)); err != nil || m["iss"] != "x" {
		t.Errorf("JWS: %v %v", m, err)
	}
	if _, err := jwtPayloadClaims("onlyonepart"); err == nil || err.Error() != "malformed status-list JWT" {
		t.Errorf("one part: %v", err)
	}
	if _, err := jwtPayloadClaims("h.!!!.s"); err == nil || !strings.Contains(err.Error(), "status-list JWT payload:") {
		t.Errorf("bad base64: %v", err)
	}
	if _, err := jwtPayloadClaims("h." + base64.RawURLEncoding.EncodeToString([]byte("{nope")) + ".s"); err == nil || !strings.Contains(err.Error(), "payload JSON") {
		t.Errorf("bad payload JSON: %v", err)
	}
}
