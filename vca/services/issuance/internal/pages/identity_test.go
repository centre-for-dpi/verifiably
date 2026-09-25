// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// allIdentity are the three identity features of an adapter.
var allIdentity = []backendv1.Feature{
	backendv1.Feature_FEATURE_ISSUER_IDENTITY_PROVISION,
	backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_DID,
	backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_X509,
}

// didKey is a did:key of an Ed25519 key.
const didKey = "did:key:z6MknMPNnbfMgsLj4nSUib4BjiPuvbZ4o7SRwQGcDU1nT9js"

// keyRef is a key reference into an external key store.
const keyRef = `{"type":"tse","server":"http://vault:8200/v1/transit","id":"issuer-key"}`

// form returns the form with the synchronizer token of the session.
func form(values map[string]string) url.Values {
	out := url.Values{staffsession.Field: {session.CSRF}}
	for k, v := range values {
		out.Set(k, v)
	}
	return out
}

func TestIdentityPageOneClick(t *testing.T) {
	h := newHarness(t, allIdentity...)
	doc := body(t, h.get(t, "/identity/"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		"Not registered", "Issuing stays locked until an identity exists.", "Start instantly", "Set up instantly",
		`<option value="did:web" selected>did:web</option>`, `<option value="Ed25519" selected>Ed25519</option>`,
		"Register with the trust registry and request a trust list entry.", "The stack keeps the key.",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	// The key never sits in a VCA store (ADR-001 decision 3).
	if strings.Contains(doc, "secret store") || strings.Contains(doc, "VCA keeps") {
		t.Error("the page says VCA keeps the key")
	}
	rec := h.post(t, "/identity/provision", form(map[string]string{"method": "did:web", "key_type": "Ed25519", "trust": "yes"}))
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "notice=registered") {
		t.Fatalf("status %d location %q body %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if len(h.identity.provision) != 1 {
		t.Fatalf("provision calls %d", len(h.identity.provision))
	}
	got := h.identity.provision[0]
	if got.GetMethod() != "did:web" || got.GetKeyType() != "Ed25519" || got.GetDomain() != "issuer-waltid.labs.example" {
		t.Fatalf("provision = %+v", got)
	}
	// The result shows the identifier and the pending entry.
	doc = body(t, h.get(t, rec.Header().Get("Location")))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{"did:web:issuer-waltid.labs.example", "Waiting for review", "Registered", "An admin approves it."} {
		if !strings.Contains(doc, want) {
			t.Errorf("the result lacks %q", want)
		}
	}
	// The identity page writes an audit event that names the staff member.
	page, err := h.audit.Query(context.Background(), auditlog.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]string{}
	for _, r := range page.Records {
		actions[r.Action] = r.Actor
	}
	if len(page.Records) != 2 || actions["issuance.ProvisionIdentity"] != session.Subject || actions["issuance.RequestTrustEntry"] != session.Subject {
		t.Fatalf("audit = %+v", page.Records)
	}
}

func TestIdentityPageRequestsTrustEntry(t *testing.T) {
	h := newHarness(t, allIdentity...)
	rec := h.post(t, "/identity/provision", form(map[string]string{"method": "did:key", "key_type": "Ed25519", "trust": "yes"}))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
	e := h.trust.entries[didKey]
	if e == nil || e.GetStatus() != trustv1.Status_STATUS_PENDING || e.GetRole() != commonv1.Role_ROLE_ISSUER ||
		e.GetServiceEndpoint() != "https://issuer-waltid.labs.example" {
		t.Fatalf("trust entry = %+v", e)
	}
	if len(h.trust.actors) != 1 || h.trust.actors[0] != session.Subject {
		t.Fatalf("trust actors = %v", h.trust.actors)
	}
	// An entry an admin approved stays approved.
	e.Status = trustv1.Status_STATUS_ACTIVE
	rec = h.post(t, "/identity/import", form(map[string]string{
		"kind": "did", "did": didKey, "key_reference": keyRef, "trust": "yes", "action": "register",
	}))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if h.trust.entries[didKey].GetStatus() != trustv1.Status_STATUS_ACTIVE || len(h.trust.actors) != 1 {
		t.Fatal("the page downgraded an approved entry")
	}
	doc := body(t, h.get(t, "/identity/"))
	if !strings.Contains(doc, "On the trust list") {
		t.Error("the page does not show the approved entry")
	}
	// Without the box, the page asks the registry for nothing.
	delete(h.trust.entries, didKey)
	h.post(t, "/identity/provision", form(map[string]string{"method": "did:key", "key_type": "Ed25519"}))
	if len(h.trust.entries) != 0 {
		t.Fatal("the page asked for an entry without the box")
	}
	// A registry that fails names the gap and keeps the identity.
	h.trust.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	rec = h.post(t, "/identity/provision", form(map[string]string{"method": "did:key", "key_type": "Ed25519", "trust": "yes"}))
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "trust_failed") {
		t.Fatalf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	doc = body(t, h.get(t, rec.Header().Get("Location")))
	if !strings.Contains(doc, "Ask an admin to add") {
		t.Error("the failure is not named")
	}
}

func TestIdentityPageImportDid(t *testing.T) {
	h := newHarness(t, allIdentity...)
	doc := body(t, h.get(t, "/identity/?kind=did"))
	for _, want := range []string{"Bring your own", `aria-label="Identity kind"`, "PKI (X.509)", "Key reference", "Organisation name", "Legal identifier"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	// Check resolves a did:key offline and calls no stack.
	rec := h.post(t, "/identity/import", form(map[string]string{"kind": "did", "did": didKey, "key_reference": keyRef, "action": "check"}))
	doc = body(t, rec)
	a11ytest.AssertPage(t, doc)
	if !strings.Contains(doc, "resolves") || len(h.identity.imports) != 0 {
		t.Fatalf("check: imports %d\n%s", len(h.identity.imports), doc)
	}
	// A broken did:key and a missing key reference are named at their fields.
	rec = h.post(t, "/identity/import", form(map[string]string{"kind": "did", "did": "did:key:zBroken", "action": "register"}))
	doc = body(t, rec)
	if !strings.Contains(doc, "The DID does not resolve.") || !strings.Contains(doc, "Type the key reference as a JSON object.") ||
		len(h.identity.imports) != 0 {
		t.Fatalf("errors missing\n%s", doc)
	}
	a11ytest.AssertPage(t, doc)
	rec = h.post(t, "/identity/import", form(map[string]string{"kind": "did", "did": "issuer.example", "key_reference": keyRef}))
	if doc = body(t, rec); !strings.Contains(doc, "Type a DID, such as did:web:issuer.example.") {
		t.Fatal("a value that is no DID passed")
	}
	// Register imports the DID with the metadata.
	rec = h.post(t, "/identity/import", form(map[string]string{
		"kind": "did", "did": "did:web:issuer-one.labs.example", "key_reference": keyRef,
		"display_name": "Ministry of Agriculture", "legal_identifier": "KE-GOV-017", "action": "register",
	}))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	got := h.identity.imports[0]
	if got.GetDid() != "did:web:issuer-one.labs.example" || got.GetKeyReference() != keyRef ||
		got.GetDisplayName() != "Ministry of Agriculture" || got.GetLegalIdentifier() != "KE-GOV-017" {
		t.Fatalf("import = %+v", got)
	}
	doc = body(t, h.get(t, "/identity/"))
	for _, want := range []string{"did:web:issuer-one.labs.example", "Ministry of Agriculture", "KE-GOV-017"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the status lacks %q", want)
		}
	}
}

// chainPEM returns one self signed certificate in PEM.
func chainPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Issuer One", Organization: []string{"Ministry of Agriculture"}, Country: []string{"KE"}},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestIdentityPageImportX509(t *testing.T) {
	h := newHarness(t, allIdentity...)
	doc := body(t, h.get(t, "/identity/?kind=x509"))
	a11ytest.AssertPage(t, doc)
	if !strings.Contains(doc, "Certificate chain (PEM)") || !strings.Contains(doc, `href="/identity/?kind=x509#own" aria-current="page"`) {
		t.Fatalf("the X.509 tab is not open\n%s", doc)
	}
	chain := chainPEM(t)
	doc = body(t, h.post(t, "/identity/import", form(map[string]string{"kind": "x509", "chain": chain, "key_reference": keyRef, "action": "check"})))
	if !strings.Contains(doc, "CN=Issuer One") {
		t.Fatalf("check does not name the leaf\n%s", doc)
	}
	doc = body(t, h.post(t, "/identity/import", form(map[string]string{"kind": "x509", "chain": "nothing", "key_reference": keyRef})))
	if !strings.Contains(doc, "Paste at least one PEM certificate.") {
		t.Fatal("a chain without a certificate passed")
	}
	rec := h.post(t, "/identity/import", form(map[string]string{"kind": "x509", "chain": chain, "key_reference": keyRef, "trust": "yes", "action": "register"}))
	if rec.Code != http.StatusSeeOther || h.identity.imports[0].GetX509ChainPem() != chain {
		t.Fatalf("status %d imports %v", rec.Code, h.identity.imports)
	}
	if e := h.trust.entries["CN=Issuer One,O=Ministry of Agriculture,C=KE"]; e == nil || e.GetStatus() != trustv1.Status_STATUS_PENDING {
		t.Fatalf("x509 trust entry = %+v", e)
	}
}

func TestIdentityPageHidesUnsupportedMethods(t *testing.T) {
	h := newHarness(t, backendv1.Feature_FEATURE_ISSUER_IDENTITY_PROVISION)
	h.caps.caps.DidMethods = []string{"did:key"}
	h.build(t)
	doc := body(t, h.get(t, "/identity/"))
	if strings.Contains(doc, `value="did:web"`) || !strings.Contains(doc, `<option value="did:key" selected>did:key</option>`) {
		t.Errorf("the method list is wrong\n%s", doc)
	}
	// No import feature: no bring your own section.
	if strings.Contains(doc, "Bring your own") {
		t.Error("the page offers an import the stack lacks")
	}
	// A method the stack lacks is refused before any call.
	rec := h.post(t, "/identity/provision", form(map[string]string{"method": "did:web", "key_type": "Ed25519"}))
	if doc = body(t, rec); !strings.Contains(doc, "Pick a method this stack offers.") || len(h.identity.provision) != 0 {
		t.Fatal("a method the stack lacks passed")
	}
	// One import kind gives no tabs.
	h = newHarness(t, backendv1.Feature_FEATURE_ISSUER_IDENTITY_IMPORT_DID)
	doc = body(t, h.get(t, "/identity/"))
	if strings.Contains(doc, "Start instantly") || strings.Contains(doc, `aria-label="Identity kind"`) || !strings.Contains(doc, "Key reference") {
		t.Errorf("one import kind\n%s", doc)
	}
	if rec := h.post(t, "/identity/provision", form(map[string]string{"method": "did:key", "key_type": "Ed25519"})); rec.Code != http.StatusNotFound {
		t.Errorf("provision without the feature: %d", rec.Code)
	}
	if rec := h.post(t, "/identity/import", form(map[string]string{"kind": "x509", "chain": chainPEM(t), "key_reference": keyRef})); rec.Code != http.StatusNotFound {
		t.Errorf("x509 import without the feature: %d", rec.Code)
	}
}

func TestIdentityPageOnAStackThatKeepsItsOwnIdentity(t *testing.T) {
	h := newHarness(t)
	h.identity.err = connect.NewError(connect.CodeUnimplemented, errors.New("the stack keeps it"))
	doc := body(t, h.get(t, "/identity/"))
	a11ytest.AssertPage(t, doc)
	if !strings.Contains(doc, "First stack sets up the issuer identity in its own configuration.") ||
		strings.Contains(doc, "Start instantly") || strings.Contains(doc, "Bring your own") {
		t.Fatalf("the page offers actions\n%s", doc)
	}
	h.identity.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if doc = body(t, h.get(t, "/identity/")); !strings.Contains(doc, "The stack did not answer.") {
		t.Fatal("an outage is not named")
	}
}

func TestIdentityPageWithoutTrustRegistry(t *testing.T) {
	h := newHarness(t, allIdentity...)
	h.withoutAdmin(t)
	doc := body(t, h.get(t, "/identity/"))
	if !strings.Contains(doc, "No trust registry runs on this deployment.") || strings.Contains(doc, "request a trust list entry") {
		t.Fatalf("the trust box shows without a registry\n%s", doc)
	}
	rec := h.post(t, "/identity/provision", form(map[string]string{"method": "did:key", "key_type": "Ed25519", "trust": "yes"}))
	if rec.Code != http.StatusSeeOther || len(h.trust.entries) != 0 {
		t.Fatalf("status %d entries %v", rec.Code, h.trust.entries)
	}
}

func TestIdentityPageNamesAStackRefusal(t *testing.T) {
	h := newHarness(t, allIdentity...)
	h.opts.Identity = refusingIdentity{h.identity}
	h.build(t)
	doc := body(t, h.post(t, "/identity/provision", form(map[string]string{"method": "did:key", "key_type": "Ed25519"})))
	if !strings.Contains(doc, "The stack did not take the identity.") {
		t.Fatalf("the refusal is not named\n%s", doc)
	}
	doc = body(t, h.post(t, "/identity/import", form(map[string]string{"kind": "did", "did": didKey, "key_reference": keyRef})))
	if !strings.Contains(doc, "The stack did not take the identity.") {
		t.Fatal("the import refusal is not named")
	}
}

// refusingIdentity reads the identity and refuses every change.
type refusingIdentity struct{ *fakeIdentity }

func (refusingIdentity) ProvisionIssuerIdentity(context.Context, *connect.Request[backendv1.ProvisionIssuerIdentityRequest]) (*connect.Response[backendv1.ProvisionIssuerIdentityResponse], error) {
	return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("no"))
}

func (refusingIdentity) ImportIssuerIdentity(context.Context, *connect.Request[backendv1.ImportIssuerIdentityRequest]) (*connect.Response[backendv1.ImportIssuerIdentityResponse], error) {
	return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("no"))
}

func TestDidWebDocumentIsServed(t *testing.T) {
	h := newHarness(t, allIdentity...)
	get := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.pages.DIDDocument().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/did.json", nil))
		return rec
	}
	if rec := get(); rec.Code != http.StatusNotFound {
		t.Fatalf("no identity: %d", rec.Code)
	}
	h.post(t, "/identity/provision", form(map[string]string{"method": "did:web", "key_type": "Ed25519"}))
	rec := get()
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/did+json" ||
		!strings.Contains(rec.Body.String(), `"id":"did:web:issuer-waltid.labs.example"`) {
		t.Fatalf("status %d type %q body %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	// A did:key of the stack is no document of this host.
	h.post(t, "/identity/provision", form(map[string]string{"method": "did:key", "key_type": "Ed25519"}))
	if rec := get(); rec.Code != http.StatusNotFound {
		t.Fatalf("did:key: %d", rec.Code)
	}
	h.opts.Identity = nil
	h.build(t)
	if rec := get(); rec.Code != http.StatusNotFound {
		t.Fatalf("no identity client: %d", rec.Code)
	}
	if doc := body(t, h.get(t, "/identity/")); !strings.Contains(doc, "sets up the issuer identity in its own configuration") {
		t.Fatal("a page without an identity client offers actions")
	}
}
