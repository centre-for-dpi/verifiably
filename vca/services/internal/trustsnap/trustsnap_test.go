// SPDX-License-Identifier: Apache-2.0

package trustsnap

import (
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

var t0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// signer is a test key with its key set.
type signer struct {
	key crypto.PrivateKey
	set jose.JWKS
}

func newSigner(t *testing.T) signer {
	t.Helper()
	k, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jose.PublicJWK(k, "registry-key")
	if err != nil {
		t.Fatal(err)
	}
	return signer{key: k, set: jose.JWKS{Keys: []jose.JWK{pub}}}
}

func (s signer) sign(t *testing.T, typ string, c Claims) string {
	t.Helper()
	tok, err := jose.Sign(s.key, "registry-key", typ, c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func until(d time.Duration) *time.Time {
	v := t0.Add(d)
	return &v
}

// sample is a snapshot with a local list and one external registry.
func sample() Claims {
	return Claims{
		Issuer: "https://trust.example", IssuedAt: t0.Unix(), ExpiresAt: t0.Add(24 * time.Hour).Unix(),
		Lists: []List{
			{
				ListURL: "https://trust.example/trust-list/etsi.jws", SignedBy: "registry-key", CheckedAt: t0,
				Entities: []Entity{
					{Name: "Ministry of Education", Role: RoleIssuer, Status: StatusActive,
						Identities: []Identity{{DID: "did:web:education.go.ke"}}, CredentialTypes: []string{"UniversityDegree"},
						StatusListEndpoints: []string{"https://education.go.ke/status/1"}},
					{Name: "Old issuer", Role: RoleIssuer, Status: "revoked", Identities: []Identity{{DID: "did:web:old.example"}}},
					{Name: "Ended issuer", Role: RoleIssuer, Status: StatusActive, ValidUntil: until(-time.Hour),
						Identities: []Identity{{DID: "did:web:ended.example"}}},
					{Name: "Future issuer", Role: RoleIssuer, Status: StatusActive, ValidFrom: until(time.Hour),
						Identities: []Identity{{DID: "did:web:future.example"}}},
					{Name: "A verifier", Role: "verifier", Status: StatusActive, Identities: []Identity{{DID: "did:web:verifier.example"}}},
					{Name: "Suspended", Role: RoleIssuer, Status: "suspended", Identities: []Identity{{DID: "did:web:suspended.example"}}},
					{Name: "Waiting", Role: RoleIssuer, Status: "pending", Identities: []Identity{{DID: "did:web:pending.example"}}},
					{Name: "X509 issuer", Role: RoleIssuer, Status: StatusActive, Identities: []Identity{{X509Subject: "CN=Issuer"}}},
					{Name: "No identity", Role: RoleIssuer, Status: StatusActive},
				},
			},
			{
				RegistryID: "reg-1", RegistryName: "Kenya trust registry", ListURL: "https://registry.go.ke/list.jws",
				SignedBy: "CN=Kenya anchor", CheckedAt: t0.Add(-time.Hour), X509Chain: "-----BEGIN CERTIFICATE-----",
				Entities: []Entity{
					{Name: "Old issuer, still trusted here", Role: RoleIssuer, Status: StatusActive, Identities: []Identity{{DID: "did:web:old.example"}}},
					{Name: "Ministry, listed twice", Role: RoleIssuer, Status: StatusActive, Identities: []Identity{{DID: "did:web:education.go.ke"}},
						CredentialTypes: []string{"UniversityDegree"}},
					{Name: "National Registration Bureau", Role: RoleIssuer, Status: StatusActive, Identities: []Identity{{DID: "did:web:registrar.go.ke"}},
						ServiceEndpoint: "https://registrar.go.ke"},
				},
			},
		},
	}
}

func TestVerifyChecksSignatureTypeAndExpiry(t *testing.T) {
	s := newSigner(t)
	c := sample()
	got, kid, verr := Verify(s.sign(t, Type, c), s.set, t0)
	if verr != nil || kid != "registry-key" || len(got.Lists) != 2 || got.Count() != 12 {
		t.Fatalf("Verify = %d lists, %q, %v", len(got.Lists), kid, verr)
	}
	other := newSigner(t)
	if _, _, err := Verify(s.sign(t, Type, c), other.set, t0); err == nil {
		t.Fatal("want a key set without the signing key refused")
	}
	if _, _, err := Verify(s.sign(t, "JWT", c), s.set, t0); err == nil {
		t.Fatal("want another typ refused")
	}
	if _, _, err := Verify(s.sign(t, Type, c), s.set, t0.Add(25*time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatalf("want an expired snapshot refused, got %v", err)
	}
	c.ExpiresAt = 0
	if _, _, err := Verify(s.sign(t, Type, c), s.set, t0); err == nil {
		t.Fatal("want a snapshot with no exp refused")
	}
	bad, err := jose.Sign(s.key, "registry-key", Type, map[string]any{"lists": "not a list", "exp": t0.Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(bad, s.set, t0); err == nil {
		t.Fatal("want claims that do not decode refused")
	}
}

func TestLookup(t *testing.T) {
	c := sample()
	cases := []struct {
		id, typ  string
		outcome  Outcome
		name     string
		registry string
	}{
		{"did:web:education.go.ke", "UniversityDegree", Trusted, "Ministry of Education", ""},
		{"did:web:education.go.ke", "", Trusted, "Ministry of Education", ""},
		{"did:web:education.go.ke", "Passport", Untrusted, "Ministry of Education", ""},
		{"did:web:registrar.go.ke", "Passport", Trusted, "National Registration Bureau", "Kenya trust registry"},
		{"did:web:old.example", "", Trusted, "Old issuer, still trusted here", "Kenya trust registry"},
		{"did:web:ended.example", "", Untrusted, "Ended issuer", ""},
		{"did:web:future.example", "", Untrusted, "Future issuer", ""},
		{"did:web:verifier.example", "", Untrusted, "A verifier", ""},
		{"did:web:suspended.example", "", Untrusted, "Suspended", ""},
		{"did:web:pending.example", "", Untrusted, "Waiting", ""},
		{"CN=Issuer", "", Trusted, "X509 issuer", ""},
		{"did:web:nobody.example", "", Unknown, "", ""},
	}
	for _, tc := range cases {
		got := c.Lookup(tc.id, tc.typ, t0)
		if got.Outcome != tc.outcome || got.Name != tc.name || got.RegistryName != tc.registry {
			t.Errorf("Lookup(%s, %s) = %+v", tc.id, tc.typ, got)
		}
		if got.Outcome != Trusted && got.Reason == "" {
			t.Errorf("Lookup(%s) gives no reason", tc.id)
		}
	}
	if got := c.Lookup("did:web:registrar.go.ke", "", t0); got.ListURL != "https://registry.go.ke/list.jws" || got.RegistryID != "reg-1" {
		t.Fatalf("want the provenance of the external list, got %+v", got)
	}
}

func TestIssuersAndChains(t *testing.T) {
	got := sample().Issuers()
	want := map[string]string{
		"did:web:education.go.ke": "", "did:web:registrar.go.ke": "Kenya trust registry",
		"did:web:old.example": "Kenya trust registry", "did:web:ended.example": "", "did:web:future.example": "",
	}
	if len(got) != len(want) {
		t.Fatalf("Issuers = %+v", got)
	}
	for _, is := range got {
		if name, ok := want[is.ID]; !ok || name != is.RegistryName {
			t.Errorf("issuer %+v not wanted", is)
		}
		if is.ID == "did:web:education.go.ke" && (len(is.StatusLists) != 1 || is.Name != "Ministry of Education") {
			t.Errorf("want the status list of the ministry, got %+v", is)
		}
	}
	chains := sample().Chains()
	if len(chains) != 1 || chains[0].RegistryID != "reg-1" || chains[0].PEM == "" {
		t.Fatalf("Chains = %+v", chains)
	}
}
