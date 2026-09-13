// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

var now = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

// Regression: legacy TestIsExpired.
func TestIsExpired(t *testing.T) {
	cases := []struct {
		name    string
		e       Entry
		expired bool
	}{
		{"zero ValidUntil never expires", Entry{}, false},
		{"future ValidUntil not expired", Entry{ValidUntil: now.Add(24 * time.Hour)}, false},
		{"past ValidUntil is expired", Entry{ValidUntil: now.Add(-time.Second)}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.e.IsExpired(now) != tc.expired {
				t.Errorf("IsExpired() = %v, want %v", tc.e.IsExpired(now), tc.expired)
			}
		})
	}
}

// Regression: legacy TestAuthorisesSchema.
func TestAuthorisesSchema(t *testing.T) {
	cases := []struct {
		name     string
		schemas  []string
		schemaID string
		want     bool
	}{
		{"nil schemas = wildcard", nil, "AnyCred", true},
		{"empty slice = wildcard", []string{}, "AnyCred", true},
		{"matching schema", []string{"DNI", "Passport"}, "Passport", true},
		{"non-matching schema", []string{"DNI", "Passport"}, "DriversLicense", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Entry{Schemas: tc.schemas}).AuthorisesSchema(tc.schemaID); got != tc.want {
				t.Errorf("AuthorisesSchema(%q) = %v, want %v", tc.schemaID, got, tc.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	if err := (Entry{}).Validate(); err == nil {
		t.Fatal("empty did must fail")
	}
	if err := (Entry{DID: "did:web:a", StatusListPolicy: "maybe"}).Validate(); err == nil {
		t.Fatal("unknown policy must fail")
	}
	for _, p := range []string{"", FailClosed, FailOpen} {
		if err := (Entry{DID: "did:web:a", StatusListPolicy: p}).Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

// Regression: legacy TestMemStore_IsTrusted_* as pure lookups.
func TestLookup(t *testing.T) {
	entries := []Entry{
		{DID: "did:web:issuer.gov", Schemas: []string{"DNI", "Passport"}},
		{DID: "did:web:expired.gov", ValidUntil: now.Add(-time.Hour)},
		{DID: "did:web:wild.gov"},
	}
	cases := []struct {
		name, did, schema string
		want              error
	}{
		{"not found", "did:web:unknown.gov", "DNI", ErrUntrusted},
		{"expired", "did:web:expired.gov", "DNI", ErrUntrusted},
		{"wrong schema", "did:web:issuer.gov", "DriversLicense", ErrUntrusted},
		{"success", "did:web:issuer.gov", "DNI", nil},
		{"wildcard", "did:web:wild.gov", "AnythingAtAll", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Lookup(entries, tc.did, tc.schema, now); !errors.Is(err, tc.want) {
				t.Fatalf("Lookup = %v, want %v", err, tc.want)
			}
		})
	}
}

// Regression: legacy TestMemStore_SortedByDID.
func TestSorted(t *testing.T) {
	in := []Entry{{DID: "did:web:z.gov"}, {DID: "did:web:a.gov"}, {DID: "did:web:m.gov"}}
	out := Sorted(in)
	if out[0].DID != "did:web:a.gov" || out[2].DID != "did:web:z.gov" || in[0].DID != "did:web:z.gov" {
		t.Fatalf("Sorted = %v, in = %v", out, in)
	}
}

// Regression: legacy TestBuildJWTES256_Structure and the round trip.
func TestBuildVerifyRoundTrip(t *testing.T) {
	entries := []Entry{
		{DID: "did:web:z.gov", DisplayName: "Z", AccreditedAt: now},
		{DID: "did:web:a.gov", Schemas: []string{"DNI"}, StatusListEndpoints: []string{"https://a.gov/status/1"}, StatusListPolicy: FailOpen, AccreditedAt: now},
	}
	for _, alg := range jose.SigningAlgorithms {
		t.Run(string(alg), func(t *testing.T) {
			key, _ := jose.GenerateKey(alg)
			tok, err := Build(entries, key, BuildOptions{Issuer: "did:web:hub.gov", Kid: "k1", Now: now, TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(tok, ".") != 2 {
				t.Fatal("JWT must have 3 parts")
			}
			hdr, _ := jose.PeekHeader(tok)
			if hdr.Alg != string(alg) || hdr.Typ != TypeJWT || hdr.Kid != "k1" {
				t.Fatalf("header = %+v", hdr)
			}
			pub, _ := jose.PublicJWK(key, "k1")
			list, err := Verify(tok, jose.JWKS{Keys: []jose.JWK{pub}}, now.Add(30*time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if list.Issuer != "did:web:hub.gov" || len(list.Entries) != 2 || list.Entries[0].DID != "did:web:a.gov" {
				t.Fatalf("list = %+v", list)
			}
			if list.ExpiresAt != now.Add(time.Hour) || list.IssuedAt != now {
				t.Fatalf("times = %v %v", list.IssuedAt, list.ExpiresAt)
			}
			if list.Entries[0].StatusListPolicy != FailOpen || list.Entries[0].StatusListEndpoints[0] != "https://a.gov/status/1" {
				t.Fatalf("entry = %+v", list.Entries[0])
			}
			if _, err := Verify(tok, jose.JWKS{Keys: []jose.JWK{pub}}, now.Add(2*time.Hour)); !errors.Is(err, ErrExpired) {
				t.Fatalf("expired: %v", err)
			}
			if err := Lookup(list.Entries, "did:web:a.gov", "DNI", now); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBuildDefaultsAndErrors(t *testing.T) {
	key, _ := jose.GenerateKey(jose.ES256)
	tok, err := Build(nil, key, BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := jose.PeekPayload(tok)
	if claims["exp"].(float64)-claims["iat"].(float64) != DefaultTTL.Seconds() {
		t.Fatalf("default ttl: %v", claims)
	}
	if _, err := Build([]Entry{{}}, key, BuildOptions{}); err == nil {
		t.Fatal("invalid entry must fail")
	}
	if _, err := Build(nil, "nope", BuildOptions{}); err == nil {
		t.Fatal("bad key must fail")
	}
}

func TestVerifyErrors(t *testing.T) {
	key, _ := jose.GenerateKey(jose.ES256)
	pub, _ := jose.PublicJWK(key, "")
	set := jose.JWKS{Keys: []jose.JWK{pub}}
	other, _ := jose.GenerateKey(jose.ES256)
	wrongKey, _ := Build(nil, other, BuildOptions{})
	noExp, _ := jose.Sign(key, "", TypeJWT, map[string]any{"iss": "x"})
	badClaims, _ := jose.Sign(key, "", TypeJWT, map[string]any{"exp": "soon"})
	cases := []struct{ name, tok string }{
		{"malformed", "not.a.valid.jwt"},
		{"wrong key", wrongKey},
		{"no exp", noExp},
		{"bad claims", badClaims},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(tc.tok, set, time.Time{}); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	// Zero now uses the wall clock.
	fresh, _ := Build(nil, key, BuildOptions{})
	if _, err := Verify(fresh, set, time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func FuzzParseList(f *testing.F) {
	key, _ := jose.GenerateKey(jose.ES256)
	pub, _ := jose.PublicJWK(key, "")
	tok, _ := Build([]Entry{{DID: "did:web:a"}}, key, BuildOptions{Now: now})
	f.Add(tok)
	f.Fuzz(func(t *testing.T, tok string) {
		_, _ = Verify(tok, jose.JWKS{Keys: []jose.JWK{pub}}, now)
	})
}
