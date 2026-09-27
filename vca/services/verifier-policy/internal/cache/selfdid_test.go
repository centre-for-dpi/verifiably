// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// TestStatusListOfASelfResolvingIssuer: a did:key and a did:jwk carry
// their key, so the cache reads the key of such an issuer with no
// network and keeps the status list the issuer signed.
func TestStatusListOfASelfResolvingIssuer(t *testing.T) {
	w := newWorld(t)
	c := w.cache(t, offline())
	ctx := context.Background()
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDID, err := did.FromPublicKey(edKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jose.PublicJWK(ecKey, "")
	if err != nil {
		t.Fatal(err)
	}
	m, err := jose.JWKToMap(pub)
	if err != nil {
		t.Fatal(err)
	}
	delete(m, "use")
	delete(m, "alg")
	jwkDID, err := did.FromJWK(m)
	if err != nil {
		t.Fatal(err)
	}
	kids := map[string]string{keyDID: keyDID + "#" + strings.TrimPrefix(keyDID, "did:key:"), jwkDID: jwkDID + "#0"}
	for issuer, key := range map[string]any{keyDID: edKey, jwkDID: ecKey} {
		if s, err := c.issuerKeys(ctx, issuer); err != nil || s.Items != 1 {
			t.Fatalf("%s: keys = %+v, %v", issuer, s, err)
		}
		list, err := jose.Sign(key, kids[issuer], "statuslist+jwt", map[string]any{"iss": issuer, "sub": "https://s.example/self"})
		if err != nil {
			t.Fatal(err)
		}
		w.docs["https://s.example/self"] = []byte(list)
		if s, err := c.statusList(ctx, "https://s.example/self"); err != nil || s.Issuer != issuer {
			t.Errorf("%s: status list = %+v, %v", issuer, s, err)
		}
	}
	if _, err := c.issuerKeys(ctx, "did:key:zBroken"); err == nil {
		t.Error("a did:key that does not decode gave keys")
	}
}
