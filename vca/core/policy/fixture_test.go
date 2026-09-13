// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// builder makes signed test credentials.
type builder struct {
	issuerKey crypto.PrivateKey
	holderKey crypto.PrivateKey
}

func newBuilder(t *testing.T) builder {
	t.Helper()
	ik, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	return builder{issuerKey: ik, holderKey: hk}
}

// jwks returns the issuer key set.
func (b builder) jwks(t *testing.T) jose.JWKS {
	t.Helper()
	k, err := jose.PublicJWK(b.issuerKey, "issuer-key")
	if err != nil {
		t.Fatal(err)
	}
	return jose.JWKS{Keys: []jose.JWK{k}}
}

// keys returns a resolver that answers with the issuer key set.
func (b builder) keys(t *testing.T) KeyResolver {
	set := b.jwks(t)
	return func(context.Context, string, string) (jose.JWKS, error) { return set, nil }
}

// sdjwtOptions configure an SD-JWT test credential.
type sdjwtOptions struct {
	claims     map[string]any
	conceal    []string
	noHolder   bool
	keyBinding bool
	aud        string
	nonce      string
	kbIAT      time.Time
}

// sdjwtCred builds one SD-JWT credential.
func (b builder) sdjwtCred(t *testing.T, o sdjwtOptions) Credential {
	t.Helper()
	claims := map[string]any{"iss": "did:web:issuer", "sub": "did:key:holder", "vct": "TestCredential"}
	for k, v := range o.claims {
		claims[k] = v
	}
	if !o.noHolder {
		pub, err := jose.PublicJWK(b.holderKey, "")
		if err != nil {
			t.Fatal(err)
		}
		m, err := jose.JWKToMap(pub)
		if err != nil {
			t.Fatal(err)
		}
		claims["cnf"] = map[string]any{"jwk": m}
	}
	conceal := o.conceal
	if conceal == nil {
		claims["given_name"] = "Ada"
		conceal = []string{"given_name"}
	}
	payload, discs, err := sdjwt.Conceal(claims, conceal)
	if err != nil {
		t.Fatal(err)
	}
	issuerJWT, err := jose.Sign(b.issuerKey, "issuer-key", string(vc.FormatSDJWT), payload)
	if err != nil {
		t.Fatal(err)
	}
	pres := sdjwt.Presentation{IssuerJWT: issuerJWT, Disclosures: discs}
	if o.keyBinding {
		iat := o.kbIAT
		if iat.IsZero() {
			iat = testNow.Add(-time.Minute)
		}
		kb, kerr := sdjwt.KeyBinding(pres, b.holderKey, sdjwt.DefaultAlg, o.aud, o.nonce, iat)
		if kerr != nil {
			t.Fatal(kerr)
		}
		pres.KeyBindingJWT = kb
	}
	return credOf(t, vc.FormatSDJWT, sdjwt.Serialize(pres))
}

// jwtCred builds one JWT credential.
func (b builder) jwtCred(t *testing.T, claims map[string]any) Credential {
	t.Helper()
	tok, err := jose.Sign(b.issuerKey, "issuer-key", "JWT", claims)
	if err != nil {
		t.Fatal(err)
	}
	return credOf(t, vc.FormatJWT, tok)
}

// credOf normalises a token into a Credential.
func credOf(t *testing.T, format vc.Format, token string) Credential {
	t.Helper()
	parsed, err := vc.Parse([]byte(token))
	if err != nil {
		t.Fatal(err)
	}
	return Credential{Format: format, Token: token, VC: parsed}
}

// objectCred builds a credential from a decoded object.
func objectCred(format vc.Format, obj map[string]any) Credential {
	return Credential{Format: format, VC: vc.FromObject(obj)}
}

// pres wraps credentials in a presentation.
func pres(creds ...Credential) Presentation {
	return Presentation{Credentials: creds}
}

// base returns a context with a fixed clock.
func base() Context { return Context{Now: testNow} }

// only returns the single result of a check, and fails otherwise.
func only(t *testing.T, got []CheckResult) CheckResult {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("want 1 result, got %d", len(got))
	}
	return got[0]
}

// wantOutcome fails when the outcome is not want.
func wantOutcome(t *testing.T, got CheckResult, want Outcome) {
	t.Helper()
	if got.Result != want {
		t.Fatalf("%s: want %s, got %s (%s)", got.Name, want, got.Result, got.Detail)
	}
}

// failFetch is a Fetcher that always fails.
func failFetch(context.Context, string) ([]byte, error) { return nil, errors.New("offline") }

// bytesFetch returns a Fetcher that answers with doc.
func bytesFetch(doc []byte) Fetcher {
	return func(context.Context, string) ([]byte, error) { return doc, nil }
}

// jsonBytes marshals v or fails the test.
func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// errNoKeys is the error a failing key resolver returns.
var errNoKeys = errors.New("no keys")
