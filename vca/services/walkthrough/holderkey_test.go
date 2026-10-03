// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package walkthrough_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// holderKey is the signing key that wallet.js keeps in IndexedDB of the
// browser of the farmer (ADR-073). The browser double signs with it as
// WebCrypto does: ES256, the raw r and s of 32 bytes each.
type holderKey struct {
	key *ecdsa.PrivateKey
	jwk string
}

func newHolderKey(t *testing.T) holderKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := make([]byte, 32), make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	enc := base64.RawURLEncoding
	raw, err := json.Marshal(map[string]string{"kty": "EC", "crv": "P-256", "x": enc.EncodeToString(x), "y": enc.EncodeToString(y)})
	if err != nil {
		t.Fatal(err)
	}
	return holderKey{key: key, jwk: string(raw)}
}

// sign signs a signing input.
func (k holderKey) sign(t *testing.T, input string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

// script runs what wallet.js does with a form: it posts the values of
// the form, with the changes, to a JSON endpoint of the same page, and
// reads the answer.
func (b *browser) script(f form, path string, changes ...string) map[string]string {
	b.t.Helper()
	u, err := url.Parse(f.action)
	if err != nil {
		b.t.Fatal(err)
	}
	u.Path, u.RawQuery = path, ""
	values := url.Values{}
	for k, v := range f.values {
		values[k] = append([]string(nil), v...)
	}
	for i := 0; i+1 < len(changes); i += 2 {
		values.Set(changes[i], changes[i+1])
	}
	req, err := http.NewRequestWithContext(b.ctx, http.MethodPost, u.String(), strings.NewReader(values.Encode()))
	if err != nil {
		b.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("POST %s: %v", u, err)
	}
	defer func() {
		if cerr := res.Body.Close(); cerr != nil {
			b.t.Log(cerr)
		}
	}()
	var out map[string]string
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil || res.StatusCode != http.StatusOK {
		b.t.Fatalf("POST %s answered %d %v: %v", u, res.StatusCode, out, err)
	}
	return out
}

// proofKey checks the proof of a credential request, as an issuer does:
// the key in its header signed it, it names the issuer and the nonce the
// issuer gave. It returns that key, which the credential then names in
// cnf.jwk. A request with no proof gets nil. It reads the proof of
// draft 13 and the proofs object of OID4VCI 1.0, and refuses a request
// that carries both (OID4VCI 1.0 section 8.2).
func proofKey(body []byte, issuer, nonce string) (map[string]any, error) {
	var req struct {
		Proof *struct {
			Type string `json:"proof_type"`
			JWT  string `json:"jwt"`
		} `json:"proof"`
		Proofs *struct {
			JWT []string `json:"jwt"`
		} `json:"proofs"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	var jwt string
	switch {
	case req.Proof != nil && req.Proofs != nil:
		return nil, errors.New("the request carries both proof and proofs")
	case req.Proofs != nil:
		if len(req.Proofs.JWT) != 1 {
			return nil, errors.New("the proofs object holds no single JWT")
		}
		jwt = req.Proofs.JWT[0]
	case req.Proof != nil:
		if req.Proof.Type != "jwt" {
			return nil, errors.New("the proof is not a JWT")
		}
		jwt = req.Proof.JWT
	default:
		return nil, nil
	}
	head, _, ok := strings.Cut(jwt, ".")
	if !ok {
		return nil, errors.New("the proof is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return nil, err
	}
	var hdr struct {
		Typ string         `json:"typ"`
		JWK map[string]any `json:"jwk"`
	}
	if json.Unmarshal(raw, &hdr) != nil || hdr.Typ != "openid4vci-proof+jwt" {
		return nil, errors.New("the proof header is not valid")
	}
	key, err := jose.JWKFromMap(hdr.JWK)
	if err != nil {
		return nil, err
	}
	payload, _, err := jose.Verify(jwt, key.Key, []jose.Algorithm{jose.ES256})
	if err != nil {
		return nil, err
	}
	var claims struct {
		Aud   string `json:"aud"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Aud != issuer || claims.Nonce != nonce {
		return nil, errors.New("the proof names another issuer or nonce")
	}
	return hdr.JWK, nil
}
