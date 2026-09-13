// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ProofType is the media type of an OID4VCI holder key proof.
const ProofType = "openid4vci-proof+jwt"

// ProofLife is the time a proof stays valid.
const ProofLife = 5 * time.Minute

// ProofKey holds the key that signs the holder proof of the
// pre-authorized flow. The adapter holds this key because the flow has
// no citizen and no wallet. It never signs a credential with it, so the
// rule of ADR-001 decision 3 holds.
type ProofKey struct {
	mu  sync.Mutex
	key *ecdsa.PrivateKey
	// generate makes a new key. Tests replace it.
	generate func() (*ecdsa.PrivateKey, error)
}

// NewProofKey returns a proof key that makes its key at first use.
func NewProofKey() *ProofKey {
	return &ProofKey{generate: generateP256}
}

// generateP256 makes a new P-256 key.
func generateP256() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// JWK returns the public key of the proof key as a JSON web key.
func (p *ProofKey) JWK() (map[string]any, error) {
	key, err := p.ensure()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(leftPad(key.X.Bytes(), 32)),
		"y":   base64.RawURLEncoding.EncodeToString(leftPad(key.Y.Bytes(), 32)),
	}, nil
}

// ensure returns the key and makes one at the first call.
func (p *ProofKey) ensure() (*ecdsa.PrivateKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key != nil {
		return p.key, nil
	}
	if p.generate == nil {
		p.generate = generateP256
	}
	key, err := p.generate()
	if err != nil {
		return nil, fmt.Errorf("inji: make the proof key: %w", err)
	}
	p.key = key
	return key, nil
}

// Sign returns the compact holder proof for the audience and the nonce.
//
// The header carries typ, alg, and jwk. It carries no kid, because Inji
// rejects a header that names a key twice. The payload carries aud, iat,
// and exp, and it carries nonce when the token endpoint returned one. It
// carries no iss and no sub, because the pre-authorized flow of OID4VCI
// has no named holder.
func (p *ProofKey) Sign(audience, nonce string, now time.Time) (string, error) {
	if strings.TrimSpace(audience) == "" {
		return "", errors.New("inji: the proof needs an audience")
	}
	key, err := p.ensure()
	if err != nil {
		return "", err
	}
	jwk, err := p.JWK()
	if err != nil {
		return "", err
	}
	header, err := json.Marshal(map[string]any{"typ": ProofType, "alg": "ES256", "jwk": jwk})
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(ProofLife).Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("inji: sign the proof: %w", err)
	}
	signature := append(leftPad(r.Bytes(), 32), leftPad(s.Bytes(), 32)...)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// leftPad puts zero bytes in front of b until it has n bytes.
func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// KeyID returns the key identifier Inji Certify used to sign the
// credential. A JSON-LD credential names it in the verification method
// of its proof. A JSON web signature names it in the kid header.
//
// The adapter reports this value in the issuer metadata answer, so an
// operator can tell which key of the issuer DID document signed a
// credential.
func KeyID(credential []byte) string {
	if kid := keyIDFromLinkedData(credential); kid != "" {
		return kid
	}
	return keyIDFromJws(credential)
}

// keyIDFromLinkedData reads proof.verificationMethod of a JSON-LD
// credential.
func keyIDFromLinkedData(credential []byte) string {
	var doc struct {
		Proof json.RawMessage `json:"proof"`
	}
	if err := json.Unmarshal(credential, &doc); err != nil || len(doc.Proof) == 0 {
		return ""
	}
	one := struct {
		VerificationMethod string `json:"verificationMethod"`
	}{}
	if json.Unmarshal(doc.Proof, &one) == nil && one.VerificationMethod != "" {
		return one.VerificationMethod
	}
	var many []struct {
		VerificationMethod string `json:"verificationMethod"`
	}
	if json.Unmarshal(doc.Proof, &many) == nil {
		for _, p := range many {
			if p.VerificationMethod != "" {
				return p.VerificationMethod
			}
		}
	}
	return ""
}

// keyIDFromJws reads the kid header of a compact JSON web signature.
func keyIDFromJws(credential []byte) string {
	text := strings.TrimSpace(string(credential))
	// An SD-JWT VC carries its disclosures after a tilde.
	if i := strings.Index(text, "~"); i > 0 {
		text = text[:i]
	}
	parts := strings.Split(text, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return ""
	}
	return header.Kid
}
