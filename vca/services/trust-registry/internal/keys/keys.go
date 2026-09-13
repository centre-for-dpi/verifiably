// SPDX-License-Identifier: Apache-2.0

// Package keys holds the signing keys of the trust registry
// (ADR-011 decision 5). The registry signs with ES256 or Ed25519 only.
// Every key has a kid. The ring keeps retired keys so that relying parties
// can check lists signed before a rotation.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// Key is one signing key with its identifier.
type Key struct {
	// ID is the kid. It is the RFC 7638 thumbprint unless the caller set it.
	ID      string
	Private crypto.PrivateKey
	Alg     jose.Algorithm
	// CreatedAt is the time the key entered the ring.
	CreatedAt time.Time
}

// Public returns the public JWK of the key.
func (k Key) Public() jose.JWK {
	// Private is ES256 or Ed25519 by construction, so PublicJWK cannot fail.
	jwk, _ := jose.PublicJWK(k.Private, k.ID)
	return jwk
}

// New wraps a private key. It checks the key type and sets the kid to the
// thumbprint when kid is empty.
func New(private crypto.PrivateKey, kid string, now time.Time) (Key, error) {
	alg, err := jose.AlgorithmFor(private)
	if err != nil {
		return Key{}, fmt.Errorf("keys: %w", err)
	}
	if ec, ok := private.(*ecdsa.PrivateKey); ok && ec.Curve != elliptic.P256() {
		return Key{}, fmt.Errorf("keys: unsupported curve %s", ec.Curve.Params().Name)
	}
	if kid == "" {
		jwk, _ := jose.PublicJWK(private, "")
		kid, err = jose.Thumbprint(jwk)
		if err != nil {
			return Key{}, err
		}
	}
	return Key{ID: kid, Private: private, Alg: alg, CreatedAt: now.UTC()}, nil
}

// Generate creates a new key for alg (ES256 or EdDSA).
func Generate(alg jose.Algorithm, now time.Time) (Key, error) {
	private, err := jose.GenerateKey(alg)
	if err != nil {
		return Key{}, fmt.Errorf("keys: %w", err)
	}
	return New(private, "", now)
}

// ParsePEM reads every PRIVATE KEY block (PKCS #8) in data.
// The first block is the active key. The others are retired keys.
func ParsePEM(data []byte, now time.Time) ([]Key, error) {
	var out []Key
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "PRIVATE KEY" {
			return nil, fmt.Errorf("keys: unsupported PEM block %q, use PKCS #8", block.Type)
		}
		private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("keys: parse PKCS #8: %w", err)
		}
		k, err := New(private, "", now)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil, errors.New("keys: no PRIVATE KEY block found")
	}
	return out, nil
}

// EncodePEM writes the keys as PKCS #8 PRIVATE KEY blocks.
func EncodePEM(keys []Key) ([]byte, error) {
	var out []byte
	for _, k := range keys {
		der, err := x509.MarshalPKCS8PrivateKey(k.Private)
		if err != nil {
			return nil, fmt.Errorf("keys: encode: %w", err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})...)
	}
	return out, nil
}

// Ring holds the active key and the retired keys.
type Ring struct {
	mu      sync.RWMutex
	active  Key
	retired []Key
}

// NewRing builds a ring. The first key is active. The rest are retired.
func NewRing(keys ...Key) (*Ring, error) {
	if len(keys) == 0 {
		return nil, errors.New("keys: ring needs at least one key")
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k.ID] {
			return nil, fmt.Errorf("keys: duplicate kid %q", k.ID)
		}
		seen[k.ID] = true
	}
	return &Ring{active: keys[0], retired: append([]Key(nil), keys[1:]...)}, nil
}

// Active returns the signing key.
func (r *Ring) Active() Key {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active
}

// Rotate makes k the active key and retires the previous active key.
func (r *Ring) Rotate(k Key) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if k.ID == r.active.ID {
		return fmt.Errorf("keys: kid %q is already active", k.ID)
	}
	for _, old := range r.retired {
		if old.ID == k.ID {
			return fmt.Errorf("keys: kid %q is retired", k.ID)
		}
	}
	r.retired = append([]Key{r.active}, r.retired...)
	r.active = k
	return nil
}

// Prune drops retired keys that entered the ring before cutoff.
func (r *Ring) Prune(cutoff time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.retired[:0]
	dropped := 0
	for _, k := range r.retired {
		if k.CreatedAt.Before(cutoff) {
			dropped++
			continue
		}
		kept = append(kept, k)
	}
	r.retired = kept
	return dropped
}

// Keys returns the active key followed by the retired keys.
func (r *Ring) Keys() []Key {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Key{r.active}, r.retired...)
}

// JWKS returns the public keys of the ring (RFC 7517 section 5).
func (r *Ring) JWKS() jose.JWKS {
	var set jose.JWKS
	for _, k := range r.Keys() {
		set.Keys = append(set.Keys, k.Public())
	}
	return set
}

// JWKSJSON returns the JWKS document bytes.
func (r *Ring) JWKSJSON() []byte {
	// Every key in the ring encodes, so Marshal cannot fail.
	out, _ := json.Marshal(r.JWKS())
	return out
}

// Sign returns a compact JWS over claims with the active key.
func (r *Ring) Sign(typ string, claims any) (string, error) {
	k := r.Active()
	return jose.Sign(k.Private, k.ID, typ, claims)
}

// IsEd25519 reports whether the key is an Ed25519 key.
func (k Key) IsEd25519() bool {
	_, ok := k.Private.(ed25519.PrivateKey)
	return ok
}
