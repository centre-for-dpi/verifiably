// SPDX-License-Identifier: Apache-2.0

package oidcflow

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// DefaultSessionTTL is the lifetime of a session JWT (ADR-020 decision 2).
const DefaultSessionTTL = 15 * time.Minute

// Claims is the claim set of a session JWT (RFC 7519 section 4).
// Service specific fields are optional and omitted when empty.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	ID        string   `json:"jti"`
	// SID is the session id that Logout revokes.
	SID string `json:"sid"`
	// Roles are the role names the subject holds.
	Roles []string `json:"roles,omitempty"`
	// Provider is the provider id that authenticated the subject.
	Provider string `json:"provider,omitempty"`
	// Name is the display name, when the service keeps one.
	Name string `json:"name,omitempty"`
	// Tenant is the tenant id, when the service keeps one.
	Tenant string `json:"tenant,omitempty"`
	// ClientID marks a machine token from client credentials.
	ClientID string `json:"client_id,omitempty"`
	// WalletID is the wallet id at the holder backend.
	WalletID string `json:"wallet_id,omitempty"`
	// HolderDID is the holder DID, when one exists.
	HolderDID string `json:"holder_did,omitempty"`
	// HasHolderKey says whether the session has a registered holder key.
	HasHolderKey bool `json:"has_holder_key,omitempty"`
}

// HasRole reports whether the claims carry role.
func (c Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Expiry returns exp as a time.
func (c Claims) Expiry() time.Time { return time.Unix(c.ExpiresAt, 0) }

// Signer issues and checks session JWTs with one ES256 key.
type Signer struct {
	key      *ecdsa.PrivateKey
	kid      string
	issuer   string
	audience string
	ttl      time.Duration
	now      func() time.Time
	deny     DenyList
}

// NewSigner returns a signer. key must be a P-256 ECDSA key.
// The kid is the RFC 7638 thumbprint of the public key.
func NewSigner(key *ecdsa.PrivateKey, issuer, audience string, ttl time.Duration, deny DenyList) (*Signer, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, errors.New("oidcflow: signing key must be an ECDSA P-256 key")
	}
	if issuer == "" || audience == "" {
		return nil, errors.New("oidcflow: signer needs an issuer and an audience")
	}
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if deny == nil {
		deny = NewMemoryDenyList(nil)
	}
	pub, _ := jose.PublicJWK(key, "")
	kid, _ := jose.Thumbprint(pub)
	return &Signer{key: key, kid: kid, issuer: issuer, audience: audience, ttl: ttl, now: time.Now, deny: deny}, nil
}

// WithClock replaces the clock, for tests.
func (s *Signer) WithClock(now func() time.Time) *Signer {
	s.now = now
	return s
}

// KeyID returns the kid the signer puts in every token header.
func (s *Signer) KeyID() string { return s.kid }

// TTL returns the token lifetime.
func (s *Signer) TTL() time.Duration { return s.ttl }

// Deny returns the deny list.
func (s *Signer) Deny() DenyList { return s.deny }

// Issue signs claims. It fills iss, aud, iat, exp, jti, and sid when
// they are empty and returns the token with the final claims.
func (s *Signer) Issue(c Claims) (string, Claims, error) {
	t := s.now()
	c.Issuer = s.issuer
	c.Audience = []string{s.audience}
	c.IssuedAt = t.Unix()
	if c.ExpiresAt == 0 {
		c.ExpiresAt = t.Add(s.ttl).Unix()
	}
	if c.ID == "" {
		c.ID = randomID()
	}
	if c.SID == "" {
		c.SID = c.ID
	}
	tok, err := jose.Sign(s.key, s.kid, "JWT", c)
	if err != nil {
		return "", Claims{}, err
	}
	return tok, c, nil
}

// Verify checks the signature, iss, aud, exp, and the deny list.
func (s *Signer) Verify(token string) (Claims, error) {
	raw, _, err := jose.Verify(token, &s.key.PublicKey, []jose.Algorithm{jose.ES256})
	if err != nil {
		return Claims{}, wrap(ErrSessionInvalid, "%v", err)
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return Claims{}, wrap(ErrSessionInvalid, "claims: %v", err)
	}
	if c.Issuer != s.issuer {
		return Claims{}, wrap(ErrSessionInvalid, "iss mismatch")
	}
	if len(c.Audience) != 1 || c.Audience[0] != s.audience {
		return Claims{}, wrap(ErrSessionInvalid, "aud mismatch")
	}
	if !s.now().Before(c.Expiry()) {
		return Claims{}, wrap(ErrSessionInvalid, "expired")
	}
	if s.deny.Revoked(c.SID) {
		return Claims{}, ErrSessionRevoked
	}
	return c, nil
}

// Revoke puts the session of token on the deny list and returns its claims.
func (s *Signer) Revoke(token string) (Claims, error) {
	c, err := s.Verify(token)
	if err != nil {
		return Claims{}, err
	}
	return c, s.deny.Revoke(c.SID, c.Expiry())
}

// JWKS returns the public key set that other services verify with.
func (s *Signer) JWKS() jose.JWKS {
	pub, _ := jose.PublicJWK(s.key, s.kid)
	return jose.JWKS{Keys: []jose.JWK{pub}}
}

// JWKSHandler serves GET /.well-known/jwks.json (ADR-012 decision 2).
func (s *Signer) JWKSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		WriteJSON(w, http.StatusOK, s.JWKS())
	})
}

// GenerateKey creates a fresh P-256 key for a signer.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// ParseKeyPEM reads an EC or PKCS#8 PEM private key.
func ParseKeyPEM(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("oidcflow: no PEM block in signing key")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("oidcflow: parse signing key: %w", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("oidcflow: signing key type %T is not ECDSA", k)
	}
	return ec, nil
}

// EncodeKeyPEM writes a key as an EC PRIVATE KEY PEM block.
func EncodeKeyPEM(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("oidcflow: encode signing key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
