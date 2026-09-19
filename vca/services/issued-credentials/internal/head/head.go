// SPDX-License-Identifier: Apache-2.0

// Package head signs the tip of the issued credential hash chain
// (ADR-017 decision 4). An auditor reads the signed head and proves that
// no record went missing.
//
// The service signs the head once a day. A signature stays valid until
// the period ends or the tip moves. The signature is a compact JWS with
// the ES256 algorithm, produced by core/jose.
package head

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// Errors the package returns.
var (
	// ErrNoKey says the signer has no signing key.
	ErrNoKey = errors.New("head: the signer has no key")
	// ErrKeyType says the key is not an ES256 key.
	ErrKeyType = errors.New("head: the signing key must be an EC P-256 key")
	// ErrNoPEM says the file holds no private key block.
	ErrNoPEM = errors.New("head: the file holds no PRIVATE KEY block")
)

// Period is the time between two signatures of an unchanged tip.
const Period = 24 * time.Hour

// TokenType is the typ header of the signed head.
//
//nolint:gosec // G101: the value is a media type, not a credential
const TokenType = "vca-chain-head+jwt"

// Tip is the state of the chain that the store reports.
type Tip struct {
	// RecordID is the id of the record the last entry touched.
	RecordID string
	// Hash is the hash of the last entry, hex encoded.
	Hash string
	// Length is the number of entries in the chain.
	Length int64
}

// Head is one signed tip.
type Head struct {
	// Tip is the state the signature covers.
	Tip Tip
	// SignedAt is the time of the signature.
	SignedAt time.Time
	// JWS is the compact signature over Claims.
	JWS string
	// KeyID is the kid header of the signature.
	KeyID string
}

// IsZero reports whether the head holds no signature.
func (h Head) IsZero() bool { return h.JWS == "" }

// Claims is the JWS payload of a signed head. The names follow the JWT
// registry where one fits.
type Claims struct {
	// Issuer names the deployment that signed the head.
	Issuer string `json:"iss,omitempty"`
	// IssuedAt is the signature time in seconds since the epoch.
	IssuedAt int64 `json:"iat"`
	// RecordID is the id of the last record.
	RecordID string `json:"record_id"`
	// RecordHash is the hash of the last entry, hex encoded.
	RecordHash string `json:"record_hash"`
	// Length is the number of entries in the chain.
	Length int64 `json:"length"`
}

// ClaimsOf returns the payload for tip at signedAt.
func ClaimsOf(issuer string, tip Tip, signedAt time.Time) Claims {
	return Claims{
		Issuer:     issuer,
		IssuedAt:   signedAt.Unix(),
		RecordID:   tip.RecordID,
		RecordHash: tip.Hash,
		Length:     tip.Length,
	}
}

// GenerateKey returns a new ES256 key.
func GenerateKey() (crypto.PrivateKey, error) { return jose.GenerateKey(jose.ES256) }

// ParsePEM reads the first PRIVATE KEY block of data as an ES256 key.
func ParsePEM(data []byte) (crypto.PrivateKey, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, ErrNoPEM
		}
		if block.Type != "PRIVATE KEY" {
			continue
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("head: parse the private key: %w", err)
		}
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			return nil, ErrKeyType
		}
		return key, nil
	}
}

// EncodePEM returns key as one PKCS 8 PEM block.
func EncodePEM(key crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("head: encode the private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// Signer holds the signing key and the last signature.
type Signer struct {
	mu     sync.Mutex
	key    crypto.PrivateKey
	kid    string
	jwk    jose.JWK
	issuer string
	period time.Duration
	last   Head
}

// Options configure a signer.
type Options struct {
	// Key is the ES256 private key. It is required.
	Key crypto.PrivateKey
	// Issuer names the deployment. It may be empty.
	Issuer string
	// Period is the time between two signatures of an unchanged tip.
	// Zero selects Period.
	Period time.Duration
}

// NewSigner builds a signer. It derives the key id from the public key
// thumbprint, so two deployments never share a key id by accident.
func NewSigner(opts Options) (*Signer, error) {
	if opts.Key == nil {
		return nil, ErrNoKey
	}
	ec, ok := opts.Key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrKeyType
	}
	jwk, err := jose.PublicJWK(ec.Public(), "")
	if err != nil {
		return nil, err
	}
	kid, err := jose.Thumbprint(jwk)
	if err != nil {
		return nil, err
	}
	jwk.KeyID = kid
	if opts.Period <= 0 {
		opts.Period = Period
	}
	return &Signer{key: opts.Key, kid: kid, jwk: jwk, issuer: opts.Issuer, period: opts.Period}, nil
}

// KeyID returns the key id of the signer.
func (s *Signer) KeyID() string { return s.kid }

// JWKS returns the public key set. An auditor checks the head with it.
func (s *Signer) JWKS() jose.JWKS { return jose.JWKS{Keys: []jose.JWK{s.jwk}} }

// Sign returns the signed head of tip at now. It reuses the last
// signature while the tip is the same and the period has not ended.
func (s *Signer) Sign(tip Tip, now time.Time) (Head, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fresh(tip, now) {
		return s.last, nil
	}
	token, err := jose.Sign(s.key, s.kid, TokenType, ClaimsOf(s.issuer, tip, now))
	if err != nil {
		return Head{}, err
	}
	s.last = Head{Tip: tip, SignedAt: now, JWS: token, KeyID: s.kid}
	return s.last, nil
}

// fresh reports whether the last signature still covers tip at now.
func (s *Signer) fresh(tip Tip, now time.Time) bool {
	if s.last.IsZero() || s.last.Tip != tip {
		return false
	}
	return now.Sub(s.last.SignedAt) < s.period
}

// Last returns the last signature without signing again.
func (s *Signer) Last() Head {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// Verify checks token against set and returns the claims. An auditor
// runs the same check.
func Verify(token string, set jose.JWKS) (Claims, error) {
	payload, _, err := jose.VerifyWithJWKS(token, set, []jose.Algorithm{jose.ES256})
	if err != nil {
		return Claims{}, err
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, fmt.Errorf("head: decode the claims: %w", err)
	}
	return c, nil
}
