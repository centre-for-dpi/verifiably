// SPDX-License-Identifier: Apache-2.0

// Package grants keeps the IdP tokens of a session sealed with AES-GCM,
// so the portal can present one as the OID4VCI authorization grant
// (ADR-020 decision 3). The plain tokens exist only in memory during a
// call. The persisted document holds ciphertext.
package grants

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// Errors of this package.
var (
	// ErrNotFound reports a session with no stored grant.
	ErrNotFound = errors.New("grants: no grant for this session")
	// ErrExpired reports a grant whose IdP token expired.
	ErrExpired = errors.New("grants: the grant expired")
	// ErrBound reports a grant that another credential issuer holds.
	ErrBound = errors.New("grants: the grant is bound to another credential issuer")
)

// Grant is the plain form of a stored grant.
type Grant struct {
	// AccessToken is the IdP access token.
	AccessToken string `json:"access_token"`
	// IDToken is the IdP ID token, for id_token_hint at logout.
	IDToken string `json:"id_token"`
	// ExpiresAt is when the access token stops working.
	ExpiresAt time.Time `json:"expires_at"`
	// CredentialIssuer is the issuer the grant is bound to. Empty until
	// the first Take.
	CredentialIssuer string `json:"credential_issuer,omitempty"`
}

type sealed struct {
	Nonce string `json:"n"`
	Data  string `json:"d"`
}

const doc = "grants"

// Vault seals grants with one AES-256-GCM key and persists ciphertext.
type Vault struct {
	aead  cipher.AEAD
	store oidcflow.Persister
	now   func() time.Time
	mu    sync.Mutex
	m     map[string]sealed
}

// New returns a vault. key must have 32 bytes.
func New(key []byte, store oidcflow.Persister, now func() time.Time) (*Vault, error) {
	if len(key) != 32 {
		return nil, errors.New("grants: key must have 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("grants: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("grants: %w", err)
	}
	if store == nil {
		store = oidcflow.NewMemoryPersister()
	}
	if now == nil {
		now = time.Now
	}
	m := map[string]sealed{}
	if err := store.Load(doc, &m); err != nil {
		return nil, err
	}
	return &Vault{aead: aead, store: store, now: now, m: m}, nil
}

// Put seals g under sid. Expired entries are dropped on every Put.
func (v *Vault) Put(sid string, g Grant) error {
	plain, err := json.Marshal(g)
	if err != nil {
		return fmt.Errorf("grants: %w", err)
	}
	nonce := make([]byte, v.aead.NonceSize())
	// crypto/rand cannot fail on a platform that Go supports.
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	ct := v.aead.Seal(nil, nonce, plain, []byte(sid))
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweep()
	v.m[sid] = sealed{Nonce: base64.RawURLEncoding.EncodeToString(nonce), Data: base64.RawURLEncoding.EncodeToString(ct)}
	return v.save()
}

// Take returns the grant of sid bound to credentialIssuer. The first
// call with an issuer binds the grant to it. A later call for another
// issuer fails with ErrBound. An empty issuer reads without binding.
func (v *Vault) Take(sid, credentialIssuer string) (Grant, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	g, err := v.open(sid)
	if err != nil {
		return Grant{}, err
	}
	if !v.now().Before(g.ExpiresAt) {
		return Grant{}, ErrExpired
	}
	if credentialIssuer != "" && g.CredentialIssuer != "" && g.CredentialIssuer != credentialIssuer {
		return Grant{}, ErrBound
	}
	if g.CredentialIssuer == "" && credentialIssuer != "" {
		g.CredentialIssuer = credentialIssuer
		if err := v.seal(sid, g); err != nil {
			return Grant{}, err
		}
	}
	return g, nil
}

// IDToken returns the ID token of sid, or "" when none is stored.
func (v *Vault) IDToken(sid string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	g, err := v.open(sid)
	if err != nil {
		return ""
	}
	return g.IDToken
}

// Delete removes the grant of sid.
func (v *Vault) Delete(sid string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.m[sid]; !ok {
		return nil
	}
	delete(v.m, sid)
	return v.save()
}

func (v *Vault) open(sid string) (Grant, error) {
	s, ok := v.m[sid]
	if !ok {
		return Grant{}, ErrNotFound
	}
	nonce, err1 := base64.RawURLEncoding.DecodeString(s.Nonce)
	ct, err2 := base64.RawURLEncoding.DecodeString(s.Data)
	if err1 != nil || err2 != nil || len(nonce) != v.aead.NonceSize() {
		return Grant{}, fmt.Errorf("%w: stored grant is corrupt", ErrNotFound)
	}
	plain, err := v.aead.Open(nil, nonce, ct, []byte(sid))
	if err != nil {
		return Grant{}, fmt.Errorf("%w: stored grant does not open with this key", ErrNotFound)
	}
	var g Grant
	if err := json.Unmarshal(plain, &g); err != nil {
		return Grant{}, fmt.Errorf("%w: stored grant is corrupt", ErrNotFound)
	}
	return g, nil
}

func (v *Vault) seal(sid string, g Grant) error {
	plain, ignored := json.Marshal(g)
	_ = ignored
	nonce := make([]byte, v.aead.NonceSize())
	// crypto/rand cannot fail on a platform that Go supports.
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	ct := v.aead.Seal(nil, nonce, plain, []byte(sid))
	prev := v.m[sid]
	v.m[sid] = sealed{Nonce: base64.RawURLEncoding.EncodeToString(nonce), Data: base64.RawURLEncoding.EncodeToString(ct)}
	if err := v.save(); err != nil {
		v.m[sid] = prev
		return err
	}
	return nil
}

// sweep drops entries whose token expired. It opens each entry, so it
// runs only on Put.
func (v *Vault) sweep() {
	t := v.now()
	for sid := range v.m {
		g, err := v.open(sid)
		if err != nil || !t.Before(g.ExpiresAt) {
			delete(v.m, sid)
		}
	}
}

func (v *Vault) save() error {
	return v.store.Save(doc, v.m)
}
