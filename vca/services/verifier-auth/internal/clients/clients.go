// SPDX-License-Identifier: Apache-2.0

// Package clients holds the machine clients that get tokens with the
// OAuth 2.0 client credentials grant (ADR-012 decision 4).
package clients

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// Errors of this package.
var (
	// ErrNotFound reports an unknown client id.
	ErrNotFound = errors.New("clients: client not found")
	// ErrInvalid reports a create request without a name or a role.
	ErrInvalid = errors.New("clients: display name and one role are required")
)

// Client is one registered machine client. The secret is never stored.
type Client struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"display_name"`
	TenantID    string     `json:"tenant_id"`
	Roles       []string   `json:"roles"`
	SecretHash  string     `json:"secret_hash"`
	Prefix      string     `json:"prefix"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// Active reports whether the client can get a token at now.
func (c Client) Active(now time.Time) bool {
	if c.RevokedAt != nil {
		return false
	}
	return c.ExpiresAt == nil || now.Before(*c.ExpiresAt)
}

const doc = "clients"

// Registry stores clients through a Persister.
type Registry struct {
	store oidcflow.Persister
	now   func() time.Time
	mu    sync.RWMutex
	m     map[string]Client
}

// New loads the registry from store.
func New(store oidcflow.Persister, now func() time.Time) (*Registry, error) {
	if now == nil {
		now = time.Now
	}
	var list []Client
	if err := store.Load(doc, &list); err != nil {
		return nil, err
	}
	r := &Registry{store: store, now: now, m: map[string]Client{}}
	for _, c := range list {
		r.m[c.ID] = c
	}
	return r, nil
}

// Create registers a client and returns it with the secret, once.
func (r *Registry) Create(displayName, tenantID string, roles []string, expiresAt *time.Time) (Client, string, error) {
	if displayName == "" || len(roles) == 0 {
		return Client{}, "", ErrInvalid
	}
	secret := random(32)
	c := Client{
		ID:          random(12),
		DisplayName: displayName,
		TenantID:    tenantID,
		Roles:       append([]string(nil), roles...),
		SecretHash:  hash(secret),
		Prefix:      secret[:8],
		CreatedAt:   r.now().UTC(),
		ExpiresAt:   expiresAt,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[c.ID] = c
	if err := r.save(); err != nil {
		delete(r.m, c.ID)
		return Client{}, "", err
	}
	return c, secret, nil
}

// List returns the clients of a tenant, or all when tenantID is empty.
func (r *Registry) List(tenantID string) []Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Client
	for _, c := range r.m {
		if tenantID == "" || c.TenantID == tenantID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Revoke disables a client at once.
func (r *Registry) Revoke(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.m[id]
	if !ok {
		return ErrNotFound
	}
	prev := c
	t := r.now().UTC()
	c.RevokedAt = &t
	r.m[id] = c
	if err := r.save(); err != nil {
		r.m[id] = prev
		return err
	}
	return nil
}

// Authenticate checks id and secret and returns the client when it is
// active. A wrong secret and an unknown id give the same error.
func (r *Registry) Authenticate(id, secret string) (Client, error) {
	r.mu.RLock()
	c, ok := r.m[id]
	r.mu.RUnlock()
	if !ok {
		// Burn the same time as a real comparison.
		subtle.ConstantTimeCompare([]byte(hash(secret)), []byte(hash("")))
		return Client{}, oidcflow.ErrUnauthorized
	}
	if subtle.ConstantTimeCompare([]byte(hash(secret)), []byte(c.SecretHash)) != 1 || !c.Active(r.now()) {
		return Client{}, oidcflow.ErrUnauthorized
	}
	return c, nil
}

func (r *Registry) save() error {
	list := make([]Client, 0, len(r.m))
	for _, c := range r.m {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	return r.store.Save(doc, list)
}

func hash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func random(n int) string {
	b := make([]byte, n)
	// crypto/rand cannot fail on a platform that Go supports.
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
