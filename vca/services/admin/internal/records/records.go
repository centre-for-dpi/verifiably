// SPDX-License-Identifier: Apache-2.0

// Package records keeps the state the admin service owns: tenants,
// machine API keys, the super admin bindings, and the one time
// bootstrap token (ADR-009, ADR-010 decision 4).
//
// The package stores JSON documents in the shared key value store. It
// holds no secret value: an API key is stored as a SHA-256 hash, and
// the bootstrap token is stored as a SHA-256 hash too.
package records

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// Errors of the package.
var (
	// ErrNotFound reports a record that does not exist.
	ErrNotFound = errors.New("records: not found")
	// ErrInvalid reports a record that fails validation.
	ErrInvalid = errors.New("records: invalid")
	// ErrBootstrapUsed reports a bootstrap token that is already spent.
	ErrBootstrapUsed = errors.New("records: the bootstrap token is used")
	// ErrBootstrapToken reports a wrong bootstrap token.
	ErrBootstrapToken = errors.New("records: the bootstrap token is wrong")
)

// MaxDisplayName is the length limit of a display name.
const MaxDisplayName = 200

// SecretPrefix marks an API key secret.
const SecretPrefix = "vca_"

// Key prefixes in the store.
const (
	tenantPrefix = "tenants/"
	keyPrefix    = "apikeys/"
	indexPrefix  = "keyindex/"
	adminPrefix  = "admins/"
	bootstrapKey = "bootstrap"
)

// States of a tenant.
const (
	StateActive    = "active"
	StateSuspended = "suspended"
)

// Tenant is one operator organisation.
type Tenant struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	State       string    `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// APIKey is one machine credential without its secret value.
type APIKey struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	TenantID    string    `json:"tenant_id"`
	Roles       []string  `json:"roles"`
	Prefix      string    `json:"prefix"`
	Hash        string    `json:"hash"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	RevokedAt   time.Time `json:"revoked_at,omitempty"`
}

// Active reports whether the key works at t.
func (k APIKey) Active(t time.Time) bool {
	if !k.RevokedAt.IsZero() {
		return false
	}
	return k.ExpiresAt.IsZero() || t.Before(k.ExpiresAt)
}

// Admin is one subject that holds the super admin role.
type Admin struct {
	Issuer  string    `json:"issuer"`
	Subject string    `json:"subject"`
	BoundAt time.Time `json:"bound_at"`
}

// bootstrap is the persisted state of the one time token.
type bootstrap struct {
	Hash   string    `json:"hash"`
	UsedAt time.Time `json:"used_at,omitempty"`
}

// Store reads and writes the admin records.
type Store struct {
	kv  store.KeyValue
	now func() time.Time
}

// New returns a store over kv. A nil clock selects time.Now.
func New(kv store.KeyValue, now func() time.Time) (*Store, error) {
	if kv == nil {
		return nil, errors.New("records: a key value store is required")
	}
	if now == nil {
		now = time.Now
	}
	return &Store{kv: kv, now: now}, nil
}

// CreateTenant stores one new tenant with an assigned id.
func (s *Store) CreateTenant(ctx context.Context, displayName string) (Tenant, error) {
	name, err := checkName(displayName)
	if err != nil {
		return Tenant{}, err
	}
	t := s.now().UTC()
	tenant := Tenant{ID: NewID(), DisplayName: name, State: StateActive, CreatedAt: t, UpdatedAt: t}
	if err := put(ctx, s.kv, tenantPrefix+tenant.ID, tenant); err != nil {
		return Tenant{}, err
	}
	return tenant, nil
}

// GetTenant returns one tenant.
func (s *Store) GetTenant(ctx context.Context, id string) (Tenant, error) {
	var tenant Tenant
	if err := get(ctx, s.kv, tenantPrefix+id, &tenant); err != nil {
		return Tenant{}, err
	}
	return tenant, nil
}

// ListTenants returns every tenant sorted by creation time, oldest first.
func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	keys, err := s.kv.List(ctx, tenantPrefix)
	if err != nil {
		return nil, fmt.Errorf("records: %w", err)
	}
	out := make([]Tenant, 0, len(keys))
	for _, k := range keys {
		var tenant Tenant
		if err := get(ctx, s.kv, k, &tenant); err != nil {
			return nil, err
		}
		out = append(out, tenant)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// UpdateTenant changes the display name, the state, or both. An empty
// name and an empty state keep the current values.
func (s *Store) UpdateTenant(ctx context.Context, id, displayName, state string) (Tenant, error) {
	tenant, err := s.GetTenant(ctx, id)
	if err != nil {
		return Tenant{}, err
	}
	if displayName != "" {
		name, err := checkName(displayName)
		if err != nil {
			return Tenant{}, err
		}
		tenant.DisplayName = name
	}
	switch state {
	case "":
	case StateActive, StateSuspended:
		tenant.State = state
	default:
		return Tenant{}, fmt.Errorf("%w: state %q is not active or suspended", ErrInvalid, state)
	}
	tenant.UpdatedAt = s.now().UTC()
	if err := put(ctx, s.kv, tenantPrefix+tenant.ID, tenant); err != nil {
		return Tenant{}, err
	}
	return tenant, nil
}

// DeleteTenant removes one tenant and every API key it owns.
func (s *Store) DeleteTenant(ctx context.Context, id string) error {
	if _, err := s.GetTenant(ctx, id); err != nil {
		return err
	}
	keys, err := s.ListKeys(ctx, id)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := s.deleteKey(ctx, k); err != nil {
			return err
		}
	}
	return del(ctx, s.kv, tenantPrefix+id)
}

// KeySpec describes a new API key.
type KeySpec struct {
	DisplayName string
	TenantID    string
	Roles       []string
	ExpiresAt   time.Time
}

// CreateKey stores one new API key and returns its secret value once.
func (s *Store) CreateKey(ctx context.Context, spec KeySpec) (APIKey, string, error) {
	name, err := checkName(spec.DisplayName)
	if err != nil {
		return APIKey{}, "", err
	}
	if strings.TrimSpace(spec.TenantID) == "" {
		return APIKey{}, "", fmt.Errorf("%w: tenant_id is required", ErrInvalid)
	}
	if _, err := s.GetTenant(ctx, spec.TenantID); err != nil {
		return APIKey{}, "", err
	}
	if len(spec.Roles) == 0 {
		return APIKey{}, "", fmt.Errorf("%w: at least one role is required", ErrInvalid)
	}
	secret := NewSecret()
	key := APIKey{
		ID:          NewID(),
		DisplayName: name,
		TenantID:    spec.TenantID,
		Roles:       append([]string(nil), spec.Roles...),
		Prefix:      secret[:8],
		Hash:        Hash(secret),
		CreatedAt:   s.now().UTC(),
		ExpiresAt:   spec.ExpiresAt.UTC(),
	}
	if spec.ExpiresAt.IsZero() {
		key.ExpiresAt = time.Time{}
	}
	if err := put(ctx, s.kv, keyPrefix+key.ID, key); err != nil {
		return APIKey{}, "", err
	}
	if err := put(ctx, s.kv, indexPrefix+key.Hash, key.ID); err != nil {
		return APIKey{}, "", err
	}
	return key, secret, nil
}

// ListKeys returns the keys of one tenant, or every key when tenantID
// is empty. The list is sorted by creation time, oldest first.
func (s *Store) ListKeys(ctx context.Context, tenantID string) ([]APIKey, error) {
	keys, err := s.kv.List(ctx, keyPrefix)
	if err != nil {
		return nil, fmt.Errorf("records: %w", err)
	}
	out := make([]APIKey, 0, len(keys))
	for _, k := range keys {
		var key APIKey
		if err := get(ctx, s.kv, k, &key); err != nil {
			return nil, err
		}
		if tenantID != "" && key.TenantID != tenantID {
			continue
		}
		out = append(out, key)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// RevokeKey disables one key at once.
func (s *Store) RevokeKey(ctx context.Context, id string) (APIKey, error) {
	var key APIKey
	if err := get(ctx, s.kv, keyPrefix+id, &key); err != nil {
		return APIKey{}, err
	}
	if key.RevokedAt.IsZero() {
		key.RevokedAt = s.now().UTC()
	}
	if err := put(ctx, s.kv, keyPrefix+key.ID, key); err != nil {
		return APIKey{}, err
	}
	return key, nil
}

// Authenticate returns the key behind a secret value. It returns
// ErrNotFound when no active key matches.
func (s *Store) Authenticate(ctx context.Context, secret string) (APIKey, error) {
	if !strings.HasPrefix(secret, SecretPrefix) {
		return APIKey{}, ErrNotFound
	}
	var id string
	if err := get(ctx, s.kv, indexPrefix+Hash(secret), &id); err != nil {
		return APIKey{}, ErrNotFound
	}
	var key APIKey
	if err := get(ctx, s.kv, keyPrefix+id, &key); err != nil {
		return APIKey{}, ErrNotFound
	}
	if subtle.ConstantTimeCompare([]byte(key.Hash), []byte(Hash(secret))) != 1 {
		return APIKey{}, ErrNotFound
	}
	if !key.Active(s.now()) {
		return APIKey{}, ErrNotFound
	}
	return key, nil
}

// deleteKey removes one key and its index entry.
func (s *Store) deleteKey(ctx context.Context, key APIKey) error {
	if err := del(ctx, s.kv, indexPrefix+key.Hash); err != nil {
		return err
	}
	return del(ctx, s.kv, keyPrefix+key.ID)
}

// BindAdmin gives the super admin role to one iss and sub pair.
func (s *Store) BindAdmin(ctx context.Context, issuer, subject string) (Admin, error) {
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(subject) == "" {
		return Admin{}, fmt.Errorf("%w: issuer and subject are required", ErrInvalid)
	}
	admin := Admin{Issuer: strings.TrimRight(issuer, "/"), Subject: subject, BoundAt: s.now().UTC()}
	if err := put(ctx, s.kv, adminPrefix+AdminKey(issuer, subject), admin); err != nil {
		return Admin{}, err
	}
	return admin, nil
}

// IsAdmin reports whether one iss and sub pair holds the super admin role.
func (s *Store) IsAdmin(ctx context.Context, issuer, subject string) bool {
	var admin Admin
	return get(ctx, s.kv, adminPrefix+AdminKey(issuer, subject), &admin) == nil
}

// CountAdmins returns the number of bound super admins.
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	keys, err := s.kv.List(ctx, adminPrefix)
	if err != nil {
		return 0, fmt.Errorf("records: %w", err)
	}
	return len(keys), nil
}

// ListAdmins returns every bound super admin sorted by issuer and subject.
func (s *Store) ListAdmins(ctx context.Context) ([]Admin, error) {
	keys, err := s.kv.List(ctx, adminPrefix)
	if err != nil {
		return nil, fmt.Errorf("records: %w", err)
	}
	out := make([]Admin, 0, len(keys))
	for _, k := range keys {
		var admin Admin
		if err := get(ctx, s.kv, k, &admin); err != nil {
			return nil, err
		}
		out = append(out, admin)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Issuer == out[j].Issuer {
			return out[i].Subject < out[j].Subject
		}
		return out[i].Issuer < out[j].Issuer
	})
	return out, nil
}

// SetBootstrap stores the hash of the one time bootstrap token. A call
// with the same token keeps the used mark, so a restart does not make a
// spent token work again.
func (s *Store) SetBootstrap(ctx context.Context, token string) error {
	if len(token) < 16 {
		return fmt.Errorf("%w: the bootstrap token needs at least 16 characters", ErrInvalid)
	}
	hash := Hash(token)
	var cur bootstrap
	if err := get(ctx, s.kv, bootstrapKey, &cur); err == nil && cur.Hash == hash {
		return nil
	}
	return put(ctx, s.kv, bootstrapKey, bootstrap{Hash: hash})
}

// BootstrapPending reports whether a bootstrap token waits for a login.
func (s *Store) BootstrapPending(ctx context.Context) bool {
	var cur bootstrap
	if err := get(ctx, s.kv, bootstrapKey, &cur); err != nil {
		return false
	}
	return cur.UsedAt.IsZero()
}

// ConsumeBootstrap checks the token and marks it spent. It returns
// ErrBootstrapToken for a wrong token and ErrBootstrapUsed for a spent
// token.
func (s *Store) ConsumeBootstrap(ctx context.Context, token string) error {
	var cur bootstrap
	if err := get(ctx, s.kv, bootstrapKey, &cur); err != nil {
		return ErrBootstrapToken
	}
	if !cur.UsedAt.IsZero() {
		return ErrBootstrapUsed
	}
	if subtle.ConstantTimeCompare([]byte(cur.Hash), []byte(Hash(token))) != 1 {
		return ErrBootstrapToken
	}
	cur.UsedAt = s.now().UTC()
	return put(ctx, s.kv, bootstrapKey, cur)
}

// AdminKey returns the store key segment of one iss and sub pair. The
// segment is a hash, so any character in a claim is safe in a key.
func AdminKey(issuer, subject string) string {
	return Hash(strings.TrimRight(issuer, "/") + "|" + subject)
}

// Hash returns the hex SHA-256 of a value.
func Hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// NewID returns a random record id of 22 characters.
func NewID() string {
	b := make([]byte, 16)
	// crypto/rand cannot fail on a platform that Go supports.
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewSecret returns a new API key secret. The value starts with vca_.
func NewSecret() string {
	b := make([]byte, 32)
	// crypto/rand cannot fail on a platform that Go supports.
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return SecretPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// NewBootstrapToken returns a random bootstrap token (ADR-010 decision 4).
func NewBootstrapToken() string {
	b := make([]byte, 24)
	// crypto/rand cannot fail on a platform that Go supports.
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// checkName trims and checks a display name.
func checkName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("%w: display_name is required", ErrInvalid)
	}
	if len([]rune(name)) > MaxDisplayName {
		return "", fmt.Errorf("%w: display_name has more than %d characters", ErrInvalid, MaxDisplayName)
	}
	return name, nil
}

func put(ctx context.Context, kv store.KeyValue, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("records: %w", err)
	}
	if err := kv.Put(ctx, key, raw); err != nil {
		return fmt.Errorf("records: %w", err)
	}
	return nil
}

func get(ctx context.Context, kv store.KeyValue, key string, v any) error {
	raw, err := kv.Get(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("%w: %s", ErrNotFound, key)
	}
	if err != nil {
		return fmt.Errorf("records: %w", err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("records: %s: %w", key, err)
	}
	return nil
}

func del(ctx context.Context, kv store.KeyValue, key string) error {
	if err := kv.Delete(ctx, key); err != nil {
		return fmt.Errorf("records: %w", err)
	}
	return nil
}
