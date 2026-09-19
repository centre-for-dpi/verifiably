// SPDX-License-Identifier: Apache-2.0

package lists

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/keys"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// Store key prefixes.
const (
	RecordPrefix = "lists/"
	SignedPrefix = "signed/"
)

// PathPrefix is the URL path under the base URL where a list is served.
const PathPrefix = "/status/"

// DefaultTTL is the validity of a signature when Options.TTL is zero.
const DefaultTTL = 24 * time.Hour

// Artifact is one signed representation of a list.
type Artifact struct {
	// MediaType is the media type the service serves the body with.
	MediaType string `json:"media_type"`
	// Body is the signed bytes exactly as served.
	Body []byte `json:"body"`
	// ETag is the strong entity tag of the body.
	ETag string `json:"etag"`
}

// Signed is the stored signature of one list (ADR-018 decision 5).
type Signed struct {
	ListID string `json:"list_id"`
	// KeyID is the kid of the signing key.
	KeyID string `json:"key_id"`
	// IssuerDID is the issuer identifier in the signed bytes.
	IssuerDID string    `json:"issuer_did"`
	SignedAt  time.Time `json:"signed_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Artifacts holds one entry per media type. The first is the default.
	Artifacts []Artifact `json:"artifacts"`
}

// Artifact returns the artifact with the media type. Empty selects the
// default. The second value is false when none matches.
func (s Signed) Artifact(mediaType string) (Artifact, bool) {
	if len(s.Artifacts) == 0 {
		return Artifact{}, false
	}
	if mediaType == "" {
		return s.Artifacts[0], true
	}
	for _, a := range s.Artifacts {
		if strings.EqualFold(a.MediaType, mediaType) {
			return a, true
		}
	}
	return Artifact{}, false
}

// Unsigned is one representation before the manager adds the ETag.
type Unsigned struct {
	MediaType string
	Body      []byte
}

// Securer signs a list. The bitstring service and the token service
// each provide one (ADR-019 decision 4).
type Securer interface {
	// Kind returns the kind of list the securer signs.
	Kind() Kind
	// MediaTypes lists the media types Secure returns, default first.
	MediaTypes() []string
	// Secure signs rec with the active key of issuer. url is the public
	// URL of the list. It returns one body per media type in the order
	// of MediaTypes.
	Secure(rec Record, issuer keys.Issuer, url string, signedAt, expiresAt time.Time) ([]Unsigned, error)
}

// Allocation is the result of Allocate.
type Allocation struct {
	ListID  string
	Index   int
	URL     string
	Purpose Purpose
}

// Options configure Open.
type Options struct {
	Store   store.KeyValue
	Issuers *keys.Issuers
	Securer Securer
	// BaseURL is the public root URL. A list URL is BaseURL + "/status/" + id.
	BaseURL string
	// Size is the number of entries of a new list. A bitstring list is
	// raised to bitstring.MinSize.
	Size int
	// DefaultBits is the status width of a new list when the caller
	// asks for none. Zero means 1.
	DefaultBits int
	// TTL is the validity of a signature. Zero means DefaultTTL.
	TTL time.Duration
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Rand is the entropy source for ids and indices. Nil means crypto/rand.
	Rand io.Reader
}

// Manager owns the records and their signatures.
type Manager struct {
	mu      sync.Mutex
	opts    Options
	records map[string]Record
	signed  map[string]Signed
}

// Open loads every record and signature from the store.
func Open(ctx context.Context, opts Options) (*Manager, error) {
	if opts.Store == nil || opts.Issuers == nil || opts.Securer == nil {
		return nil, errors.New("lists: Store, Issuers, and Securer are required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.TTL <= 0 {
		opts.TTL = DefaultTTL
	}
	if opts.DefaultBits <= 0 {
		opts.DefaultBits = 1
	}
	opts.BaseURL = strings.TrimRight(opts.BaseURL, "/")
	m := &Manager{opts: opts, records: map[string]Record{}, signed: map[string]Signed{}}
	if err := loadAll(ctx, opts.Store, RecordPrefix, m.records, func(r Record) string { return r.ID }); err != nil {
		return nil, err
	}
	if err := loadAll(ctx, opts.Store, SignedPrefix, m.signed, func(s Signed) string { return s.ListID }); err != nil {
		return nil, err
	}
	for id, r := range m.records {
		if r.Kind != opts.Securer.Kind() {
			return nil, fmt.Errorf("lists: list %s has kind %s, this service serves %s", id, r.Kind, opts.Securer.Kind())
		}
	}
	return m, nil
}

func loadAll[T any](ctx context.Context, kv store.KeyValue, prefix string, into map[string]T, id func(T) string) error {
	ks, err := kv.List(ctx, prefix)
	if err != nil {
		return fmt.Errorf("lists: %w", err)
	}
	for _, k := range ks {
		data, err := kv.Get(ctx, k)
		if err != nil {
			return fmt.Errorf("lists: %w", err)
		}
		var v T
		if err := json.Unmarshal(data, &v); err != nil {
			return fmt.Errorf("lists: parse %s: %w", k, err)
		}
		into[id(v)] = v
	}
	return nil
}

// URL returns the public URL of the list with id.
func (m *Manager) URL(id string) string { return m.opts.BaseURL + PathPrefix + id }

// Kind returns the kind this manager serves.
func (m *Manager) Kind() Kind { return m.opts.Securer.Kind() }

// MediaTypes returns the media types the securer produces, default first.
func (m *Manager) MediaTypes() []string { return m.opts.Securer.MediaTypes() }

func (m *Manager) newID() (string, error) {
	rnd := m.opts.Rand
	if rnd == nil {
		return randomHex(16)
	}
	b := make([]byte, 16)
	if _, err := io.ReadFull(rnd, b); err != nil {
		return "", fmt.Errorf("lists: random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Allocate reserves one random index in a list of the issuer with the
// purpose and width. It creates and signs a new list when none has room.
func (m *Manager) Allocate(ctx context.Context, issuerDID string, purpose Purpose, bitsPerEntry int) (Allocation, error) {
	if err := CheckPurpose(purpose); err != nil {
		return Allocation{}, err
	}
	issuer, err := m.opts.Issuers.Resolve(issuerDID)
	if err != nil {
		return Allocation{}, err
	}
	if bitsPerEntry == 0 {
		bitsPerEntry = m.opts.DefaultBits
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.findRoom(issuer.Slug, purpose, bitsPerEntry)
	if !ok {
		rec, err = m.create(ctx, issuer, purpose, bitsPerEntry)
		if err != nil {
			return Allocation{}, err
		}
	}
	idx, err := rec.Allocate(m.opts.Rand)
	if err != nil {
		return Allocation{}, err
	}
	if err := m.saveRecord(ctx, rec); err != nil {
		return Allocation{}, err
	}
	return Allocation{ListID: rec.ID, Index: idx, URL: m.URL(rec.ID), Purpose: purpose}, nil
}

func (m *Manager) findRoom(slug string, purpose Purpose, bitsPerEntry int) (Record, bool) {
	for _, r := range m.sorted() {
		if r.IssuerSlug == slug && r.Purpose == purpose && r.Bits == bitsPerEntry && r.Free() > 0 {
			return r, true
		}
	}
	return Record{}, false
}

func (m *Manager) create(ctx context.Context, issuer keys.Issuer, purpose Purpose, bitsPerEntry int) (Record, error) {
	id, err := m.newID()
	if err != nil {
		return Record{}, err
	}
	rec, err := NewRecord(id, m.Kind(), purpose, bitsPerEntry, m.opts.Size, issuer.Slug, m.opts.Now())
	if err != nil {
		return Record{}, err
	}
	if _, err := m.sign(ctx, rec, issuer); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// sign builds and stores the signature of rec. The caller holds the lock.
func (m *Manager) sign(ctx context.Context, rec Record, issuer keys.Issuer) (Signed, error) {
	now := m.opts.Now().UTC().Truncate(time.Second)
	exp := now.Add(m.opts.TTL)
	bodies, err := m.opts.Securer.Secure(rec, issuer, m.URL(rec.ID), now, exp)
	if err != nil {
		return Signed{}, err
	}
	s := Signed{ListID: rec.ID, KeyID: issuer.Kid(issuer.Active()), IssuerDID: issuer.DID(), SignedAt: now, ExpiresAt: exp}
	for _, b := range bodies {
		s.Artifacts = append(s.Artifacts, Artifact{MediaType: b.MediaType, Body: b.Body, ETag: ETagOf(b.Body)})
	}
	if len(s.Artifacts) == 0 {
		return Signed{}, errors.New("lists: securer returned no artifact")
	}
	data := anyval.Must(json.Marshal(s))
	if err := m.opts.Store.Put(ctx, SignedPrefix+rec.ID, data); err != nil {
		return Signed{}, fmt.Errorf("lists: %w", err)
	}
	m.signed[rec.ID] = s
	return s, nil
}

func (m *Manager) saveRecord(ctx context.Context, rec Record) error {
	data := anyval.Must(json.Marshal(rec))
	if err := m.opts.Store.Put(ctx, RecordPrefix+rec.ID, data); err != nil {
		return fmt.Errorf("lists: %w", err)
	}
	m.records[rec.ID] = rec
	return nil
}

func (m *Manager) issuerOf(rec Record) (keys.Issuer, error) {
	issuer, ok := m.opts.Issuers.BySlug(rec.IssuerSlug)
	if !ok {
		return keys.Issuer{}, fmt.Errorf("%w: list %s belongs to an issuer that is not configured", keys.ErrUnknownIssuer, rec.ID)
	}
	return issuer, nil
}

// Set writes value v at index i of the list and signs the list again.
// It returns the previous value and the new signature.
func (m *Manager) Set(ctx context.Context, id string, i, v int) (int, Signed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[id]
	if !ok {
		return 0, Signed{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	issuer, err := m.issuerOf(rec)
	if err != nil {
		return 0, Signed{}, err
	}
	prev, err := rec.Set(i, v, m.opts.Now())
	if err != nil {
		return 0, Signed{}, err
	}
	s, err := m.sign(ctx, rec, issuer)
	if err != nil {
		return 0, Signed{}, err
	}
	if err := m.saveRecord(ctx, rec); err != nil {
		return 0, Signed{}, err
	}
	return prev, s, nil
}

// Status is the result of Get.
type Status struct {
	Value     int
	Purpose   Purpose
	ChangedAt time.Time
	Changed   bool
}

// Get reads the value at index i of the list.
func (m *Manager) Get(id string, i int) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[id]
	if !ok {
		return Status{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	v, err := rec.Get(i)
	if err != nil {
		return Status{}, err
	}
	st := Status{Value: v, Purpose: rec.Purpose}
	st.ChangedAt, st.Changed = rec.ChangedAt(i)
	return st, nil
}

// Record returns the record of the list.
func (m *Manager) Record(id string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[id]
	if !ok {
		return Record{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return rec, nil
}

// Signed returns the record and the current signature of the list. When
// the signature expired, it signs the list again first.
func (m *Manager) Signed(ctx context.Context, id string) (Record, Signed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[id]
	if !ok {
		return Record{}, Signed{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	s, ok := m.signed[id]
	if ok && m.opts.Now().Before(s.ExpiresAt) {
		return rec, s, nil
	}
	issuer, err := m.issuerOf(rec)
	if err != nil {
		return Record{}, Signed{}, err
	}
	s, err = m.sign(ctx, rec, issuer)
	if err != nil {
		return Record{}, Signed{}, err
	}
	return rec, s, nil
}

// Entry is one row of List.
type Entry struct {
	Record Record
	Signed Signed
}

// Page is the result of List.
type Page struct {
	Entries []Entry
	// NextToken selects the next page. Empty means the last page.
	NextToken string
	Total     int
}

// List returns the lists with the purpose in pages of pageSize, oldest
// first. An empty purpose selects every list. token is the NextToken
// of the previous page or empty.
func (m *Manager) List(purpose Purpose, pageSize int, token string) (Page, error) {
	if pageSize <= 0 {
		return Page{}, errors.New("lists: page size must be positive")
	}
	start := 0
	if token != "" {
		n, err := parseToken(token)
		if err != nil {
			return Page{}, err
		}
		start = n
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []Record
	for _, r := range m.sorted() {
		if purpose == "" || r.Purpose == purpose {
			all = append(all, r)
		}
	}
	if start > len(all) {
		start = len(all)
	}
	end := start + pageSize
	if end > len(all) {
		end = len(all)
	}
	p := Page{Total: len(all)}
	for _, r := range all[start:end] {
		p.Entries = append(p.Entries, Entry{Record: r, Signed: m.signed[r.ID]})
	}
	if end < len(all) {
		p.NextToken = fmt.Sprintf("%d", end)
	}
	return p, nil
}

func parseToken(token string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(token, "%d", &n); err != nil || n < 0 || fmt.Sprintf("%d", n) != token {
		return 0, fmt.Errorf("lists: page token %q is not valid", token)
	}
	return n, nil
}

// sorted returns the records oldest first, then by id. The caller holds
// the lock.
func (m *Manager) sorted() []Record {
	out := make([]Record, 0, len(m.records))
	for _, r := range m.records {
		out = append(out, r)
	}
	sort.Slice(out, func(a, b int) bool {
		if !out[a].CreatedAt.Equal(out[b].CreatedAt) {
			return out[a].CreatedAt.Before(out[b].CreatedAt)
		}
		return out[a].ID < out[b].ID
	})
	return out
}

// Rotation is the result of Rotate.
type Rotation struct {
	KeyID         string
	PreviousKeyID string
	ListsSigned   int
}

// Rotate creates a new key for the issuer and signs every list of the
// issuer with it (ADR-018 decision 6). alg empty keeps the algorithm.
func (m *Manager) Rotate(ctx context.Context, issuerDID string, alg jose.Algorithm) (Rotation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	issuer, retired, err := m.opts.Issuers.Rotate(ctx, issuerDID, alg)
	if err != nil {
		return Rotation{}, err
	}
	out := Rotation{KeyID: issuer.Kid(issuer.Active()), PreviousKeyID: issuer.Kid(retired)}
	for _, r := range m.sorted() {
		if r.IssuerSlug != issuer.Slug {
			continue
		}
		if _, err := m.sign(ctx, r, issuer); err != nil {
			return Rotation{}, err
		}
		out.ListsSigned++
	}
	return out, nil
}

// JWKS returns the public keys of every issuer as a JWKS document.
func (m *Manager) JWKS() []byte { return m.opts.Issuers.JWKSJSON() }

// ETagOf returns the strong entity tag of body.
func ETagOf(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("lists: random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
