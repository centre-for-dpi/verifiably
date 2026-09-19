// SPDX-License-Identifier: Apache-2.0

// Package keys holds the signing keys of the status list services, one
// ring per issuer (ADR-018 decision 6, ADR-019 decision 4). The
// services sign with ES256 or Ed25519 only. Every key has a kid. A ring
// keeps retired keys so that lists signed before a rotation stay
// verifiable through the JWKS.
//
// An issuer is either a configured DID, for example did:web, or the
// did:jwk of its active key. Rings persist in the key value store, so a
// restart keeps the keys and a rotation keeps the old keys.
package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// Prefix is the store key prefix of the rings.
const Prefix = "keys/"

// DefaultSlug is the store name of the issuer that has no configured DID.
const DefaultSlug = "default"

// ErrUnknownIssuer reports a DID that names no issuer of this service.
var ErrUnknownIssuer = errors.New("keys: unknown issuer")

// Key is one signing key with its identifier.
type Key struct {
	// ID is the kid. It is the RFC 7638 thumbprint.
	ID      string
	Private crypto.PrivateKey
	Alg     jose.Algorithm
	// CreatedAt is the time the key entered the ring.
	CreatedAt time.Time
}

// Public returns the public JWK of the key with kid.
func (k Key) Public(kid string) jose.JWK {
	// Private is ES256 or Ed25519 in a ring built by New. A key of any
	// other type gives the zero JWK, which fails later checks.
	return anyval.OrZero(jose.PublicJWK(k.Private, kid))
}

// DIDJWK returns the did:jwk of the public key.
func (k Key) DIDJWK() string {
	// A key that New did not accept gives "", which fails later checks.
	m := anyval.OrZero(jose.JWKToMap(k.Public("")))
	return anyval.OrZero(did.FromJWK(m))
}

// New wraps a private key. It checks the key type and sets the kid to
// the thumbprint.
func New(private crypto.PrivateKey, now time.Time) (Key, error) {
	alg, err := jose.AlgorithmFor(private)
	if err != nil {
		return Key{}, fmt.Errorf("keys: %w", err)
	}
	if ec, ok := private.(*ecdsa.PrivateKey); ok && ec.Curve != elliptic.P256() {
		return Key{}, fmt.Errorf("keys: unsupported curve %s", ec.Curve.Params().Name)
	}
	// AlgorithmFor accepted the key above, so PublicJWK cannot fail.
	jwk := anyval.Must(jose.PublicJWK(private, ""))
	kid, err := jose.Thumbprint(jwk)
	if err != nil {
		return Key{}, err
	}
	return Key{ID: kid, Private: private, Alg: alg, CreatedAt: now.UTC()}, nil
}

// Generate creates a new key for alg (ES256 or EdDSA).
func Generate(alg jose.Algorithm, now time.Time) (Key, error) {
	private, err := jose.GenerateKey(alg)
	if err != nil {
		return Key{}, fmt.Errorf("keys: %w", err)
	}
	return New(private, now)
}

// ParsePEM reads every PRIVATE KEY block (PKCS #8) in data. The first
// block is the active key. The others are retired keys.
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
		k, err := New(private, now)
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

// Slug returns the store name of an issuer DID. Empty means DefaultSlug.
func Slug(issuerDID string) string {
	if issuerDID == "" {
		return DefaultSlug
	}
	sum := sha256.Sum256([]byte(issuerDID))
	return hex.EncodeToString(sum[:8])
}

// Issuer is one issuer with its key ring. The first key is active. The
// rest are retired, newest first.
type Issuer struct {
	// ConfiguredDID is the configured issuer DID. Empty means the issuer
	// is the did:jwk of its active key.
	ConfiguredDID string
	// Slug is the store name.
	Slug string
	Keys []Key
}

// Active returns the signing key.
func (i Issuer) Active() Key { return i.Keys[0] }

// DID returns the issuer identifier used in signed lists.
func (i Issuer) DID() string {
	if i.ConfiguredDID != "" {
		return i.ConfiguredDID
	}
	return i.Active().DIDJWK()
}

// Kid returns the JWS header kid of k for this issuer. A did:jwk issuer
// uses the verification method id of its DID document.
func (i Issuer) Kid(k Key) string {
	if i.ConfiguredDID != "" {
		return k.ID
	}
	return k.DIDJWK() + "#0"
}

// Matches reports whether d names this issuer. A did:jwk issuer matches
// the did:jwk of every key in its ring, so lists signed before a
// rotation still resolve.
func (i Issuer) Matches(d string) bool {
	if i.ConfiguredDID != "" {
		return d == i.ConfiguredDID
	}
	for _, k := range i.Keys {
		if k.DIDJWK() == d {
			return true
		}
	}
	return false
}

// JWKS returns the public keys of the ring.
func (i Issuer) JWKS() jose.JWKS {
	var set jose.JWKS
	for _, k := range i.Keys {
		set.Keys = append(set.Keys, k.Public(i.Kid(k)))
	}
	return set
}

// document is the stored form of a ring.
type document struct {
	ConfiguredDID string        `json:"configured_did,omitempty"`
	Keys          []keyDocument `json:"keys"`
}

type keyDocument struct {
	PKCS8     []byte    `json:"pkcs8"`
	CreatedAt time.Time `json:"created_at"`
}

func encode(i Issuer) ([]byte, error) {
	doc := document{ConfiguredDID: i.ConfiguredDID}
	for _, k := range i.Keys {
		der, err := x509.MarshalPKCS8PrivateKey(k.Private)
		if err != nil {
			return nil, fmt.Errorf("keys: encode: %w", err)
		}
		doc.Keys = append(doc.Keys, keyDocument{PKCS8: der, CreatedAt: k.CreatedAt})
	}
	return json.Marshal(doc)
}

func decode(slug string, data []byte) (Issuer, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return Issuer{}, fmt.Errorf("keys: parse ring %s: %w", slug, err)
	}
	i := Issuer{ConfiguredDID: doc.ConfiguredDID, Slug: slug}
	for _, kd := range doc.Keys {
		private, err := x509.ParsePKCS8PrivateKey(kd.PKCS8)
		if err != nil {
			return Issuer{}, fmt.Errorf("keys: parse ring %s: %w", slug, err)
		}
		k, err := New(private, kd.CreatedAt)
		if err != nil {
			return Issuer{}, err
		}
		i.Keys = append(i.Keys, k)
	}
	if len(i.Keys) == 0 {
		return Issuer{}, fmt.Errorf("keys: ring %s has no key", slug)
	}
	return i, nil
}

// Options configure Open.
type Options struct {
	// Configured lists the issuer DIDs. Empty means one did:jwk issuer.
	// The first entry is the default issuer.
	Configured []string
	// Alg is the algorithm of a generated key.
	Alg jose.Algorithm
	// ImportPEM holds PKCS #8 keys for the default issuer. It is used
	// only when the store has no ring for it yet.
	ImportPEM []byte
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Issuers holds every ring behind a mutex and saves after each change.
type Issuers struct {
	mu      sync.RWMutex
	kv      store.KeyValue
	now     func() time.Time
	order   []string
	issuers map[string]Issuer
	// Generated is true when Open made a new key for the default issuer.
	Generated bool
}

// Open loads the rings from kv. It creates a ring for every configured
// issuer that has none.
func Open(ctx context.Context, kv store.KeyValue, opts Options) (*Issuers, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Alg == "" {
		opts.Alg = jose.ES256
	}
	dids := opts.Configured
	if len(dids) == 0 {
		dids = []string{""}
	}
	is := &Issuers{kv: kv, now: opts.Now, issuers: map[string]Issuer{}}
	seen := map[string]bool{}
	for idx, d := range dids {
		slug := Slug(d)
		if seen[slug] {
			return nil, fmt.Errorf("keys: issuer %q is listed twice", d)
		}
		seen[slug] = true
		i, err := is.load(ctx, slug, d)
		if errors.Is(err, store.ErrNotFound) {
			i, err = is.create(ctx, slug, d, opts, idx == 0)
		}
		if err != nil {
			return nil, err
		}
		is.order = append(is.order, slug)
		is.issuers[slug] = i
	}
	return is, nil
}

func (is *Issuers) load(ctx context.Context, slug, configured string) (Issuer, error) {
	data, err := is.kv.Get(ctx, Prefix+slug)
	if err != nil {
		return Issuer{}, err
	}
	i, err := decode(slug, data)
	if err != nil {
		return Issuer{}, err
	}
	if i.ConfiguredDID != configured {
		return Issuer{}, fmt.Errorf("keys: ring %s belongs to issuer %q, not %q", slug, i.ConfiguredDID, configured)
	}
	return i, nil
}

func (is *Issuers) create(ctx context.Context, slug, configured string, opts Options, first bool) (Issuer, error) {
	now := is.now()
	i := Issuer{ConfiguredDID: configured, Slug: slug}
	var err error
	if first && len(opts.ImportPEM) > 0 {
		i.Keys, err = ParsePEM(opts.ImportPEM, now)
	} else {
		var k Key
		k, err = Generate(opts.Alg, now)
		i.Keys = []Key{k}
		if first {
			is.Generated = true
		}
	}
	if err != nil {
		return Issuer{}, err
	}
	if err := is.save(ctx, i); err != nil {
		return Issuer{}, err
	}
	return i, nil
}

func (is *Issuers) save(ctx context.Context, i Issuer) error {
	data, err := encode(i)
	if err != nil {
		return err
	}
	return is.kv.Put(ctx, Prefix+i.Slug, data)
}

// Default returns the default issuer.
func (is *Issuers) Default() Issuer {
	is.mu.RLock()
	defer is.mu.RUnlock()
	return is.issuers[is.order[0]]
}

// Resolve returns the issuer that d names. Empty selects the default.
func (is *Issuers) Resolve(d string) (Issuer, error) {
	if d == "" {
		return is.Default(), nil
	}
	is.mu.RLock()
	defer is.mu.RUnlock()
	for _, slug := range is.order {
		if i := is.issuers[slug]; i.Matches(d) {
			return i, nil
		}
	}
	return Issuer{}, fmt.Errorf("%w: %s", ErrUnknownIssuer, d)
}

// BySlug returns the issuer with the store name slug.
func (is *Issuers) BySlug(slug string) (Issuer, bool) {
	is.mu.RLock()
	defer is.mu.RUnlock()
	i, ok := is.issuers[slug]
	return i, ok
}

// All returns every issuer in configuration order.
func (is *Issuers) All() []Issuer {
	is.mu.RLock()
	defer is.mu.RUnlock()
	out := make([]Issuer, 0, len(is.order))
	for _, slug := range is.order {
		out = append(out, is.issuers[slug])
	}
	return out
}

// Rotate makes a new key the active key of the issuer that d names.
// alg empty keeps the algorithm of the current key. It returns the
// issuer after the rotation and the retired key.
func (is *Issuers) Rotate(ctx context.Context, d string, alg jose.Algorithm) (Issuer, Key, error) {
	cur, err := is.Resolve(d)
	if err != nil {
		return Issuer{}, Key{}, err
	}
	if alg == "" {
		alg = cur.Active().Alg
	}
	k, err := Generate(alg, is.now())
	if err != nil {
		return Issuer{}, Key{}, err
	}
	is.mu.Lock()
	defer is.mu.Unlock()
	cur = is.issuers[cur.Slug]
	next := Issuer{ConfiguredDID: cur.ConfiguredDID, Slug: cur.Slug, Keys: append([]Key{k}, cur.Keys...)}
	if err := is.save(ctx, next); err != nil {
		return Issuer{}, Key{}, err
	}
	is.issuers[cur.Slug] = next
	return next, cur.Active(), nil
}

// JWKSJSON returns the public keys of every issuer as one JWKS
// document (RFC 7517 section 5).
func (is *Issuers) JWKSJSON() []byte {
	var set jose.JWKS
	for _, i := range is.All() {
		set.Keys = append(set.Keys, i.JWKS().Keys...)
	}
	sort.SliceStable(set.Keys, func(a, b int) bool { return set.Keys[a].KeyID < set.Keys[b].KeyID })
	// Every key encodes, so Marshal cannot fail.
	out := anyval.Must(json.Marshal(set))
	return out
}
