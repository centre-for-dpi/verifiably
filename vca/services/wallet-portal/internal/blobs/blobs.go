// SPDX-License-Identifier: Apache-2.0

// Package blobs is the browser side credential store
// (ADR-021 decision 4). A deployment with no DPG wallet keeps every
// credential in the browser. The browser encrypts each credential with
// a key it derives from the holder key of ADR-020 decision 4. The
// server keeps the ciphertext only, keyed by the wallet key of the
// citizen.
//
// The server never holds the content key. It cannot read a blob.
//
// The envelope is a small JSON document:
//
//	{"v":1,"kdf":"HKDF-SHA256","alg":"A256GCM","iv":"<base64url>","ct":"<base64url>"}
//
// The browser file internal/static/wallet.js writes the same document
// with WebCrypto. The Go functions here follow that format, so a test
// can check one format against both sides.
package blobs

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// Version is the envelope version this package writes.
const Version = 1

// AlgGCM names the content encryption of the envelope.
const AlgGCM = "A256GCM"

// KDF names the key derivation of the envelope.
const KDF = "HKDF-SHA256"

// Info is the HKDF info string. The browser uses the same text.
const Info = "vca-wallet-blob-v1"

// Salt is the HKDF salt. The browser uses the same bytes.
const Salt = "vca-wallet-portal"

// KeyBytes is the length of the content key.
const KeyBytes = 32

// NonceBytes is the length of the AES-GCM nonce.
const NonceBytes = 12

// Errors the package returns.
var (
	// ErrBadEnvelope reports an envelope the package cannot read.
	ErrBadEnvelope = errors.New("blobs: the envelope is not valid")
	// ErrTooLarge reports a blob above the size limit.
	ErrTooLarge = errors.New("blobs: the blob is too large")
	// ErrBadID reports an id the store cannot key.
	ErrBadID = errors.New("blobs: the id has a character the store rejects")
	// ErrNotFound reports a blob that does not exist.
	ErrNotFound = errors.New("blobs: no such blob")
)

// Envelope is one encrypted credential as the browser wrote it.
type Envelope struct {
	// Version is the envelope version.
	Version int `json:"v"`
	// KDF names the key derivation.
	KDF string `json:"kdf"`
	// Alg names the content encryption.
	Alg string `json:"alg"`
	// IV is the AES-GCM nonce, base64url without padding.
	IV string `json:"iv"`
	// CT is the ciphertext with the tag, base64url without padding.
	CT string `json:"ct"`
}

// Check reports whether the envelope has the shape this package writes.
func (e Envelope) Check() error {
	switch {
	case e.Version != Version:
		return fmt.Errorf("%w: version %d", ErrBadEnvelope, e.Version)
	case e.KDF != KDF:
		return fmt.Errorf("%w: key derivation %q", ErrBadEnvelope, e.KDF)
	case e.Alg != AlgGCM:
		return fmt.Errorf("%w: content encryption %q", ErrBadEnvelope, e.Alg)
	case e.IV == "" || e.CT == "":
		return fmt.Errorf("%w: the nonce or the ciphertext is empty", ErrBadEnvelope)
	}
	return nil
}

// Marshal returns the envelope as JSON.
func Marshal(e Envelope) ([]byte, error) {
	if err := e.Check(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

// Parse reads an envelope from JSON.
func Parse(raw []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrBadEnvelope, err)
	}
	if err := e.Check(); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

// DeriveKey returns the content key for a shared secret. The browser
// gets the secret from a WebCrypto ECDH derivation over its holder key.
func DeriveKey(secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("blobs: the secret is empty")
	}
	key, err := hkdf.Key(sha256.New, secret, []byte(Salt), Info, KeyBytes)
	if err != nil {
		return nil, fmt.Errorf("blobs: derive the key: %w", err)
	}
	return key, nil
}

// Seal encrypts plaintext with key and returns the envelope.
func Seal(key, plaintext []byte) (Envelope, error) {
	gcm, err := mode(key)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, fmt.Errorf("blobs: read random bytes: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return Envelope{
		Version: Version, KDF: KDF, Alg: AlgGCM,
		IV: b64(nonce), CT: b64(ct),
	}, nil
}

// Open decrypts an envelope with key.
func Open(key []byte, e Envelope) ([]byte, error) {
	if err := e.Check(); err != nil {
		return nil, err
	}
	gcm, err := mode(key)
	if err != nil {
		return nil, err
	}
	nonce, err := unb64(e.IV)
	if err != nil || len(nonce) != NonceBytes {
		return nil, fmt.Errorf("%w: the nonce is not %d bytes", ErrBadEnvelope, NonceBytes)
	}
	ct, err := unb64(e.CT)
	if err != nil {
		return nil, fmt.Errorf("%w: the ciphertext is not base64url", ErrBadEnvelope)
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: the content key does not open it", ErrBadEnvelope)
	}
	return plain, nil
}

// mode returns the AES-GCM mode for key.
func mode(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyBytes {
		return nil, fmt.Errorf("blobs: the key needs %d bytes, got %d", KeyBytes, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("blobs: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("blobs: %w", err)
	}
	return gcm, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// Record is one stored blob with its metadata. The metadata carries no
// personal data: the server cannot read the credential.
type Record struct {
	// ID is the blob id the browser chose.
	ID string `json:"id"`
	// Envelope holds the ciphertext.
	Envelope Envelope `json:"envelope"`
	// StoredAt is the time the server wrote the blob.
	StoredAt time.Time `json:"stored_at"`
}

// Store keeps the ciphertext blobs of every citizen.
type Store struct {
	kv       store.KeyValue
	maxBytes int64
	now      func() time.Time
}

// DefaultMaxBytes caps one blob.
const DefaultMaxBytes = 256 << 10

// NewStore returns a store over kv. A maxBytes of zero or less means
// DefaultMaxBytes. A nil now means time.Now.
func NewStore(kv store.KeyValue, maxBytes int64, now func() time.Time) (*Store, error) {
	if kv == nil {
		return nil, errors.New("blobs: a key value store is required")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if now == nil {
		now = time.Now
	}
	return &Store{kv: kv, maxBytes: maxBytes, now: now}, nil
}

// Prefix is the first key segment of every blob.
const Prefix = "blob"

// key returns the store key of one blob.
func key(wallet, id string) (string, error) {
	if strings.TrimSpace(wallet) == "" {
		return "", fmt.Errorf("%w: the wallet key is empty", ErrBadID)
	}
	if strings.TrimSpace(id) == "" {
		return "", fmt.Errorf("%w: the id is empty", ErrBadID)
	}
	if strings.ContainsAny(wallet+id, "/") {
		return "", fmt.Errorf("%w: a slash is not allowed", ErrBadID)
	}
	full := Prefix + "/" + wallet + "/" + id
	if err := store.ValidateKey(full); err != nil {
		return "", fmt.Errorf("%w: %w", ErrBadID, err)
	}
	return full, nil
}

// Put writes one blob. It replaces a blob with the same id.
func (s *Store) Put(ctx context.Context, wallet, id string, e Envelope) (Record, error) {
	k, err := key(wallet, id)
	if err != nil {
		return Record{}, err
	}
	rec := Record{ID: id, Envelope: e, StoredAt: s.now().UTC()}
	raw, err := json.Marshal(rec)
	if err != nil {
		return Record{}, fmt.Errorf("blobs: encode the record: %w", err)
	}
	if int64(len(raw)) > s.maxBytes {
		return Record{}, ErrTooLarge
	}
	if err := e.Check(); err != nil {
		return Record{}, err
	}
	if err := s.kv.Put(ctx, k, raw); err != nil {
		return Record{}, fmt.Errorf("blobs: write %s: %w", id, err)
	}
	return rec, nil
}

// Get returns one blob.
func (s *Store) Get(ctx context.Context, wallet, id string) (Record, error) {
	k, err := key(wallet, id)
	if err != nil {
		return Record{}, err
	}
	raw, err := s.kv.Get(ctx, k)
	if errors.Is(err, store.ErrNotFound) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("blobs: read %s: %w", id, err)
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Record{}, fmt.Errorf("%w: %w", ErrBadEnvelope, err)
	}
	return rec, nil
}

// List returns every blob of one wallet, oldest key first.
func (s *Store) List(ctx context.Context, wallet string) ([]Record, error) {
	if strings.TrimSpace(wallet) == "" {
		return nil, fmt.Errorf("%w: the wallet key is empty", ErrBadID)
	}
	keys, err := s.kv.List(ctx, Prefix+"/"+wallet+"/")
	if err != nil {
		return nil, fmt.Errorf("blobs: list %s: %w", wallet, err)
	}
	sort.Strings(keys)
	out := make([]Record, 0, len(keys))
	for _, k := range keys {
		id := k[strings.LastIndex(k, "/")+1:]
		rec, err := s.Get(ctx, wallet, id)
		if err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

// Delete removes one blob. A missing blob is not an error.
func (s *Store) Delete(ctx context.Context, wallet, id string) error {
	k, err := key(wallet, id)
	if err != nil {
		return err
	}
	if err := s.kv.Delete(ctx, k); err != nil {
		return fmt.Errorf("blobs: remove %s: %w", id, err)
	}
	return nil
}

// MaxBytes returns the size limit of one blob.
func (s *Store) MaxBytes() int64 { return s.maxBytes }
