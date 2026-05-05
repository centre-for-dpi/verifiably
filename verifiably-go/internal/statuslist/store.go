package statuslist

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store wraps a single status list (one Bitstring) plus the disk
// persistence and JWS signing needed to publish it. One Store instance per
// (type, id) pair — typically the issuer keeps two: one bitstring Store
// for W3C VCDM 2.0 credentials, one token Store for SD-JWT.
//
// Concurrency: all mutations go through Allocate / Revoke / Reinstate
// which serialize through s.mu. Publish reads under s.mu.RLock and copies
// out before signing, so two simultaneous status-list HTTP fetches don't
// contend with each other.
type Store struct {
	// Kind is "bitstring" (W3C BSL 2023) or "token" (IETF Token Status List).
	Kind string

	// ListID is the public id of this list ("v1"). Embedded into the
	// publish URL each issuance refers back to via credentialStatus.
	ListID string

	// PublishURL is the absolute URL the verifier will GET to fetch the
	// signed list, e.g. "https://issuer.example/status-list/bitstring/v1".
	// Set at construction by the handler layer that knows the public
	// origin.
	PublishURL string

	// path is where the raw bytes + next-free counter persist. JSON
	// envelope so we can extend it with versioning later if needed.
	path string

	mu       sync.RWMutex
	bits     *Bitstring
	nextFree int
}

// onDisk is the serialized form of a Store's mutable state.
type onDisk struct {
	Size     int    `json:"size"`
	NextFree int    `json:"nextFree"`
	Bits     string `json:"bits"` // base64url of raw bytes, no compression
}

// NewStore opens or creates a status list at path. Kind must be
// "bitstring" or "token" — they share storage but Publish dispatches on
// it. The bitstring is sized to DefaultBits on first creation.
func NewStore(kind, listID, path, publishURL string) (*Store, error) {
	if kind != "bitstring" && kind != "token" {
		return nil, fmt.Errorf("statuslist: unknown kind %q", kind)
	}
	if listID == "" {
		return nil, fmt.Errorf("statuslist: listID required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	s := &Store{Kind: kind, ListID: listID, path: path, PublishURL: publishURL}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// newBitsForKind picks the right bit-ordering convention for this Store.
// kind="bitstring" → W3C MSB-first; kind="token" → IETF LSB-first. Critical:
// passing the wrong convention silently corrupts the wire format — verifiers
// see flipped bits relative to what the allocator wrote.
func (s *Store) newBitsForKind(size int) *Bitstring {
	if s.Kind == "token" {
		return NewIETF(size)
	}
	return New(size)
}

func (s *Store) bitsFromBytes(b []byte, size int) (*Bitstring, error) {
	if s.Kind == "token" {
		return FromBytesIETF(b, size)
	}
	return FromBytes(b, size)
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		s.bits = s.newBitsForKind(DefaultBits)
		s.nextFree = 0
		return s.save()
	}
	if err != nil {
		return fmt.Errorf("statuslist: read %s: %w", s.path, err)
	}
	var d onDisk
	if err := json.Unmarshal(b, &d); err != nil {
		return fmt.Errorf("statuslist: parse %s: %w", s.path, err)
	}
	if d.Size <= 0 {
		d.Size = DefaultBits
	}
	raw, err := base64.RawURLEncoding.DecodeString(d.Bits)
	if err != nil {
		return fmt.Errorf("statuslist: decode raw: %w", err)
	}
	bs, err := s.bitsFromBytes(raw, d.Size)
	if err != nil {
		return fmt.Errorf("statuslist: decode bits: %w", err)
	}
	s.bits = bs
	s.nextFree = d.NextFree
	return nil
}

func (s *Store) save() error {
	b := s.bits.Bytes()
	d := onDisk{
		Size:     s.bits.Size(),
		NextFree: s.nextFree,
		Bits:     encodeRawBytes(b),
	}
	out, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Allocate reserves the next free index and returns it. The bit at that
// index is left at 0 (active). Returns an error if the list is full.
func (s *Store) Allocate() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextFree >= s.bits.Size() {
		return 0, fmt.Errorf("statuslist: list %q full at %d entries", s.ListID, s.bits.Size())
	}
	idx := s.nextFree
	s.nextFree++
	if err := s.save(); err != nil {
		// Roll back so we don't leak indices on disk-write failure.
		s.nextFree--
		return 0, err
	}
	return idx, nil
}

// Revoke flips the bit at index to 1.
func (s *Store) Revoke(index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.bits.Get(index)
	if err := s.bits.Set(index, true); err != nil {
		return err
	}
	if err := s.save(); err != nil {
		_ = s.bits.Set(index, prev)
		return err
	}
	return nil
}

// Reinstate flips the bit at index back to 0. Not yet exposed via UI but
// provided so the API surface is symmetric and future operator features
// can reuse it.
func (s *Store) Reinstate(index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.bits.Get(index)
	if err := s.bits.Set(index, false); err != nil {
		return err
	}
	if err := s.save(); err != nil {
		_ = s.bits.Set(index, prev)
		return err
	}
	return nil
}

// IsRevoked reads bit `index`. Used by tests; production verifiers fetch
// the published list and check themselves.
func (s *Store) IsRevoked(index int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bits.Get(index)
}

// Size returns the number of bits in this list.
func (s *Store) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bits.Size()
}

// NextFree returns the next allocatable index without consuming it.
func (s *Store) NextFree() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nextFree
}

// PublishBitstringJWT signs and returns the W3C BSL 2023 list as a JWT
// containing the BitstringStatusListCredential payload. Per VCDM 2.0
// "Securing Verifiable Credentials with JOSE" the VC payload sits in the
// JWT body as `vc` — verifiers expecting JOSE-secured VCs read it from
// there.
func (s *Store) PublishBitstringJWT(key *SigningKey) (string, error) {
	if s.Kind != "bitstring" {
		return "", fmt.Errorf("statuslist: PublishBitstringJWT called on kind=%q", s.Kind)
	}
	s.mu.RLock()
	encoded, err := s.bits.EncodeGzipBase64URL()
	s.mu.RUnlock()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	vc := map[string]any{
		"@context": []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://w3id.org/vc/status-list/2021/v1",
		},
		"id":   s.PublishURL,
		"type": []string{"VerifiableCredential", "BitstringStatusListCredential"},
		// Issuer is the DID; verifiers resolve it to fetch the JWK.
		"issuer":       key.Issuer(),
		"validFrom":    now.Format(time.RFC3339),
		"credentialSubject": map[string]any{
			"id":            s.PublishURL + "#list",
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   encoded,
		},
	}
	claims := map[string]any{
		"iss": key.Issuer(),
		"sub": s.PublishURL,
		"iat": now.Unix(),
		"vc":  vc,
	}
	return key.SignJWT("vc+jwt", claims)
}

// PublishTokenStatusList signs and returns the IETF Token Status List
// JWT. Per draft-ietf-oauth-status-list, the JWT carries a top-level
// `status_list` claim with `bits: 1` (one bit per credential) and `lst`
// holding the zlib+base64url-encoded bitstring.
func (s *Store) PublishTokenStatusList(key *SigningKey) (string, error) {
	if s.Kind != "token" {
		return "", fmt.Errorf("statuslist: PublishTokenStatusList called on kind=%q", s.Kind)
	}
	s.mu.RLock()
	encoded, err := s.bits.EncodeZlibBase64URL()
	s.mu.RUnlock()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	claims := map[string]any{
		"iss": key.Issuer(),
		"sub": s.PublishURL,
		"iat": now.Unix(),
		"status_list": map[string]any{
			"bits": 1,
			"lst":  encoded,
		},
	}
	return key.SignJWT("statuslist+jwt", claims)
}

// --- helpers ---

// encodeRawBytes writes the bitstring storage to disk as base64url with
// no compression. We don't gzip the at-rest form because gzip headers
// vary across implementations and bit-for-bit equality after a load+save
// round-trip matters for test stability. The decode counterpart lives
// inline in load() so it can dispatch on s.Kind for bit ordering.
func encodeRawBytes(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
