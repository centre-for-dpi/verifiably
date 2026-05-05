// Package statuslist implements the two revocation status list formats
// verifiably-go publishes for credentials it has issued:
//
//   - W3C Bitstring Status List 2023 (https://www.w3.org/TR/vc-bitstring-status-list/)
//     for credentials with Std == "w3c_vcdm_2"
//
//   - IETF OAuth Token Status List
//     (https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
//     for credentials with Std == "sd_jwt_vc (IETF)"
//
// Each format is a fixed-size bitstring where bit i represents the
// revocation state of the credential we allocated index i to. A 1 bit means
// "revoked"; 0 means "issued and valid".
//
// Bit ordering DIFFERS between the two specs:
//
//   - W3C BSL 2023 §5.1 — MSB-first within each byte. Bit 0 of the
//     bitstring is the MOST-significant bit of byte 0 (network/big-endian).
//
//   - IETF Token Status List draft-ietf-oauth-status-list §4.2.1 —
//     LSB-first within each byte. Bit 0 is the LEAST-significant bit
//     of byte 0.
//
// The Bitstring type is parameterized on which convention it uses so the
// Store for each kind can construct the right one. Mixing the two would
// cause a verifier (which reads with the spec-mandated ordering) to see a
// freshly-issued credential's bit at a different position than the
// allocator wrote it to — manifesting as "credential reads as revoked
// when it shouldn't" / "Revoke makes the credential valid" polarity flips.
//
// The signing layer in jws.go wraps the encoded payload as a JWT for both
// formats — VCDM 2.0 explicitly permits "Securing VC with JOSE" so a JWT
// containing a BitstringStatusListCredential is a valid status list.
package statuslist

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"sync"
)

// DefaultBits is the size of every list we provision. 131,072 bits =
// 16 KiB uncompressed, well above the W3C-required 16,384-bit minimum and
// roughly the spec-recommended ceiling once compressed (compresses to
// well under 64 KB even fully populated). One list is enough for the
// demo-scale issuance volumes verifiably-go targets.
const DefaultBits = 131072

// Bitstring is a fixed-size mutable bit array. Concurrent calls to Set /
// Get / Encode are safe — every read or mutation goes through the mu.
//
// lsbFirst chooses between W3C BSL 2023 (MSB-first, false) and IETF
// Token Status List (LSB-first, true) bit-position-within-byte conventions.
type Bitstring struct {
	mu       sync.RWMutex
	bits     []byte // length = ceil(size / 8)
	size     int    // number of bits this list can address
	lsbFirst bool   // false = W3C (MSB-first), true = IETF (LSB-first)
}

// New returns an all-zeros W3C-conventional (MSB-first) bitstring of the
// given bit length. Length is rounded up to a multiple of 8 by the
// storage layer (the bitstring still only addresses [0, size)).
func New(size int) *Bitstring {
	return newBitstring(size, false)
}

// NewIETF returns an all-zeros IETF Token Status List bitstring (LSB-first
// bit ordering within each byte). Use this for sd_jwt_vc credentials per
// draft-ietf-oauth-status-list §4.2.1.
func NewIETF(size int) *Bitstring {
	return newBitstring(size, true)
}

func newBitstring(size int, lsbFirst bool) *Bitstring {
	if size <= 0 {
		size = DefaultBits
	}
	return &Bitstring{bits: make([]byte, (size+7)/8), size: size, lsbFirst: lsbFirst}
}

// FromBytes wraps an existing byte buffer (e.g. one we just loaded from
// disk) without copying. size is the addressable bit count, NOT the byte
// count — the caller must ensure len(b)*8 >= size. Defaults to the
// W3C MSB-first convention; use FromBytesIETF for SD-JWT lists.
func FromBytes(b []byte, size int) (*Bitstring, error) {
	return fromBytes(b, size, false)
}

// FromBytesIETF is FromBytes for IETF Token Status List (LSB-first).
func FromBytesIETF(b []byte, size int) (*Bitstring, error) {
	return fromBytes(b, size, true)
}

func fromBytes(b []byte, size int, lsbFirst bool) (*Bitstring, error) {
	if size <= 0 {
		return nil, fmt.Errorf("statuslist: size must be positive")
	}
	if len(b)*8 < size {
		return nil, fmt.Errorf("statuslist: %d bytes too short for %d bits", len(b), size)
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return &Bitstring{bits: cp, size: size, lsbFirst: lsbFirst}, nil
}

// Size returns the number of addressable bits.
func (b *Bitstring) Size() int { return b.size }

// Bytes returns a defensive copy of the raw bit storage.
func (b *Bitstring) Bytes() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]byte, len(b.bits))
	copy(out, b.bits)
	return out
}

// bitPos resolves the (byteIdx, bitMask) pair for index i under whichever
// convention this Bitstring was constructed with.
func (b *Bitstring) bitPos(i int) (int, byte) {
	byteIdx := i / 8
	off := uint(i % 8)
	if !b.lsbFirst {
		off = 7 - off // MSB-first (W3C)
	}
	return byteIdx, 1 << off
}

// Get reads bit i. Out-of-range indices return false (callers shouldn't
// hit this unless the log got corrupted; the caller is responsible for
// staying inside [0, Size())).
func (b *Bitstring) Get(i int) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if i < 0 || i >= b.size {
		return false
	}
	byteIdx, mask := b.bitPos(i)
	return b.bits[byteIdx]&mask != 0
}

// Set assigns bit i. Returns an error on out-of-range so the caller's log
// stays in sync (silent no-ops would mask bugs in the index allocator).
func (b *Bitstring) Set(i int, v bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if i < 0 || i >= b.size {
		return fmt.Errorf("statuslist: index %d out of range [0, %d)", i, b.size)
	}
	byteIdx, mask := b.bitPos(i)
	if v {
		b.bits[byteIdx] |= mask
	} else {
		b.bits[byteIdx] &^= mask
	}
	return nil
}

// EncodeGzipBase64URL produces the W3C BSL 2023 `encodedList` form: gzip
// the raw bytes, base64url-encode without padding. This is the value that
// goes into credentialSubject.encodedList of the published status list VC.
func (b *Bitstring) EncodeGzipBase64URL() (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b.bits); err != nil {
		_ = w.Close()
		return "", fmt.Errorf("statuslist: gzip write: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("statuslist: gzip close: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeGzipBase64URL is the inverse of EncodeGzipBase64URL. Used by tests
// and by any future verifier-side code that needs to round-trip what we
// publish.
func DecodeGzipBase64URL(s string, size int) (*Bitstring, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("statuslist: base64 decode: %w", err)
	}
	gr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("statuslist: gzip reader: %w", err)
	}
	defer gr.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(gr); err != nil {
		return nil, fmt.Errorf("statuslist: gzip read: %w", err)
	}
	return FromBytes(out.Bytes(), size)
}
