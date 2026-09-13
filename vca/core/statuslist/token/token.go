// SPDX-License-Identifier: Apache-2.0

// Package token implements the IETF Token Status List
// (draft-ietf-oauth-status-list, https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/).
//
// A list is a byte array that holds one status per index. Each status
// uses 1, 2, 4 or 8 bits. Index 0 sits in the least significant bits of
// byte 0 (section 4.1). The list is compressed with zlib (DEFLATE) and
// base64url encoded in the JWT form, or carried as a byte string in the
// CWT form.
//
// The package is pure. A List is a value with no locks.
package token

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"
)

// Status values defined by the specification (section 7.1).
const (
	Valid     uint8 = 0x00
	Invalid   uint8 = 0x01
	Suspended uint8 = 0x02
)

// Media types and JOSE/COSE typ values (section 5).
const (
	TypeJWT = "statuslist+jwt"
	TypeCWT = "statuslist+cwt"
)

// MaxDecodedBytes bounds the uncompressed size a decoder accepts.
const MaxDecodedBytes = 16 << 20

// ErrOutOfRange reports an index outside the list.
var ErrOutOfRange = errors.New("token: index out of range")

// List is a status list with a fixed status width.
type List struct {
	bits int
	data []byte
	size int
}

func checkBits(bits int) error {
	switch bits {
	case 1, 2, 4, 8:
		return nil
	}
	return fmt.Errorf("token: bits must be 1, 2, 4 or 8, got %d", bits)
}

// New returns an all-zero list of size entries with the given status width.
func New(bits, size int) (*List, error) {
	if err := checkBits(bits); err != nil {
		return nil, err
	}
	if size <= 0 {
		return nil, errors.New("token: size must be positive")
	}
	perByte := 8 / bits
	return &List{bits: bits, data: make([]byte, (size+perByte-1)/perByte), size: size}, nil
}

// FromBytes wraps a copy of raw list bytes.
func FromBytes(bits int, data []byte) (*List, error) {
	if err := checkBits(bits); err != nil {
		return nil, err
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return &List{bits: bits, data: cp, size: len(data) * (8 / bits)}, nil
}

// Bits returns the status width.
func (l *List) Bits() int { return l.bits }

// Size returns the number of entries.
func (l *List) Size() int { return l.size }

// Bytes returns a copy of the raw bytes.
func (l *List) Bytes() []byte {
	out := make([]byte, len(l.data))
	copy(out, l.data)
	return out
}

func (l *List) pos(i int) (int, uint, error) {
	if i < 0 || i >= l.size {
		return 0, 0, fmt.Errorf("%w: %d of %d", ErrOutOfRange, i, l.size)
	}
	perByte := 8 / l.bits
	return i / perByte, uint(i%perByte) * uint(l.bits), nil
}

// Get reads the status at index i.
func (l *List) Get(i int) (uint8, error) {
	idx, shift, err := l.pos(i)
	if err != nil {
		return 0, err
	}
	mask := byte(1<<uint(l.bits) - 1)
	return (l.data[idx] >> shift) & mask, nil
}

// Set writes the status at index i. v must fit in the status width.
func (l *List) Set(i int, v uint8) error {
	idx, shift, err := l.pos(i)
	if err != nil {
		return err
	}
	mask := byte(1<<uint(l.bits) - 1)
	if v > mask {
		return fmt.Errorf("token: status %d does not fit in %d bits", v, l.bits)
	}
	l.data[idx] = (l.data[idx] &^ (mask << shift)) | (v << shift)
	return nil
}

// Compress returns the zlib compressed list bytes (the CWT lst value).
func (l *List) Compress() []byte {
	var buf bytes.Buffer
	// Writes to a bytes.Buffer cannot fail.
	w, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	_, _ = w.Write(l.data)
	_ = w.Close()
	return buf.Bytes()
}

// Encode returns the base64url form of Compress (the JWT lst value).
func (l *List) Encode() string {
	return base64.RawURLEncoding.EncodeToString(l.Compress())
}

// Decompress parses zlib compressed list bytes.
func Decompress(bits int, raw []byte) (*List, error) {
	if err := checkBits(bits); err != nil {
		return nil, err
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("token: zlib: %w", err)
	}
	out, err := io.ReadAll(io.LimitReader(zr, MaxDecodedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("token: zlib read: %w", err)
	}
	if len(out) > MaxDecodedBytes {
		return nil, errors.New("token: decoded list exceeds MaxDecodedBytes")
	}
	return FromBytes(bits, out)
}

// Decode parses a base64url lst value.
func Decode(bits int, lst string) (*List, error) {
	raw, err := base64.RawURLEncoding.DecodeString(lst)
	if err != nil {
		return nil, fmt.Errorf("token: base64url: %w", err)
	}
	return Decompress(bits, raw)
}

// Claims are the registered claims of a Status List Token (section 5).
type Claims struct {
	Issuer         string
	Subject        string
	IssuedAt       time.Time
	ExpiresAt      time.Time     // zero: no exp claim
	TTL            time.Duration // zero: no ttl claim
	AggregationURI string
}

// JWTClaims builds the claim set of a Status List JWT (section 5.1).
// The token must be signed with typ "statuslist+jwt".
func JWTClaims(c Claims, l *List) map[string]any {
	sl := map[string]any{"bits": l.Bits(), "lst": l.Encode()}
	if c.AggregationURI != "" {
		sl["aggregation_uri"] = c.AggregationURI
	}
	out := map[string]any{
		"iss":         c.Issuer,
		"sub":         c.Subject,
		"iat":         c.IssuedAt.Unix(),
		"status_list": sl,
	}
	if !c.ExpiresAt.IsZero() {
		out["exp"] = c.ExpiresAt.Unix()
	}
	if c.TTL > 0 {
		out["ttl"] = int64(c.TTL / time.Second)
	}
	return out
}

// ParseJWTClaims reads a decoded Status List JWT claim set.
func ParseJWTClaims(m map[string]any) (Claims, *List, error) {
	sub, _ := m["sub"].(string)
	if sub == "" {
		return Claims{}, nil, errors.New("token: sub claim missing")
	}
	iat, ok := m["iat"].(float64)
	if !ok {
		return Claims{}, nil, errors.New("token: iat claim missing")
	}
	sl, ok := m["status_list"].(map[string]any)
	if !ok {
		return Claims{}, nil, errors.New("token: status_list claim missing")
	}
	bits, _ := sl["bits"].(float64)
	lst, _ := sl["lst"].(string)
	l, err := Decode(int(bits), lst)
	if err != nil {
		return Claims{}, nil, err
	}
	c := Claims{Subject: sub, IssuedAt: time.Unix(int64(iat), 0).UTC()}
	c.Issuer, _ = m["iss"].(string)
	c.AggregationURI, _ = sl["aggregation_uri"].(string)
	if exp, ok := m["exp"].(float64); ok {
		c.ExpiresAt = time.Unix(int64(exp), 0).UTC()
	}
	if ttl, ok := m["ttl"].(float64); ok {
		c.TTL = time.Duration(ttl) * time.Second
	}
	return c, l, nil
}

// Ref is a parsed status claim of a Referenced Token (section 6).
type Ref struct {
	URI   string
	Index int
}

// ParseRef reads the "status" claim of a Referenced Token:
// {"status_list": {"idx": 0, "uri": "https://..."}}.
func ParseRef(status map[string]any) (Ref, error) {
	sl, ok := status["status_list"].(map[string]any)
	if !ok {
		return Ref{}, errors.New("token: status.status_list missing")
	}
	uri, _ := sl["uri"].(string)
	if uri == "" {
		return Ref{}, errors.New("token: status_list.uri missing")
	}
	idx, ok := sl["idx"].(float64)
	if !ok || idx < 0 || idx != float64(int(idx)) {
		return Ref{}, errors.New("token: status_list.idx is not a non-negative integer")
	}
	return Ref{URI: uri, Index: int(idx)}, nil
}
