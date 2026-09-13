// SPDX-License-Identifier: Apache-2.0

// Package bitstring implements the W3C Bitstring Status List v1.0
// (https://www.w3.org/TR/vc-bitstring-status-list/).
//
// A list is a fixed size bit array. Bit i holds the status of the
// credential that was allocated index i. Bit 0 is the most significant
// bit of byte 0 (section 3.2). The encoded form is multibase base64url
// (prefix "u") of the GZIP compressed bytes.
//
// The package is pure. A List is a value with no locks. Callers that
// share a List across goroutines must serialise access themselves.
package bitstring

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

// MinSize is the minimum number of entries a list must hold
// (section 3.1: at least 131,072 entries, 16 KiB uncompressed).
const MinSize = 131072

// MaxDecodedBytes bounds the uncompressed size Decode accepts.
// It protects the decoder against compression bombs.
const MaxDecodedBytes = 16 << 20

// Purpose is a statusPurpose value (section 3.1).
type Purpose string

// Purposes defined by the specification.
const (
	Revocation Purpose = "revocation"
	Suspension Purpose = "suspension"
	Message    Purpose = "message"
)

// Type names used in credentialSubject and credentialStatus.
const (
	TypeCredential = "BitstringStatusListCredential"
	TypeList       = "BitstringStatusList"
	TypeEntry      = "BitstringStatusListEntry"
	ContextV2      = "https://www.w3.org/ns/credentials/v2"
)

// ErrOutOfRange reports an index outside the list.
var ErrOutOfRange = errors.New("bitstring: index out of range")

// List is a fixed size bit array with W3C bit order (MSB first).
type List struct {
	bits []byte
	size int
}

// New returns an all-zero list. A size below MinSize is raised to MinSize.
func New(size int) *List {
	if size < MinSize {
		size = MinSize
	}
	return &List{bits: make([]byte, (size+7)/8), size: size}
}

// FromBytes wraps a copy of raw bytes. The list addresses len(b)*8 bits.
func FromBytes(b []byte) *List {
	cp := make([]byte, len(b))
	copy(cp, b)
	return &List{bits: cp, size: len(b) * 8}
}

// Size returns the number of addressable bits.
func (l *List) Size() int { return l.size }

// Bytes returns a copy of the raw bytes.
func (l *List) Bytes() []byte {
	out := make([]byte, len(l.bits))
	copy(out, l.bits)
	return out
}

func (l *List) pos(i int) (int, byte, error) {
	if i < 0 || i >= l.size {
		return 0, 0, fmt.Errorf("%w: %d of %d", ErrOutOfRange, i, l.size)
	}
	return i / 8, 1 << (7 - uint(i%8)), nil
}

// Get reads bit i.
func (l *List) Get(i int) (bool, error) {
	idx, mask, err := l.pos(i)
	if err != nil {
		return false, err
	}
	return l.bits[idx]&mask != 0, nil
}

// Set writes bit i.
func (l *List) Set(i int, v bool) error {
	idx, mask, err := l.pos(i)
	if err != nil {
		return err
	}
	if v {
		l.bits[idx] |= mask
	} else {
		l.bits[idx] &^= mask
	}
	return nil
}

// Encode returns the encodedList value: "u" + base64url(gzip(bytes)).
func (l *List) Encode() string {
	var buf bytes.Buffer
	// Writes to a bytes.Buffer cannot fail.
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(l.bits)
	_ = w.Close()
	return "u" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

// Decode parses an encodedList value produced by Encode or by another
// conforming issuer. The multibase "u" prefix is required.
func Decode(s string) (*List, error) {
	if len(s) == 0 || s[0] != 'u' {
		return nil, errors.New("bitstring: encodedList must use multibase base64url (prefix u)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s[1:])
	if err != nil {
		return nil, fmt.Errorf("bitstring: base64url: %w", err)
	}
	gr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("bitstring: gzip: %w", err)
	}
	out, err := io.ReadAll(io.LimitReader(gr, MaxDecodedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("bitstring: gzip read: %w", err)
	}
	if len(out) > MaxDecodedBytes {
		return nil, errors.New("bitstring: decoded list exceeds MaxDecodedBytes")
	}
	return FromBytes(out), nil
}

// Credential builds an unsigned BitstringStatusListCredential (section 3.1).
// id is the URL where the list is published. issuer is the issuer DID.
func Credential(id, issuer string, purpose Purpose, l *List, validFrom time.Time) map[string]any {
	return map[string]any{
		"@context":  []string{ContextV2},
		"id":        id,
		"type":      []string{"VerifiableCredential", TypeCredential},
		"issuer":    issuer,
		"validFrom": validFrom.UTC().Format(time.RFC3339),
		"credentialSubject": map[string]any{
			"id":            id + "#list",
			"type":          TypeList,
			"statusPurpose": string(purpose),
			"encodedList":   l.Encode(),
		},
	}
}

// Entry builds the credentialStatus object for one credential (section 3.1).
func Entry(listURL string, index int, purpose Purpose) map[string]any {
	return map[string]any{
		"id":                   fmt.Sprintf("%s#%d", listURL, index),
		"type":                 TypeEntry,
		"statusPurpose":        string(purpose),
		"statusListIndex":      strconv.Itoa(index),
		"statusListCredential": listURL,
	}
}

// ParseCredential reads the list and its purpose from a decoded
// BitstringStatusListCredential. The map may be the credential itself
// or a JWT claim set that carries the credential under "vc".
func ParseCredential(doc map[string]any) (Purpose, *List, error) {
	if inner, ok := doc["vc"].(map[string]any); ok {
		doc = inner
	}
	cs, ok := doc["credentialSubject"].(map[string]any)
	if !ok {
		return "", nil, errors.New("bitstring: credentialSubject missing")
	}
	enc, _ := cs["encodedList"].(string)
	if enc == "" {
		return "", nil, errors.New("bitstring: encodedList missing")
	}
	purpose, _ := cs["statusPurpose"].(string)
	if purpose == "" {
		return "", nil, errors.New("bitstring: statusPurpose missing")
	}
	l, err := Decode(enc)
	if err != nil {
		return "", nil, err
	}
	return Purpose(purpose), l, nil
}

// EntryRef is a parsed credentialStatus entry.
type EntryRef struct {
	ListURL string
	Index   int
	Purpose Purpose
}

// ParseEntry reads a BitstringStatusListEntry object.
// statusListIndex is a string per the specification. A number is accepted too.
func ParseEntry(cs map[string]any) (EntryRef, error) {
	if t, _ := cs["type"].(string); t != TypeEntry {
		return EntryRef{}, fmt.Errorf("bitstring: credentialStatus type %q is not %s", t, TypeEntry)
	}
	url, _ := cs["statusListCredential"].(string)
	if url == "" {
		return EntryRef{}, errors.New("bitstring: statusListCredential missing")
	}
	var idx int
	switch v := cs["statusListIndex"].(type) {
	case string:
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return EntryRef{}, fmt.Errorf("bitstring: statusListIndex %q is not a non-negative integer", v)
		}
		idx = n
	case float64:
		if v < 0 || v != float64(int(v)) {
			return EntryRef{}, fmt.Errorf("bitstring: statusListIndex %v is not a non-negative integer", v)
		}
		idx = int(v)
	default:
		return EntryRef{}, errors.New("bitstring: statusListIndex missing")
	}
	purpose, _ := cs["statusPurpose"].(string)
	if purpose == "" {
		purpose = string(Revocation)
	}
	return EntryRef{ListURL: url, Index: idx, Purpose: Purpose(purpose)}, nil
}
