// SPDX-License-Identifier: Apache-2.0

// Package lists keeps the status lists of one service: the records with
// their values, the random index allocation, and the signed copies
// (ADR-018 decisions 3, 4, 5 and ADR-019 decisions 3, 4). The bitstring
// and the token service share this package. They differ only in the
// Securer that builds the signed bytes.
//
// A Record is a value. The Manager owns the records, serialises access,
// and writes every change to the key value store.
package lists

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"strconv"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/statuslist/bitstring"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/token"
)

// Kind names the status list standard.
type Kind string

// Kinds.
const (
	KindBitstring Kind = "bitstring"
	KindToken     Kind = "token"
)

// Purpose names what a status value means (ADR-018 decision 3).
type Purpose string

// Purposes.
const (
	Revocation Purpose = "revocation"
	Suspension Purpose = "suspension"
	Message    Purpose = "message"
)

// Errors of the package.
var (
	ErrFull         = errors.New("lists: list is full")
	ErrNotAllocated = errors.New("lists: index is not allocated")
	ErrNotFound     = errors.New("lists: list not found")
	ErrBadPurpose   = errors.New("lists: unsupported purpose")
	ErrBadKind      = errors.New("lists: unsupported kind")
	ErrBadValue     = errors.New("lists: unsupported status value")
	ErrOutOfRange   = errors.New("lists: index is out of range")
)

// CheckPurpose reports whether p is a supported purpose.
func CheckPurpose(p Purpose) error {
	switch p {
	case Revocation, Suspension, Message:
		return nil
	}
	return fmt.Errorf("%w: %q", ErrBadPurpose, p)
}

// Record is one status list with its bookkeeping.
type Record struct {
	// ID is the list id. It is a random hex string.
	ID      string  `json:"id"`
	Kind    Kind    `json:"kind"`
	Purpose Purpose `json:"purpose"`
	// Bits is the status width. A bitstring list uses 1.
	Bits int `json:"bits"`
	// Size is the number of entries.
	Size int `json:"size"`
	// IssuerSlug is the store name of the issuer that signs the list.
	IssuerSlug string    `json:"issuer_slug"`
	CreatedAt  time.Time `json:"created_at"`
	// Allocated is a bit map, most significant bit first. Bit i is set
	// when index i is allocated. Padding bits past Size are set.
	Allocated []byte `json:"allocated"`
	// AllocatedCount is the number of allocated indices.
	AllocatedCount int `json:"allocated_count"`
	// Values holds the status values in the layout of the kind.
	Values []byte `json:"values"`
	// Changed maps a decimal index to the time of its last change.
	Changed map[string]time.Time `json:"changed,omitempty"`
}

// NewRecord returns an empty record. A bitstring list uses 1 bit and at
// least bitstring.MinSize entries. A token list uses bits of 1, 2, 4, or 8.
func NewRecord(id string, kind Kind, purpose Purpose, bitsPerEntry, size int, issuerSlug string, now time.Time) (Record, error) {
	if err := CheckPurpose(purpose); err != nil {
		return Record{}, err
	}
	var values []byte
	switch kind {
	case KindBitstring:
		if bitsPerEntry == 0 {
			bitsPerEntry = 1
		}
		if bitsPerEntry != 1 {
			return Record{}, fmt.Errorf("lists: a bitstring list uses 1 bit, got %d", bitsPerEntry)
		}
		l := bitstring.New(size)
		size = l.Size()
		values = l.Bytes()
	case KindToken:
		if bitsPerEntry == 0 {
			bitsPerEntry = 1
		}
		l, err := token.New(bitsPerEntry, size)
		if err != nil {
			return Record{}, err
		}
		values = l.Bytes()
	default:
		return Record{}, fmt.Errorf("%w: %q", ErrBadKind, kind)
	}
	allocated := make([]byte, (size+7)/8)
	for i := size; i < len(allocated)*8; i++ {
		allocated[i/8] |= 1 << (7 - i%8)
	}
	return Record{
		ID: id, Kind: kind, Purpose: purpose, Bits: bitsPerEntry, Size: size,
		IssuerSlug: issuerSlug, CreatedAt: now.UTC(), Allocated: allocated, Values: values,
	}, nil
}

// Free returns the number of indices the record can still allocate.
func (r Record) Free() int { return r.Size - r.AllocatedCount }

// IsAllocated reports whether index i is allocated.
func (r Record) IsAllocated(i int) bool {
	if i < 0 || i >= r.Size {
		return false
	}
	return r.Allocated[i/8]&(1<<(7-i%8)) != 0
}

// Allocate picks one free index at random and marks it allocated
// (ADR-018 decision 4). rnd is the entropy source. Nil means crypto/rand.
// An index is never allocated twice.
func (r *Record) Allocate(rnd io.Reader) (int, error) {
	free := r.Free()
	if free <= 0 {
		return 0, ErrFull
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	n, err := rand.Int(rnd, big.NewInt(int64(free)))
	if err != nil {
		return 0, fmt.Errorf("lists: random index: %w", err)
	}
	pick := int(n.Int64())
	for byteIdx, b := range r.Allocated {
		zeros := 8 - bits.OnesCount8(b)
		if pick >= zeros {
			pick -= zeros
			continue
		}
		for bit := 0; bit < 8; bit++ {
			mask := byte(1 << (7 - bit))
			if b&mask != 0 {
				continue
			}
			if pick == 0 {
				r.Allocated[byteIdx] |= mask
				r.AllocatedCount++
				return byteIdx*8 + bit, nil
			}
			pick--
		}
	}
	// Free counted an index that the bit map does not show. The record
	// is corrupt.
	return 0, errors.New("lists: allocation bit map does not match the count")
}

// Get reads the value at index i.
func (r Record) Get(i int) (int, error) {
	switch r.Kind {
	case KindBitstring:
		v, err := bitstring.FromBytes(r.Values).Get(i)
		if err != nil {
			return 0, fmt.Errorf("%w: %w", ErrOutOfRange, err)
		}
		if v {
			return 1, nil
		}
		return 0, nil
	default:
		l, err := token.FromBytes(r.Bits, r.Values)
		if err != nil {
			return 0, err
		}
		v, err := l.Get(i)
		if err != nil {
			return 0, fmt.Errorf("%w: %w", ErrOutOfRange, err)
		}
		return int(v), nil
	}
}

// Set writes value v at the allocated index i and records the time. It
// returns the previous value.
func (r *Record) Set(i, v int, now time.Time) (int, error) {
	if !r.IsAllocated(i) {
		return 0, fmt.Errorf("%w: %d", ErrNotAllocated, i)
	}
	prev, err := r.Get(i)
	if err != nil {
		return 0, err
	}
	if v < 0 || v > 255 {
		return 0, fmt.Errorf("%w: %d", ErrBadValue, v)
	}
	switch r.Kind {
	case KindBitstring:
		if v > 1 {
			return 0, fmt.Errorf("%w: %d does not fit in 1 bit", ErrBadValue, v)
		}
		l := bitstring.FromBytes(r.Values)
		// i is allocated, so it is in range.
		_ = l.Set(i, v == 1)
		r.Values = l.Bytes()
	default:
		// Bits and Values are valid by construction.
		l, _ := token.FromBytes(r.Bits, r.Values)
		if err := l.Set(i, uint8(v)); err != nil {
			return 0, fmt.Errorf("%w: %d does not fit in %d bits", ErrBadValue, v, r.Bits)
		}
		r.Values = l.Bytes()
	}
	if r.Changed == nil {
		r.Changed = map[string]time.Time{}
	}
	r.Changed[strconv.Itoa(i)] = now.UTC()
	return prev, nil
}

// ChangedAt returns the time of the last change of index i. The second
// value is false when the index never changed.
func (r Record) ChangedAt(i int) (time.Time, bool) {
	t, ok := r.Changed[strconv.Itoa(i)]
	return t, ok
}

// BitstringList returns the values as a bitstring list.
func (r Record) BitstringList() *bitstring.List { return bitstring.FromBytes(r.Values) }

// TokenList returns the values as a token list.
func (r Record) TokenList() (*token.List, error) { return token.FromBytes(r.Bits, r.Values) }
