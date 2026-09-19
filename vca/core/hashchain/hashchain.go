// SPDX-License-Identifier: Apache-2.0

// Package hashchain links records with SHA-256 hashes so that a reader
// can prove that no record changed and no record went missing
// (ADR-017 decisions 1 and 4).
//
// Each Entry holds the canonical JSON of a record body, the hash of the
// previous entry, and its own hash. The hash of an entry is SHA-256 over
// the previous hash, a zero byte, and the canonical body. The first entry
// has an empty previous hash.
//
// Canonical JSON sorts object keys at every level and has no white space.
// encoding/json already sorts map keys. Canonical re-encodes any body
// through a generic value, so structs get sorted keys as well.
//
// The package is pure. A Chain is a value. Callers that share a Chain
// across goroutines must serialise access themselves.
package hashchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// Errors the package returns. Callers match them with errors.Is.
var (
	// ErrBrokenLink says an entry does not point at its predecessor.
	ErrBrokenLink = errors.New("hashchain: previous hash does not match")
	// ErrBadHash says the hash of an entry does not match its content.
	ErrBadHash = errors.New("hashchain: entry hash does not match")
)

// Entry is one link of the chain.
type Entry struct {
	// Index is the zero based position of the entry.
	Index int64 `json:"index"`
	// Body is the canonical JSON of the record.
	Body json.RawMessage `json:"body"`
	// PreviousHash is the hex hash of the entry before this one. Empty on
	// the first entry.
	PreviousHash string `json:"previous_hash"`
	// Hash is the hex SHA-256 of PreviousHash, a zero byte, and Body.
	Hash string `json:"hash"`
}

// VerifyError reports the first entry that failed a check.
type VerifyError struct {
	// Index is the position of the failed entry.
	Index int64
	// Err is ErrBrokenLink or ErrBadHash.
	Err error
}

func (e *VerifyError) Error() string { return fmt.Sprintf("%v at index %d", e.Err, e.Index) }

// Unwrap returns the underlying error for errors.Is.
func (e *VerifyError) Unwrap() error { return e.Err }

// Canonical returns the canonical JSON of v.
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("hashchain: encode body: %w", err)
	}
	// Output of json.Marshal always decodes and re-encodes.
	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	anyval.MustDo(dec.Decode(&generic))
	out := anyval.Must(json.Marshal(generic))
	return out, nil
}

// HashOf returns the hex hash of an entry with previousHash and body.
func HashOf(previousHash string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(previousHash))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// Chain is an append only list of entries.
type Chain struct {
	entries []Entry
}

// New returns an empty chain.
func New() Chain { return Chain{} }

// Load builds a chain from stored entries. It verifies every link first.
func Load(entries []Entry) (Chain, error) {
	if err := Verify(entries); err != nil {
		return Chain{}, err
	}
	return Chain{entries: append([]Entry(nil), entries...)}, nil
}

// Append adds body to the chain and returns the new chain and entry.
// The receiver does not change.
func (c Chain) Append(body any) (Chain, Entry, error) {
	canonical, err := Canonical(body)
	if err != nil {
		return c, Entry{}, err
	}
	e := Entry{Index: int64(len(c.entries)), Body: canonical}
	if head, ok := c.Head(); ok {
		e.PreviousHash = head.Hash
	}
	e.Hash = HashOf(e.PreviousHash, e.Body)
	next := Chain{entries: make([]Entry, len(c.entries)+1)}
	copy(next.entries, c.entries)
	next.entries[len(c.entries)] = e
	return next, e, nil
}

// Head returns the last entry. ok is false on an empty chain.
func (c Chain) Head() (Entry, bool) {
	if len(c.entries) == 0 {
		return Entry{}, false
	}
	return c.entries[len(c.entries)-1], true
}

// Len returns the number of entries.
func (c Chain) Len() int { return len(c.entries) }

// Entries returns a copy of every entry in order.
func (c Chain) Entries() []Entry { return append([]Entry(nil), c.entries...) }

// Verify checks that every entry links to the one before it and that
// every hash matches its content. It returns a *VerifyError on the first
// failure.
func Verify(entries []Entry) error {
	prev := ""
	for i, e := range entries {
		if e.Index != int64(i) || e.PreviousHash != prev {
			return &VerifyError{Index: int64(i), Err: ErrBrokenLink}
		}
		if HashOf(e.PreviousHash, e.Body) != e.Hash {
			return &VerifyError{Index: int64(i), Err: ErrBadHash}
		}
		prev = e.Hash
	}
	return nil
}
