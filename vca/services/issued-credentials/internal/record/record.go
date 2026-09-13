// SPDX-License-Identifier: Apache-2.0

// Package record holds the issued credential record and the pure rules
// over it (ADR-017 decisions 1 and 2). The record carries no personal
// data. It carries a salted subject reference and the claims the schema
// marks as searchable.
//
// The log is append only. The package models it as two events: an issue
// event writes a new record, and a status event changes the status of a
// record. The state of a record is the fold of its events.
package record

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Errors the package returns.
var (
	ErrInvalid   = errors.New("record: the record is not valid")
	ErrNoReason  = errors.New("record: the status change needs a reason")
	ErrNotFound  = errors.New("record: no record with that id")
	ErrFinal     = errors.New("record: a revoked credential stays revoked")
	ErrNoBinding = errors.New("record: the credential has no status list entry")
)

// Status names the status of an issued credential.
type Status string

// The status values, as the proto enum names them.
const (
	Active    Status = "active"
	Suspended Status = "suspended"
	Revoked   Status = "revoked"
	Expired   Status = "expired"
)

// StatusKind names the status list standard of a binding.
type StatusKind string

// The status list kinds.
const (
	KindBitstring StatusKind = "bitstring"
	KindToken     StatusKind = "token"
)

// Binding points at the status list entry of a credential.
type Binding struct {
	Kind       StatusKind `json:"kind,omitempty"`
	ListID     string     `json:"list_id,omitempty"`
	Index      int64      `json:"index,omitempty"`
	PublishURL string     `json:"publish_url,omitempty"`
}

// IsZero reports whether the credential has no status list entry.
func (b Binding) IsZero() bool { return b.ListID == "" }

// Record is one entry of the log.
type Record struct {
	ID               string            `json:"id"`
	SchemaID         string            `json:"schema_id"`
	SchemaVersion    int               `json:"schema_version"`
	SubjectRef       string            `json:"subject_ref"`
	Format           string            `json:"format,omitempty"`
	Binding          Binding           `json:"binding,omitempty"`
	Status           Status            `json:"status"`
	DPG              string            `json:"dpg,omitempty"`
	IssuedAt         time.Time         `json:"issued_at"`
	Hash             string            `json:"hash,omitempty"`
	PreviousHash     string            `json:"previous_hash,omitempty"`
	RecordHash       string            `json:"record_hash,omitempty"`
	SearchableClaims map[string]string `json:"searchable_claims,omitempty"`
	ValidFrom        time.Time         `json:"valid_from,omitempty"`
	ValidUntil       time.Time         `json:"valid_until,omitempty"`
	OfferID          string            `json:"offer_id,omitempty"`
	StatusChangedAt  time.Time         `json:"status_changed_at,omitempty"`
	StatusReason     string            `json:"status_reason,omitempty"`
	RetainUntil      time.Time         `json:"retain_until,omitempty"`
}

// EventKind names what an event does.
type EventKind string

// The event kinds of the log.
const (
	EventIssue  EventKind = "issue"
	EventStatus EventKind = "status"
)

// Event is one body of the hash chain. Exactly one of Record or Change
// is set, as Kind says.
type Event struct {
	Kind   EventKind `json:"kind"`
	Record *Record   `json:"record,omitempty"`
	Change *Change   `json:"change,omitempty"`
}

// Change is a status change of one record.
type Change struct {
	RecordID  string    `json:"record_id"`
	Status    Status    `json:"status"`
	Reason    string    `json:"reason"`
	ChangedAt time.Time `json:"changed_at"`
}

// SubjectRef returns the salted, one way reference of subject
// (ADR-017 decision 2). It is an HMAC-SHA256 with the deployment salt as
// the key, so no one can build a rainbow table without the salt.
func SubjectRef(salt, subject string) string {
	m := hmac.New(sha256.New, []byte(salt))
	m.Write([]byte(subject))
	return hex.EncodeToString(m.Sum(nil))
}

// Validate checks one issue event before it joins the chain.
func (r Record) Validate() error {
	switch {
	case strings.TrimSpace(r.ID) == "":
		return fmt.Errorf("%w: the id is empty", ErrInvalid)
	case strings.TrimSpace(r.SchemaID) == "":
		return fmt.Errorf("%w: the schema id is empty", ErrInvalid)
	case r.SchemaVersion <= 0:
		return fmt.Errorf("%w: the schema version must be positive", ErrInvalid)
	case strings.TrimSpace(r.SubjectRef) == "":
		return fmt.Errorf("%w: the subject reference is empty", ErrInvalid)
	case r.IssuedAt.IsZero():
		return fmt.Errorf("%w: the issuance time is empty", ErrInvalid)
	case strings.Contains(r.SubjectRef, ":"):
		return fmt.Errorf("%w: the subject reference must not be a DID", ErrInvalid)
	}
	return nil
}

// Keep returns a copy of claims with only the names in allowed
// (ADR-017 decision 2). A nil allow list keeps nothing.
func Keep(claims map[string]string, allowed []string) map[string]string {
	if len(claims) == 0 || len(allowed) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		set[a] = struct{}{}
	}
	out := make(map[string]string, len(claims))
	for k, v := range claims {
		if _, ok := set[k]; ok {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// NextStatus returns the status after a change, or an error when the
// change is not allowed. Revoked is final (ADR-017 decision 3).
func NextStatus(current, want Status) error {
	if current == Revoked {
		return ErrFinal
	}
	switch want {
	case Revoked, Suspended, Active:
		return nil
	}
	return fmt.Errorf("%w: status %q", ErrInvalid, want)
}

// Apply returns r with the change applied.
func (r Record) Apply(c Change) Record {
	r.Status = c.Status
	r.StatusReason = c.Reason
	r.StatusChangedAt = c.ChangedAt
	return r
}

// Expired reports whether the validity window of r ended before now.
func (r Record) Expired(now time.Time) bool {
	return !r.ValidUntil.IsZero() && now.After(r.ValidUntil)
}

// Filter narrows a list, a search, or an export.
type Filter struct {
	SchemaID   string
	Status     Status
	Format     string
	From       time.Time
	To         time.Time
	SubjectRef string
}

// Match reports whether r passes f. A zero field of f matches every
// record.
func (f Filter) Match(r Record) bool {
	switch {
	case f.SchemaID != "" && r.SchemaID != f.SchemaID:
		return false
	case f.Status != "" && r.Status != f.Status:
		return false
	case f.Format != "" && r.Format != f.Format:
		return false
	case f.SubjectRef != "" && r.SubjectRef != f.SubjectRef:
		return false
	case !f.From.IsZero() && r.IssuedAt.Before(f.From):
		return false
	case !f.To.IsZero() && r.IssuedAt.After(f.To):
		return false
	}
	return true
}

// MaxQuery is the longest search text the service accepts.
const MaxQuery = 200

// Matches reports whether any searchable claim of r contains query.
// The comparison ignores case. An empty query matches every record.
func (r Record) Matches(query string) bool {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return true
	}
	for _, v := range r.SearchableClaims {
		if strings.Contains(strings.ToLower(v), q) {
			return true
		}
	}
	return false
}

// SortNewestFirst orders records by issuance time, newest first. Records
// issued at the same time keep a stable order by id.
func SortNewestFirst(rs []Record) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].IssuedAt.Equal(rs[j].IssuedAt) {
			return rs[i].ID < rs[j].ID
		}
		return rs[i].IssuedAt.After(rs[j].IssuedAt)
	})
}

// ClaimNames returns the searchable claim names of rs, sorted. The CSV
// export needs a stable column order.
func ClaimNames(rs []Record) []string {
	set := map[string]struct{}{}
	for _, r := range rs {
		for k := range r.SearchableClaims {
			set[k] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
