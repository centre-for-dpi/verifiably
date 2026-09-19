// SPDX-License-Identifier: Apache-2.0

// Package audit is the append only audit log of the admin service
// (ADR-009 decision 6). Every admin action writes one record with the
// actor, the action, and the request id.
//
// The log offers Append and Query only. No function changes or removes
// a record. Each record id starts with the time in milliseconds, so the
// store returns the records in time order.
package audit

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// Prefix is the store key prefix of every record.
const Prefix = "audit/"

// DefaultPageSize is the page size of a query without one.
const DefaultPageSize = 50

// MaxPageSize caps a page.
const MaxPageSize = 500

// Record is one entry of the log.
type Record struct {
	// ID is the record id. Ids increase over time.
	ID string `json:"id"`
	// At is the time of the action.
	At time.Time `json:"at"`
	// Actor is the caller as iss|sub, or the API key id.
	Actor string `json:"actor"`
	// Action is the RPC name, for example admin.CreateTenant.
	Action string `json:"action"`
	// RequestID is the request id of the call.
	RequestID string `json:"request_id,omitempty"`
	// Target is the id of the record the action touched.
	Target string `json:"target,omitempty"`
	// OK reports whether the action succeeded.
	OK bool `json:"ok"`
}

// Entry is what a caller appends. The log fills the id and the time.
type Entry struct {
	Actor     string
	Action    string
	RequestID string
	Target    string
	OK        bool
}

// Filter selects records. An empty field means no filter on that field.
type Filter struct {
	// From is the earliest time, inclusive.
	From time.Time
	// To is the latest time, inclusive.
	To time.Time
	// Actor matches the actor exactly.
	Actor string
	// Action matches the action exactly.
	Action string
	// PageSize is the maximum number of records. Zero selects
	// DefaultPageSize. The log caps the value at MaxPageSize.
	PageSize int
	// PageToken is the NextPageToken of the previous page.
	PageToken string
}

// Page is one page of records, newest first.
type Page struct {
	// Records are the matching records, newest first.
	Records []Record
	// NextPageToken continues the query. It is empty on the last page.
	NextPageToken string
	// TotalSize is the number of records that match the filter.
	TotalSize int
}

// Log is the append only log.
type Log struct {
	kv  store.KeyValue
	now func() time.Time
}

// New returns a log over kv. A nil clock selects time.Now.
func New(kv store.KeyValue, now func() time.Time) (*Log, error) {
	if kv == nil {
		return nil, errors.New("audit: a key value store is required")
	}
	if now == nil {
		now = time.Now
	}
	return &Log{kv: kv, now: now}, nil
}

// Append writes one record and returns it. It never replaces a record:
// the id holds a random part, so two calls in the same millisecond
// write two records.
func (l *Log) Append(ctx context.Context, e Entry) (Record, error) {
	if strings.TrimSpace(e.Action) == "" {
		return Record{}, errors.New("audit: the action is required")
	}
	at := l.now().UTC()
	rec := Record{
		ID:        NewID(at),
		At:        at,
		Actor:     e.Actor,
		Action:    e.Action,
		RequestID: e.RequestID,
		Target:    e.Target,
		OK:        e.OK,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return Record{}, fmt.Errorf("audit: %w", err)
	}
	// CompareAndSwap with a nil old value fails when the key exists, so
	// a record is never overwritten.
	if err := l.kv.CompareAndSwap(ctx, Prefix+rec.ID, nil, raw); err != nil {
		return Record{}, fmt.Errorf("audit: %w", err)
	}
	return rec, nil
}

// Query returns one page of records, newest first.
func (l *Log) Query(ctx context.Context, f Filter) (Page, error) {
	keys, err := l.kv.List(ctx, Prefix)
	if err != nil {
		return Page{}, fmt.Errorf("audit: %w", err)
	}
	// List returns the keys in ascending order. Reverse them, so the
	// newest record comes first.
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	size := f.PageSize
	if size <= 0 {
		size = DefaultPageSize
	}
	if size > MaxPageSize {
		size = MaxPageSize
	}
	var page Page
	started := f.PageToken == ""
	for _, k := range keys {
		var rec Record
		raw, err := l.kv.Get(ctx, k)
		if err != nil {
			return Page{}, fmt.Errorf("audit: %w", err)
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			return Page{}, fmt.Errorf("audit: %s: %w", k, err)
		}
		if !Matches(rec, f) {
			continue
		}
		page.TotalSize++
		if !started {
			if rec.ID == f.PageToken {
				started = true
			}
			continue
		}
		if len(page.Records) < size {
			page.Records = append(page.Records, rec)
			continue
		}
		page.NextPageToken = page.Records[len(page.Records)-1].ID
	}
	if len(page.Records) < size {
		page.NextPageToken = ""
	}
	return page, nil
}

// Matches reports whether a record passes the filter of f. The page
// fields of f are not used.
func Matches(rec Record, f Filter) bool {
	if f.Actor != "" && rec.Actor != f.Actor {
		return false
	}
	if f.Action != "" && rec.Action != f.Action {
		return false
	}
	if !f.From.IsZero() && rec.At.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && rec.At.After(f.To) {
		return false
	}
	return true
}

// NewID returns a sortable record id for at. The id is the time in
// milliseconds with 15 digits, a dash, and 12 random characters.
func NewID(at time.Time) string {
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%015d-%s", at.UTC().UnixMilli(), base64.RawURLEncoding.EncodeToString(b))
}
