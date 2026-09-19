// SPDX-License-Identifier: Apache-2.0

// Package offers keeps the state of the issuance service: one record per
// offer, one per batch job, and one per row of a job. The state lives in
// the shared key value store, so a restart keeps it when the deployment
// mounts a volume.
package offers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// ErrNotFound reports that no record has the id.
var ErrNotFound = errors.New("offers: not found")

// State names the phase of one offer.
type State string

// The phases of an offer.
const (
	// StatePending means no wallet has claimed the offer.
	StatePending State = "pending"
	// StateDelivered means the citizen has the credential or the
	// document.
	StateDelivered State = "delivered"
	// StateDeferred means the DPG will issue later.
	StateDeferred State = "deferred"
	// StateExpired means the offer stopped working.
	StateExpired State = "expired"
	// StateFailed means the issuance failed.
	StateFailed State = "failed"
)

// Offer is the stored state of one issuance.
type Offer struct {
	ID            string            `json:"id"`
	Channel       string            `json:"channel"`
	State         State             `json:"state"`
	OfferURI      string            `json:"offer_uri,omitempty"`
	Pin           string            `json:"pin,omitempty"`
	PdfRef        string            `json:"pdf_ref,omitempty"`
	Link          string            `json:"link,omitempty"`
	RecordID      string            `json:"record_id,omitempty"`
	TransactionID string            `json:"transaction_id,omitempty"`
	Credential    []byte            `json:"credential,omitempty"`
	Format        int32             `json:"format,omitempty"`
	SchemaID      string            `json:"schema_id,omitempty"`
	SchemaVersion int32             `json:"schema_version,omitempty"`
	SubjectRef    string            `json:"subject_ref,omitempty"`
	Claims        map[string]string `json:"claims,omitempty"`
	Error         string            `json:"error,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	ExpiresAt     time.Time         `json:"expires_at"`
	ClaimedAt     time.Time         `json:"claimed_at,omitempty"`
}

// Job is the stored state of one batch.
type Job struct {
	ID        string    `json:"id"`
	Total     int64     `json:"total"`
	Processed int64     `json:"processed"`
	Accepted  int64     `json:"accepted"`
	Rejected  int64     `json:"rejected"`
	Done      bool      `json:"done"`
	CreatedAt time.Time `json:"created_at"`
}

// Row is the result of one row of a batch.
type Row struct {
	Row     int64  `json:"row"`
	Label   string `json:"label"`
	OfferID string `json:"offer_id,omitempty"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// Failed reports whether the row failed.
func (r Row) Failed() bool { return r.Code != "" }

// Store keeps the state of the service.
type Store struct {
	kv store.KeyValue
	// now returns the current time. Tests replace it.
	now func() time.Time
}

// New returns a store over the key value backend.
func New(kv store.KeyValue, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{kv: kv, now: now}
}

// NewID returns a new random identifier.
func NewID() string {
	b := make([]byte, 16)
	// crypto/rand cannot fail on a platform that Go supports.
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func offerKey(id string) string { return "offer/" + safe(id) }
func pdfKey(ref string) string  { return "pdf/" + safe(ref) }
func jobKey(id string) string   { return "job/" + safe(id) }

// rowKey sorts the rows of a job by their number, so a page reads in
// row order.
func rowKey(jobID string, row int64) string {
	return "row/" + safe(jobID) + "/" + fmt.Sprintf("%012d", row)
}

// safe makes a value usable as a store key segment.
func safe(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// PutOffer stores one offer.
func (s *Store) PutOffer(ctx context.Context, o Offer) error {
	raw, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("offers: encode the offer: %w", err)
	}
	return s.kv.Put(ctx, offerKey(o.ID), raw)
}

// Offer returns one offer. It reports the state expired when the offer
// outlived its window.
func (s *Store) Offer(ctx context.Context, id string) (Offer, error) {
	raw, err := s.kv.Get(ctx, offerKey(id))
	if errors.Is(err, store.ErrNotFound) {
		return Offer{}, fmt.Errorf("%w: the offer %q", ErrNotFound, id)
	}
	if err != nil {
		return Offer{}, err
	}
	var o Offer
	if err := json.Unmarshal(raw, &o); err != nil {
		return Offer{}, fmt.Errorf("offers: read the offer: %w", err)
	}
	if o.State == StatePending && !o.ExpiresAt.IsZero() && s.now().UTC().After(o.ExpiresAt) {
		o.State = StateExpired
	}
	return o, nil
}

// PutDocument stores the bytes of one rendered document.
func (s *Store) PutDocument(ctx context.Context, ref string, document []byte) error {
	return s.kv.Put(ctx, pdfKey(ref), document)
}

// Document returns the bytes of one rendered document.
func (s *Store) Document(ctx context.Context, ref string) ([]byte, error) {
	raw, err := s.kv.Get(ctx, pdfKey(ref))
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: the document %q", ErrNotFound, ref)
	}
	return raw, err
}

// PutJob stores one batch job.
func (s *Store) PutJob(ctx context.Context, j Job) error {
	raw, err := json.Marshal(j)
	if err != nil {
		return fmt.Errorf("offers: encode the job: %w", err)
	}
	return s.kv.Put(ctx, jobKey(j.ID), raw)
}

// Job returns one batch job.
func (s *Store) Job(ctx context.Context, id string) (Job, error) {
	raw, err := s.kv.Get(ctx, jobKey(id))
	if errors.Is(err, store.ErrNotFound) {
		return Job{}, fmt.Errorf("%w: the job %q", ErrNotFound, id)
	}
	if err != nil {
		return Job{}, err
	}
	var j Job
	if err := json.Unmarshal(raw, &j); err != nil {
		return Job{}, fmt.Errorf("offers: read the job: %w", err)
	}
	return j, nil
}

// PutRow stores the result of one row.
func (s *Store) PutRow(ctx context.Context, jobID string, r Row) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("offers: encode the row: %w", err)
	}
	return s.kv.Put(ctx, rowKey(jobID, r.Row), raw)
}

// Rows returns one page of the rows of a job in row order. The token is
// the row number to start at. The second value is the token of the next
// page, which is empty on the last page.
func (s *Store) Rows(ctx context.Context, jobID string, start int64, size int, failedOnly bool) (
	[]Row, string, error,
) {
	keys, err := s.kv.List(ctx, "row/"+safe(jobID)+"/")
	if err != nil {
		return nil, "", err
	}
	sort.Strings(keys)
	var out []Row
	for _, key := range keys {
		raw, err := s.kv.Get(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		var r Row
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, "", fmt.Errorf("offers: read the row: %w", err)
		}
		if r.Row < start || (failedOnly && !r.Failed()) {
			continue
		}
		if len(out) == size {
			return out, strconv.FormatInt(r.Row, 10), nil
		}
		out = append(out, r)
	}
	return out, "", nil
}

// ParseToken reads a page token. An empty token starts at the first row.
func ParseToken(token string) (int64, error) {
	if strings.TrimSpace(token) == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(token, 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("offers: bad page token")
	}
	return n, nil
}
