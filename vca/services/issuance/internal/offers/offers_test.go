// SPDX-License-Identifier: Apache-2.0

package offers_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/offers"
)

// fixedTime is the clock of the tests.
var fixedTime = time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)

// clock returns a time function that answers with the value.
func clock(at time.Time) func() time.Time { return func() time.Time { return at } }

// newStore returns a store over memory with the fixed clock.
func newStore() *offers.Store { return offers.New(store.Memory(), clock(fixedTime)) }

func TestNewUsesTheWallClockByDefault(t *testing.T) {
	if offers.New(store.Memory(), nil) == nil {
		t.Fatal("New returned nothing")
	}
}

func TestNewIDReturnsADistinctValue(t *testing.T) {
	first, second := offers.NewID(), offers.NewID()
	if first == second || len(first) != 32 {
		t.Fatalf("ids = %q and %q", first, second)
	}
}

func TestPutOfferAndOfferRoundTrip(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	want := offers.Offer{
		ID:        "offer-1",
		Channel:   "oid4vci",
		State:     offers.StatePending,
		OfferURI:  "openid-credential-offer://x",
		Pin:       "4821",
		SchemaID:  "farmer",
		Claims:    map[string]string{"farmerID": "FM-0001"},
		CreatedAt: fixedTime,
		ExpiresAt: fixedTime.Add(time.Hour),
	}
	if err := s.PutOffer(ctx, want); err != nil {
		t.Fatalf("PutOffer: %v", err)
	}
	got, err := s.Offer(ctx, "offer-1")
	if err != nil {
		t.Fatalf("Offer: %v", err)
	}
	if got.OfferURI != want.OfferURI || got.Pin != want.Pin || got.State != offers.StatePending {
		t.Fatalf("offer = %+v", got)
	}
	if got.Claims["farmerID"] != "FM-0001" {
		t.Fatalf("claims = %v", got.Claims)
	}
}

func TestOfferReportsAnExpiredOffer(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	err := s.PutOffer(ctx, offers.Offer{
		ID: "offer-1", State: offers.StatePending, ExpiresAt: fixedTime.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("PutOffer: %v", err)
	}
	got, gerr := s.Offer(ctx, "offer-1")
	if gerr != nil {
		t.Fatalf("Offer: %v", gerr)
	}
	if got.State != offers.StateExpired {
		t.Fatalf("state = %q, want expired", got.State)
	}
}

func TestOfferKeepsADeliveredOfferAfterTheWindow(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	err := s.PutOffer(ctx, offers.Offer{
		ID: "offer-1", State: offers.StateDelivered, ExpiresAt: fixedTime.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("PutOffer: %v", err)
	}
	got, verr := s.Offer(ctx, "offer-1")
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if got.State != offers.StateDelivered {
		t.Fatalf("state = %q", got.State)
	}
}

func TestOfferReportsAMissingRecord(t *testing.T) {
	_, err := newStore().Offer(context.Background(), "nope")
	if !errors.Is(err, offers.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestOfferReportsUnreadableBytes(t *testing.T) {
	kv := store.Memory()
	ctx := context.Background()
	if err := kv.Put(ctx, "offer/offer-1", []byte("not json")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := offers.New(kv, clock(fixedTime)).Offer(ctx, "offer-1"); err == nil {
		t.Fatal("Offer read a broken record")
	}
}

func TestOfferAndJobReportAStoreFailure(t *testing.T) {
	ctx := context.Background()
	broken := offers.New(&brokenStore{KeyValue: store.Memory(), getErr: errors.New("no read")}, nil)
	if _, err := broken.Offer(ctx, "offer-1"); err == nil {
		t.Fatal("Offer passed a failed read")
	}
	if _, err := broken.Job(ctx, "job-1"); err == nil {
		t.Fatal("Job passed a failed read")
	}
}

func TestDocumentRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	if err := s.PutDocument(ctx, "ref-1", []byte("%PDF-1.4")); err != nil {
		t.Fatalf("PutDocument: %v", err)
	}
	got, err := s.Document(ctx, "ref-1")
	if err != nil || string(got) != "%PDF-1.4" {
		t.Fatalf("document = %q, error = %v", got, err)
	}
	if _, err := s.Document(ctx, "nope"); !errors.Is(err, offers.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestJobRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	if err := s.PutJob(ctx, offers.Job{ID: "job-1", Total: 3, Accepted: 2, Rejected: 1, Done: true}); err != nil {
		t.Fatalf("PutJob: %v", err)
	}
	got, err := s.Job(ctx, "job-1")
	if err != nil {
		t.Fatalf("Job: %v", err)
	}
	if got.Total != 3 || got.Accepted != 2 || !got.Done {
		t.Fatalf("job = %+v", got)
	}
	if _, err := s.Job(ctx, "nope"); !errors.Is(err, offers.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestJobReportsUnreadableBytes(t *testing.T) {
	kv := store.Memory()
	ctx := context.Background()
	if err := kv.Put(ctx, "job/job-1", []byte("not json")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := offers.New(kv, nil).Job(ctx, "job-1"); err == nil {
		t.Fatal("Job read a broken record")
	}
}

func TestRowsPagesInRowOrder(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	for _, r := range []offers.Row{
		{Row: 3, Label: "Grace", OfferID: "offer-3"},
		{Row: 1, Label: "Ada", OfferID: "offer-1"},
		{Row: 2, Label: "No identifier", Code: "invalid_argument", Message: "farmerID is missing"},
	} {
		if err := s.PutRow(ctx, "job-1", r); err != nil {
			t.Fatalf("PutRow: %v", err)
		}
	}
	page, token, err := s.Rows(ctx, "job-1", 0, 2, false)
	if err != nil {
		t.Fatalf("Rows: %v", err)
	}
	if len(page) != 2 || page[0].Row != 1 || page[1].Row != 2 {
		t.Fatalf("page = %+v", page)
	}
	if token != "3" {
		t.Fatalf("token = %q", token)
	}
	start, perr := offers.ParseToken(token)
	if perr != nil {
		t.Fatalf("ParseToken: %v", perr)
	}
	rest, next, rerr := s.Rows(ctx, "job-1", start, 2, false)
	if rerr != nil {
		t.Fatalf("Rows: %v", rerr)
	}
	if len(rest) != 1 || rest[0].Row != 3 || next != "" {
		t.Fatalf("rest = %+v, token = %q", rest, next)
	}
}

func TestRowsKeepsTheFailedRowsOnly(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	rows := []offers.Row{
		{Row: 1, Label: "Ada"},
		{Row: 2, Label: "No identifier", Code: "invalid_argument"},
	}
	for _, r := range rows {
		if err := s.PutRow(ctx, "job-1", r); err != nil {
			t.Fatalf("PutRow: %v", err)
		}
	}
	got, _, err := s.Rows(ctx, "job-1", 0, 10, true)
	if err != nil {
		t.Fatalf("Rows: %v", err)
	}
	if len(got) != 1 || !got[0].Failed() {
		t.Fatalf("rows = %+v", got)
	}
	if rows[0].Failed() {
		t.Fatal("a row without a code failed")
	}
}

func TestRowsReportsUnreadableBytes(t *testing.T) {
	kv := store.Memory()
	ctx := context.Background()
	if err := kv.Put(ctx, "row/job-1/000000000001", []byte("not json")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, _, err := offers.New(kv, nil).Rows(ctx, "job-1", 0, 10, false); err == nil {
		t.Fatal("Rows read a broken record")
	}
}

func TestRowsReportsAStoreFailure(t *testing.T) {
	ctx := context.Background()
	listFails := &brokenStore{KeyValue: store.Memory(), listErr: errors.New("no list")}
	if _, _, err := offers.New(listFails, nil).Rows(ctx, "job-1", 0, 10, false); err == nil {
		t.Fatal("Rows passed a failed list")
	}
	kv := store.Memory()
	if err := kv.Put(ctx, "row/job-1/000000000001", []byte(`{"row":1}`)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	getFails := &brokenStore{KeyValue: kv, getErr: errors.New("no read")}
	if _, _, err := offers.New(getFails, nil).Rows(ctx, "job-1", 0, 10, false); err == nil {
		t.Fatal("Rows passed a failed read")
	}
}

func TestRowsSkipsARowThatWentAway(t *testing.T) {
	ctx := context.Background()
	kv := store.Memory()
	if err := kv.Put(ctx, "row/job-1/000000000001", []byte(`{"row":1}`)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	gone := &brokenStore{KeyValue: kv, getErr: store.ErrNotFound}
	got, _, err := offers.New(gone, nil).Rows(ctx, "job-1", 0, 10, false)
	if err != nil {
		t.Fatalf("Rows: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("rows = %+v", got)
	}
}

func TestKeysStaySafe(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	for _, id := range []string{"", "../escape", "a b/c"} {
		if err := s.PutOffer(ctx, offers.Offer{ID: id, State: offers.StateDelivered}); err != nil {
			t.Fatalf("PutOffer(%q): %v", id, err)
		}
		if _, err := s.Offer(ctx, id); err != nil {
			t.Fatalf("Offer(%q): %v", id, err)
		}
	}
}

func TestParseToken(t *testing.T) {
	if n, err := offers.ParseToken("  "); n != 0 || err != nil {
		t.Fatalf("an empty token = %d, %v", n, err)
	}
	if n, err := offers.ParseToken("7"); n != 7 || err != nil {
		t.Fatalf("token = %d, %v", n, err)
	}
	for _, bad := range []string{"x", "-1"} {
		if _, err := offers.ParseToken(bad); err == nil {
			t.Fatalf("the token %q was accepted", bad)
		}
	}
}

// brokenStore fails the operations the test names.
type brokenStore struct {
	store.KeyValue
	getErr  error
	listErr error
}

func (b *brokenStore) Get(ctx context.Context, key string) ([]byte, error) {
	if b.getErr != nil {
		return nil, b.getErr
	}
	return b.KeyValue.Get(ctx, key)
}

func (b *brokenStore) List(ctx context.Context, prefix string) ([]string, error) {
	if b.listErr != nil {
		return nil, b.listErr
	}
	return b.KeyValue.List(ctx, prefix)
}
