// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/results"
)

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func newService(t *testing.T) *Service {
	t.Helper()
	svc, err := New(Options{
		Store:        results.New(store.Memory(), nil),
		Retention:    720 * time.Hour,
		RawRetention: 24 * time.Hour,
		Now:          func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func sample(id string, at time.Time) *resultsv1.VerificationResult {
	return &resultsv1.VerificationResult{
		Id:          id,
		Verdict:     policyv1.EvaluateResponse_VERDICT_VALID,
		EvaluatedAt: timestamppb.New(at),
		RawRef:      "raw-" + id,
		Credentials: []*resultsv1.CredentialSummary{{
			Issuer: "did:web:issuer", DecodedJson: `{"a":1}`,
		}},
	}
}

func TestNewChecks(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("want an error without a store")
	}
	st := results.New(store.Memory(), nil)
	if _, err := New(Options{Store: st}); err == nil {
		t.Fatal("want an error without a retention window")
	}
	if _, err := New(Options{Store: st, Retention: time.Hour}); err == nil {
		t.Fatal("want an error without a raw retention window")
	}
	svc, err := New(Options{Store: st, Retention: time.Hour, RawRetention: time.Hour})
	if err != nil || !svc.Ready() {
		t.Fatalf("want a ready service, got %v", err)
	}
}

func TestStoreAndGet(t *testing.T) {
	ctx := context.Background()
	svc := newService(t)
	stored, err := svc.Store(ctx, connect.NewRequest(&resultsv1.StoreRequest{
		Result: &resultsv1.VerificationResult{Id: "ignored", Carrier: "qr"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	got := stored.Msg.GetResult()
	if got.GetId() == "ignored" || got.GetId() == "" {
		t.Fatalf("want a new id, got %q", got.GetId())
	}
	if !got.GetRetainUntil().AsTime().Equal(testNow.Add(720 * time.Hour)) {
		t.Fatalf("want the retention window, got %v", got.GetRetainUntil().AsTime())
	}
	if !got.GetReceivedAt().AsTime().Equal(testNow) {
		t.Fatal("want the arrival time")
	}
	read, err := svc.Get(ctx, connect.NewRequest(&resultsv1.GetRequest{Id: got.GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	if read.Msg.GetResult().GetCarrier() != "qr" {
		t.Fatalf("unexpected result: %+v", read.Msg.GetResult())
	}
}

func TestStoreProblems(t *testing.T) {
	ctx := context.Background()
	svc := newService(t)
	if _, err := svc.Store(ctx, connect.NewRequest(&resultsv1.StoreRequest{})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want an invalid argument error, got %v", err)
	}
	if _, err := svc.Get(ctx, connect.NewRequest(&resultsv1.GetRequest{Id: "missing"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want not found, got %v", err)
	}
	if _, err := svc.Get(ctx, connect.NewRequest(&resultsv1.GetRequest{Id: "bad id"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want a bad id error, got %v", err)
	}
}

func TestQueryAndPaging(t *testing.T) {
	ctx := context.Background()
	svc := newService(t)
	for i, id := range []string{"a", "b", "c"} {
		if _, err := svc.opts.Store.Put(ctx, sample(id, testNow.Add(time.Duration(i)*time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	all, err := svc.Query(ctx, connect.NewRequest(&resultsv1.QueryRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Msg.GetResults()) != 3 || all.Msg.GetResults()[0].GetId() != "c" {
		t.Fatalf("want the newest first, got %+v", all.Msg.GetResults())
	}
	page, err := svc.Query(ctx, connect.NewRequest(&resultsv1.QueryRequest{
		Page: &commonv1.Pagination{PageSize: 2},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if page.Msg.GetPage().GetNextPageToken() != "2" {
		t.Fatalf("want a next page token, got %q", page.Msg.GetPage().GetNextPageToken())
	}
	next, err := svc.Query(ctx, connect.NewRequest(&resultsv1.QueryRequest{
		Page: &commonv1.Pagination{PageToken: "2"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Msg.GetResults()) != 1 {
		t.Fatalf("want the last page, got %d", len(next.Msg.GetResults()))
	}
	far, err := svc.Query(ctx, connect.NewRequest(&resultsv1.QueryRequest{
		Page: &commonv1.Pagination{PageToken: "9"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(far.Msg.GetResults()) != 0 {
		t.Fatal("want no results past the end")
	}
	if _, serr := svc.Query(ctx, connect.NewRequest(&resultsv1.QueryRequest{
		Page: &commonv1.Pagination{PageToken: "x"},
	})); connect.CodeOf(serr) != connect.CodeInvalidArgument {
		t.Fatalf("want a bad token error, got %v", serr)
	}
	filtered, err := svc.QueryAll(ctx, &resultsv1.Filter{Issuer: "did:web:other"})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 0 {
		t.Fatalf("want no match, got %d", len(filtered))
	}
	if _, err := svc.Read(ctx, "a"); err != nil {
		t.Fatal(err)
	}
}

// collector keeps the chunks of an export.
type collector struct {
	chunks [][]byte
	fail   bool
}

func (c *collector) Send(resp *resultsv1.ExportResponse) error {
	if c.fail {
		return errors.New("closed")
	}
	c.chunks = append(c.chunks, resp.GetChunk())
	return nil
}

func TestExportEncodings(t *testing.T) {
	ctx := context.Background()
	svc := newService(t)
	if _, err := svc.opts.Store.Put(ctx, sample("a", testNow)); err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []resultsv1.ExportRequest_Encoding{
		resultsv1.ExportRequest_ENCODING_CSV, resultsv1.ExportRequest_ENCODING_JSON,
	} {
		body, err := Encode(encoding, []*resultsv1.VerificationResult{sample("a", testNow)})
		if err != nil {
			t.Fatal(err)
		}
		if len(body) == 0 {
			t.Fatalf("want an export body for %s", encoding)
		}
	}
	var buf []byte
	out := &collector{}
	if err := svc.SendExport(ctx, &resultsv1.ExportRequest{}, out); err != nil {
		t.Fatal(err)
	}
	for _, c := range out.chunks {
		buf = append(buf, c...)
	}
	if !strings.Contains(string(buf), "result_id") {
		t.Fatalf("want the CSV header, got %q", buf)
	}
}

func TestPurge(t *testing.T) {
	ctx := context.Background()
	svc := newService(t)
	old := sample("old", testNow.Add(-800*time.Hour))
	recent := sample("recent", testNow.Add(-time.Hour))
	for _, r := range []*resultsv1.VerificationResult{old, recent} {
		if _, err := svc.opts.Store.Put(ctx, r); err != nil {
			t.Fatal(err)
		}
		if err := svc.opts.Store.PutRaw(ctx, r.GetId(), []byte("payload")); err != nil {
			t.Fatal(err)
		}
	}
	dry, err := svc.Purge(ctx, connect.NewRequest(&resultsv1.PurgeRequest{DryRun: true}))
	if err != nil {
		t.Fatal(err)
	}
	if dry.Msg.GetRawDeleted() != 1 || dry.Msg.GetResultsDeleted() != 1 {
		t.Fatalf("unexpected dry run counts: %+v", dry.Msg)
	}
	if _, serr := svc.opts.Store.Get(ctx, "old"); serr != nil {
		t.Fatal("want the dry run to write nothing")
	}
	counts, err := svc.PurgeNow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts.GetRawDeleted() != 1 || counts.GetResultsDeleted() != 1 {
		t.Fatalf("unexpected counts: %+v", counts)
	}
	if _, err := svc.opts.Store.Get(ctx, "old"); !errors.Is(err, results.ErrNotFound) {
		t.Fatalf("want the old result to be gone, got %v", err)
	}
	if _, err := svc.opts.Store.Get(ctx, "recent"); err != nil {
		t.Fatal("want the recent result to stay")
	}
}

func TestPurgeRawOnly(t *testing.T) {
	ctx := context.Background()
	svc := newService(t)
	r := sample("one", testNow.Add(-48*time.Hour))
	if _, err := svc.opts.Store.Put(ctx, r); err != nil {
		t.Fatal(err)
	}
	counts, err := svc.Purge(ctx, connect.NewRequest(&resultsv1.PurgeRequest{
		RawOnly: true, Before: timestamppb.New(testNow),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if counts.Msg.GetRawDeleted() != 1 || counts.Msg.GetResultsDeleted() != 0 {
		t.Fatalf("unexpected counts: %+v", counts.Msg)
	}
	got, err := svc.opts.Store.Get(ctx, "one")
	if err != nil {
		t.Fatal(err)
	}
	if got.GetRawRef() != "" || got.GetCredentials()[0].GetDecodedJson() != "" {
		t.Fatalf("want the raw data cleared, got %+v", got)
	}
	again, err := svc.Purge(ctx, connect.NewRequest(&resultsv1.PurgeRequest{RawOnly: true}))
	if err != nil {
		t.Fatal(err)
	}
	if again.Msg.GetRawDeleted() != 0 {
		t.Fatal("want no second raw deletion")
	}
}

func TestRetainUntilFallback(t *testing.T) {
	r := &resultsv1.VerificationResult{EvaluatedAt: timestamppb.New(testNow)}
	if got := retainUntil(r, time.Hour); !got.Equal(testNow.Add(time.Hour)) {
		t.Fatalf("want the window, got %v", got)
	}
}

// brokenStore fails every list.
type brokenKV struct{ store.KeyValue }

func (brokenKV) List(context.Context, string) ([]string, error) { return nil, errors.New("broken") }

func TestBackendErrors(t *testing.T) {
	ctx := context.Background()
	svc, err := New(Options{
		Store: results.New(brokenKV{store.Memory()}, nil), Retention: time.Hour, RawRetention: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Query(ctx, connect.NewRequest(&resultsv1.QueryRequest{})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("want an internal error, got %v", err)
	}
	if err := svc.SendExport(ctx, &resultsv1.ExportRequest{}, &collector{}); err == nil {
		t.Fatal("want the backend error")
	}
	if _, err := svc.PurgeNow(ctx); err == nil {
		t.Fatal("want the backend error")
	}
	if _, err := svc.Purge(ctx, connect.NewRequest(&resultsv1.PurgeRequest{})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("want an internal error, got %v", err)
	}
}

// writeFailKV lists and reads, and fails every write.
type writeFailKV struct{ store.KeyValue }

func (writeFailKV) Put(context.Context, string, []byte) error { return errors.New("full") }

// readFailKV fails every read.
type readFailKV struct{ store.KeyValue }

func (readFailKV) Get(context.Context, string) ([]byte, error) { return nil, errors.New("unreadable") }

// deleteFailKV fails every delete.
type deleteFailKV struct{ store.KeyValue }

func (deleteFailKV) Delete(context.Context, string) error { return errors.New("locked") }

func withStore(t *testing.T, kv store.KeyValue) *Service {
	t.Helper()
	svc, err := New(Options{
		Store: results.New(kv, nil), Retention: time.Hour, RawRetention: time.Hour,
		Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestStoreWriteError(t *testing.T) {
	svc := withStore(t, writeFailKV{store.Memory()})
	_, err := svc.Store(context.Background(), connect.NewRequest(&resultsv1.StoreRequest{
		Result: &resultsv1.VerificationResult{},
	}))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("want an internal error, got %v", err)
	}
}

func TestGetReadError(t *testing.T) {
	svc := withStore(t, readFailKV{store.Memory()})
	_, err := svc.Get(context.Background(), connect.NewRequest(&resultsv1.GetRequest{Id: "one"}))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("want an internal error, got %v", err)
	}
}

func TestPurgeWriteErrors(t *testing.T) {
	ctx := context.Background()
	mem := store.Memory()
	seed := withStore(t, mem)
	if _, err := seed.opts.Store.Put(ctx, sample("one", testNow.Add(-48*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if _, err := withStore(t, deleteFailKV{mem}).PurgeNow(ctx); err == nil {
		t.Fatal("want the raw delete error")
	}
	if _, err := withStore(t, writeFailKV{mem}).PurgeNow(ctx); err == nil {
		t.Fatal("want the write error")
	}
}

func TestExportChunks(t *testing.T) {
	ctx := context.Background()
	svc := newService(t)
	for i := 0; i < 400; i++ {
		if _, err := svc.opts.Store.Put(ctx, sample("id"+strconv.Itoa(i), testNow)); err != nil {
			t.Fatal(err)
		}
	}
	out := &collector{}
	if err := svc.SendExport(ctx, &resultsv1.ExportRequest{
		Encoding: resultsv1.ExportRequest_ENCODING_JSON,
	}, out); err != nil {
		t.Fatal(err)
	}
	if len(out.chunks) < 2 {
		t.Fatalf("want more than one chunk, got %d", len(out.chunks))
	}
	if err := svc.SendExport(ctx, &resultsv1.ExportRequest{}, &collector{fail: true}); err == nil {
		t.Fatal("want the send error")
	}
}

func TestHoldsRaw(t *testing.T) {
	if holdsRaw(&resultsv1.VerificationResult{}) {
		t.Fatal("want no raw data")
	}
	if !holdsRaw(&resultsv1.VerificationResult{RawRef: "x"}) {
		t.Fatal("want raw data")
	}
}
