// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
)

// TestListTransactions lists the transactions newest first, reads a
// pending request past its expiry as expired, filters by state, and
// pages with the offset token. The verifier overview counts the open
// requests with it (P5-01).
func TestListTransactions(t *testing.T) {
	svc, store := build(t, service.Options{})
	ctx := context.Background()
	put := func(id string, state txn.State, created time.Time, expires time.Time) {
		t.Helper()
		rec := txn.Transaction{
			ID: id, StateParam: "s-" + id, TemplateID: "age-check", TemplateVersion: 2,
			State: state, CreatedAt: created, ExpiresAt: expires,
		}
		if state == txn.StateReceived {
			rec.AnsweredAt = created.Add(time.Minute)
		}
		if err := store.Put(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	put("old", txn.StatePending, clock.Add(-2*time.Hour), clock.Add(-time.Hour))
	put("done", txn.StateReceived, clock.Add(-30*time.Minute), clock.Add(time.Hour))
	put("open", txn.StatePending, clock.Add(-time.Minute), clock.Add(4*time.Minute))

	all, err := svc.ListTransactions(ctx, connect.NewRequest(&ingestv1.ListTransactionsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	got := all.Msg.GetTransactions()
	if len(got) != 3 || all.Msg.GetPage().GetTotalSize() != 3 {
		t.Fatalf("want 3 transactions, got %d (total %d)", len(got), all.Msg.GetPage().GetTotalSize())
	}
	if got[0].GetTransactionId() != "open" || got[2].GetTransactionId() != "old" {
		t.Errorf("want newest first, got %s ... %s", got[0].GetTransactionId(), got[2].GetTransactionId())
	}
	if got[1].GetAnsweredAt() == nil || got[0].GetAnsweredAt() != nil {
		t.Errorf("want the answer time of the received transaction only")
	}
	if got[2].GetState() != ingestv1.GetTransactionResponse_STATE_EXPIRED {
		t.Errorf("a pending request past its expiry reads %s, want expired", got[2].GetState())
	}
	if got[0].GetTemplateId() != "age-check" || got[0].GetTemplateVersion() != 2 || !got[0].GetExpiresAt().AsTime().Equal(clock.Add(4*time.Minute)) {
		t.Errorf("summary = %+v", got[0])
	}

	open, err := svc.ListTransactions(ctx, connect.NewRequest(&ingestv1.ListTransactionsRequest{
		State: ingestv1.GetTransactionResponse_STATE_PENDING,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(open.Msg.GetTransactions()); n != 1 || open.Msg.GetTransactions()[0].GetTransactionId() != "open" {
		t.Fatalf("want the one open request, got %d", n)
	}

	first, err := svc.ListTransactions(ctx, connect.NewRequest(&ingestv1.ListTransactionsRequest{
		Page: &commonv1.Pagination{PageSize: 2},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Msg.GetTransactions()) != 2 || first.Msg.GetPage().GetNextPageToken() != "2" {
		t.Fatalf("want a page of 2 with the next token, got %d %q", len(first.Msg.GetTransactions()), first.Msg.GetPage().GetNextPageToken())
	}
	second, err := svc.ListTransactions(ctx, connect.NewRequest(&ingestv1.ListTransactionsRequest{
		Page: &commonv1.Pagination{PageSize: 2, PageToken: "2"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Msg.GetTransactions()) != 1 || second.Msg.GetPage().GetNextPageToken() != "" {
		t.Fatalf("want the last page, got %d", len(second.Msg.GetTransactions()))
	}
	if _, err := svc.ListTransactions(ctx, connect.NewRequest(&ingestv1.ListTransactionsRequest{
		Page: &commonv1.Pagination{PageToken: "x"},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a bad page token gives %v, want invalid argument", err)
	}
}

// brokenList fails every list of the store.
type brokenList struct{ shared.KeyValue }

func (brokenList) List(context.Context, string) ([]string, error) {
	return nil, errors.New("disk gone")
}

func TestListTransactionsStoreFault(t *testing.T) {
	store, err := txn.NewStore(brokenList{shared.Memory()})
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	faulty, err := service.New(service.Options{Store: store, SigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := faulty.ListTransactions(context.Background(), connect.NewRequest(&ingestv1.ListTransactionsRequest{})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("want internal, got %v", err)
	}
}
