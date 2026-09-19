// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/service"
)

func TestIssueBatchStreamsTheProgress(t *testing.T) {
	h := newHarness(t, nil)
	sent, err := h.batch(t, &issuancev1.IssueBatchRequest{
		SchemaId: "farmer",
		Channel:  backendv1.Channel_CHANNEL_OID4VCI_PREAUTH,
		Items: []*issuancev1.IssueBatchRequest_Item{
			{Row: 1, SubjectData: `{"fullName":"Ada Lovelace","farmerID":"FM-0001"}`},
			{Row: 2, SubjectData: `{"fullName":"Grace Hopper","farmerID":"FM-0002"}`},
			{Row: 3, SubjectData: `{"fullName":"No identifier"}`},
		},
	})
	if err != nil {
		t.Fatalf("IssueBatch: %v", err)
	}
	if len(sent) != 5 {
		t.Fatalf("messages = %d, want one at the start, one per row, and one at the end", len(sent))
	}
	last := sent[len(sent)-1]
	if !last.GetDone() || last.GetTotal() != 3 {
		t.Fatalf("last message = %v", last)
	}
	if last.GetAccepted() != 2 || last.GetRejected() != 1 {
		t.Fatalf("accepted = %d rejected = %d", last.GetAccepted(), last.GetRejected())
	}
	jobID := last.GetJobId()
	page, err := h.service.GetBatch(context.Background(), connect.NewRequest(&issuancev1.GetBatchRequest{
		JobId: jobID,
	}))
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if len(page.Msg.GetRows()) != 2 {
		t.Fatalf("rows = %d, the page holds two", len(page.Msg.GetRows()))
	}
	if page.Msg.GetRows()[0].GetLabel() != "Ada Lovelace" {
		t.Fatalf("label = %q", page.Msg.GetRows()[0].GetLabel())
	}
	if page.Msg.GetRows()[0].GetOffer().GetOfferUri() == "" {
		t.Fatal("the first row has no offer")
	}
	token := page.Msg.GetPage().GetNextPageToken()
	if token == "" {
		t.Fatal("the first page has no next token")
	}
	rest, err := h.service.GetBatch(context.Background(), connect.NewRequest(&issuancev1.GetBatchRequest{
		JobId: jobID, Page: &commonv1.Pagination{PageToken: token},
	}))
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if len(rest.Msg.GetRows()) != 1 || rest.Msg.GetPage().GetNextPageToken() != "" {
		t.Fatalf("the last page = %v", rest.Msg)
	}
	failed, err := h.service.GetBatch(context.Background(), connect.NewRequest(&issuancev1.GetBatchRequest{
		JobId: jobID, FailedOnly: true,
	}))
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if len(failed.Msg.GetRows()) != 1 {
		t.Fatalf("failed rows = %d", len(failed.Msg.GetRows()))
	}
	row := failed.Msg.GetRows()[0]
	if row.GetError() == nil || row.GetError().GetNextStep() == "" {
		t.Fatalf("the failed row carries no error: %v", row)
	}
	if !strings.Contains(row.GetError().GetMessage(), "farmerID") {
		t.Fatalf("the error %q does not name the missing claim", row.GetError().GetMessage())
	}
}

func TestIssueBatchReadsTheRowsOfASourceJob(t *testing.T) {
	h := newHarness(t, nil)
	h.rows.rows = []map[string]string{
		{"fullName": "Ada Lovelace", "farmerID": "FM-0001"},
		{"fullName": "Grace Hopper", "farmerID": "FM-0002"},
	}
	sent, err := h.batch(t, &issuancev1.IssueBatchRequest{
		SchemaId:    "farmer",
		Channel:     backendv1.Channel_CHANNEL_OID4VCI_PREAUTH,
		SourceJobId: "source-1",
	})
	if err != nil {
		t.Fatalf("IssueBatch: %v", err)
	}
	last := sent[len(sent)-1]
	if last.GetAccepted() != 2 || last.GetTotal() != 2 {
		t.Fatalf("progress = %v", last)
	}
}

func TestIssueBatchChecksItsInput(t *testing.T) {
	h := newHarness(t, nil)
	_, err := h.batch(t, &issuancev1.IssueBatchRequest{SchemaId: "farmer"})
	wantCode(t, err, connect.CodeInvalidArgument)
	h.rows.rows = nil
	_, err = h.batch(t, &issuancev1.IssueBatchRequest{SchemaId: "farmer", SourceJobId: "source-1"})
	wantCode(t, err, connect.CodeInvalidArgument)
	h.rows.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	_, err = h.batch(t, &issuancev1.IssueBatchRequest{SchemaId: "farmer", SourceJobId: "source-1"})
	wantCode(t, err, connect.CodeUnavailable)
}

func TestIssueBatchNeedsADataSourceServiceForASourceJob(t *testing.T) {
	h := newHarness(t, func(o *service.Options, _ *harness) { o.Rows = nil })
	_, err := h.batch(t, &issuancev1.IssueBatchRequest{SchemaId: "farmer", SourceJobId: "source-1"})
	wantCode(t, err, connect.CodeFailedPrecondition)
}

func TestGetBatchChecksItsInput(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	_, err := h.service.GetBatch(ctx, connect.NewRequest(&issuancev1.GetBatchRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = h.service.GetBatch(ctx, connect.NewRequest(&issuancev1.GetBatchRequest{
		JobId: "does-not-exist",
	}))
	wantCode(t, err, connect.CodeNotFound)
	sent, berr := h.batch(t, &issuancev1.IssueBatchRequest{
		SchemaId: "farmer",
		Items: []*issuancev1.IssueBatchRequest_Item{
			{Row: 1, SubjectData: `{"fullName":"Ada","farmerID":"FM-1"}`},
		},
	})
	if berr != nil {
		t.Fatalf("IssueBatch: %v", berr)
	}
	jobID := sent[0].GetJobId()
	_, err = h.service.GetBatch(ctx, connect.NewRequest(&issuancev1.GetBatchRequest{
		JobId: jobID, Page: &commonv1.Pagination{PageToken: "not a number"},
	}))
	wantCode(t, err, connect.CodeInvalidArgument)
}

func TestDeferredReadsTheAdapterState(t *testing.T) {
	h := newHarness(t, nil)
	created := h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	h.adapter.state = &backendv1.GetIssuanceStatusResponse{
		State: backendv1.GetIssuanceStatusResponse_STATE_ISSUED,
		Credential: &commonv1.Credential{
			Format: commonv1.Format_FORMAT_VC_SD_JWT, Payload: []byte("header.payload.sig~"),
		},
	}
	resp, err := h.service.Deferred(context.Background(),
		connect.NewRequest(&issuancev1.DeferredRequest{OfferId: created.GetId()}))
	if err != nil {
		t.Fatalf("Deferred: %v", err)
	}
	offer := resp.Msg.GetOffer()
	if offer.GetState() != issuancev1.Offer_STATE_DELIVERED {
		t.Fatalf("state = %v", offer.GetState())
	}
	if string(offer.GetCredential().GetPayload()) != "header.payload.sig~" {
		t.Fatalf("credential = %q", offer.GetCredential().GetPayload())
	}
}

func TestDeferredMapsEveryState(t *testing.T) {
	cases := map[backendv1.GetIssuanceStatusResponse_State]issuancev1.Offer_State{
		backendv1.GetIssuanceStatusResponse_STATE_PENDING:  issuancev1.Offer_STATE_PENDING,
		backendv1.GetIssuanceStatusResponse_STATE_DEFERRED: issuancev1.Offer_STATE_DEFERRED,
		backendv1.GetIssuanceStatusResponse_STATE_EXPIRED:  issuancev1.Offer_STATE_EXPIRED,
		backendv1.GetIssuanceStatusResponse_STATE_FAILED:   issuancev1.Offer_STATE_FAILED,
	}
	for from, want := range cases {
		h := newHarness(t, nil)
		created := h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
		h.adapter.state = &backendv1.GetIssuanceStatusResponse{State: from, Error: "no key"}
		resp, err := h.service.Deferred(context.Background(),
			connect.NewRequest(&issuancev1.DeferredRequest{OfferId: created.GetId()}))
		if err != nil {
			t.Fatalf("Deferred: %v", err)
		}
		if got := resp.Msg.GetOffer().GetState(); got != want {
			t.Fatalf("the state %v became %v, want %v", from, got, want)
		}
	}
}

func TestDeferredChecksItsInput(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	_, err := h.service.Deferred(ctx, connect.NewRequest(&issuancev1.DeferredRequest{}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = h.service.Deferred(ctx, connect.NewRequest(&issuancev1.DeferredRequest{
		OfferId: "does-not-exist",
	}))
	wantCode(t, err, connect.CodeNotFound)
	created := h.issue(t, backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, nil)
	h.adapter.stateErr = connect.NewError(connect.CodeUnimplemented, errors.New("no state"))
	_, err = h.service.Deferred(ctx, connect.NewRequest(&issuancev1.DeferredRequest{
		OfferId: created.GetId(),
	}))
	wantCode(t, err, connect.CodeUnimplemented)
}
