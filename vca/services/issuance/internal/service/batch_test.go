// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
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

// TestIssueBatchRefusesASourceJob covers the old source job path. The
// data source pages start every bulk run and send typed rows, so a
// request that names a source job fails before it reads any row. The
// answer names the pages.
func TestIssueBatchRefusesASourceJob(t *testing.T) {
	h := newHarness(t, nil)
	for _, req := range []*issuancev1.IssueBatchRequest{
		{SchemaId: "farmer", SourceJobId: "source-1"},
		{SchemaId: "farmer", SourceJobId: "source-1", Items: []*issuancev1.IssueBatchRequest_Item{
			{Row: 1, SubjectData: `{"fullName":"Ada Lovelace","farmerID":"FM-0001"}`},
		}},
	} {
		sent, err := h.batch(t, req)
		wantCode(t, err, connect.CodeFailedPrecondition)
		if !strings.Contains(err.Error(), "/sources/") {
			t.Fatalf("the refusal does not name the data source pages: %v", err)
		}
		if len(sent) != 0 {
			t.Fatalf("the refused batch sent %d messages", len(sent))
		}
	}
}

func TestIssueBatchChecksItsInput(t *testing.T) {
	h := newHarness(t, nil)
	_, err := h.batch(t, &issuancev1.IssueBatchRequest{SchemaId: "farmer"})
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = h.batch(t, &issuancev1.IssueBatchRequest{SchemaId: "farmer", SourceJobId: "  "})
	wantCode(t, err, connect.CodeInvalidArgument)
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

// typedFarmer is the farmer schema with an integer, a boolean and a
// nested object, as a data source fills them.
const typedFarmer = `{"type":"object","properties":{
  "fullName":{"type":"string"},"farmerID":{"type":"string"},
  "hectares":{"type":"integer","minimum":1},"organic":{"type":"boolean"},
  "address":{"type":"object","properties":{"county":{"type":"string"}}}},
  "required":["fullName","farmerID"]}`

// TestIssueBatchKeepsTheTypesOfTheClaims proves a row of a batch reaches
// the schema check and the adapter with its JSON types, as a single
// issue does, so the integer 12 passes an integer claim.
func TestIssueBatchKeepsTheTypesOfTheClaims(t *testing.T) {
	h := newHarness(t, nil)
	h.schemas.schema.JsonSchema = typedFarmer
	sent, err := h.batch(t, &issuancev1.IssueBatchRequest{
		SchemaId: "farmer", Channel: backendv1.Channel_CHANNEL_OID4VCI_PREAUTH,
		Items: []*issuancev1.IssueBatchRequest_Item{
			{Row: 1, SubjectData: `{"fullName":"Wanjiku Njeri","farmerID":"FM-0042","hectares":12,"organic":true,"address":{"county":"Kiambu"}}`},
			{Row: 2, SubjectData: `{"fullName":"Otieno Ouma","farmerID":"FM-0043","hectares":"12"}`},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	last := sent[len(sent)-1]
	if last.GetAccepted() != 1 || last.GetRejected() != 1 {
		t.Fatalf("progress = %v, want the typed row issued and the text row refused", last)
	}
	var got map[string]any
	if jerr := json.Unmarshal([]byte(h.adapter.specs[0].GetSubjectData()), &got); jerr != nil {
		t.Fatal(jerr)
	}
	if got["hectares"] != float64(12) || got["organic"] != true {
		t.Fatalf("subject data %v lost the types", got)
	}
	failed, err := h.service.GetBatch(context.Background(), connect.NewRequest(&issuancev1.GetBatchRequest{JobId: last.GetJobId(), FailedOnly: true}))
	if err != nil {
		t.Fatal(err)
	}
	if rows := failed.Msg.GetRows(); len(rows) != 1 || rows[0].GetRow() != 2 || !strings.Contains(rows[0].GetError().GetMessage(), "/hectares") {
		t.Fatalf("failed rows = %v", rows)
	}
}

// nativeHarness is a harness whose adapter lists the bulk import.
func nativeHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t, nil)
	h.adapter.capabilities.Features = append(h.adapter.capabilities.Features, backendv1.Feature_FEATURE_BULK_NATIVE)
	h.schemas.schema.JsonSchema = typedFarmer
	return h
}

// TestIssueBatchNativeIssuesInOneCall proves a native batch sends every
// row that passes the schema to the adapter in one call, turns each
// credential into a document, and lists the rows the schema or the
// stack refused.
func TestIssueBatchNativeIssuesInOneCall(t *testing.T) {
	h := nativeHarness(t)
	h.adapter.batch = &backendv1.IssueBatchResponse{Items: []*backendv1.IssueBatchResponse_Item{
		{Position: 0, Credential: h.adapter.credential.GetCredential()},
		{Position: 1, Error: &commonv1.Error{Code: "DPG-ROW", Message: "the stack refused the row"}},
	}}
	sent, err := h.batch(t, &issuancev1.IssueBatchRequest{
		SchemaId: "farmer", Channel: backendv1.Channel_CHANNEL_PDF, Native: true,
		Items: []*issuancev1.IssueBatchRequest_Item{
			{Row: 1, SubjectData: `{"fullName":"Wanjiku Njeri","farmerID":"FM-0042","hectares":12}`},
			{Row: 2, SubjectData: `{"fullName":"Otieno Ouma","farmerID":"FM-0043"}`},
			{Row: 3, SubjectData: `{"fullName":"No identifier"}`},
			{Row: 4, SubjectData: `not json`},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.adapter.batches) != 1 || len(h.adapter.batches[0].GetSpecs()) != 2 {
		t.Fatalf("adapter batches = %v, want one call with the two valid rows", h.adapter.batches)
	}
	if spec := h.adapter.batches[0].GetSpecs()[0]; !strings.Contains(spec.GetSubjectData(), `"hectares":12`) || spec.GetStatus() == nil {
		t.Fatalf("spec = %v", spec)
	}
	last := sent[len(sent)-1]
	if !last.GetDone() || last.GetTotal() != 4 || last.GetAccepted() != 1 || last.GetRejected() != 3 {
		t.Fatalf("progress = %v", last)
	}
	page, err := h.service.GetBatch(context.Background(), connect.NewRequest(&issuancev1.GetBatchRequest{
		JobId: last.GetJobId(), Page: &commonv1.Pagination{PageSize: 2},
	}))
	if err != nil {
		t.Fatal(err)
	}
	first := page.Msg.GetRows()[0]
	if first.GetRow() != 1 || first.GetOffer().GetLink() == "" || first.GetOffer().GetChannel() != backendv1.Channel_CHANNEL_PDF {
		t.Fatalf("row 1 = %v, want a document", first)
	}
	if h.recorder.last() == nil {
		t.Fatal("the native row has no issued record")
	}
	if second := page.Msg.GetRows()[1]; !strings.Contains(second.GetError().GetMessage(), "the stack refused the row") {
		t.Fatalf("row 2 = %v", second)
	}
}

func TestIssueBatchNativeChecksTheStack(t *testing.T) {
	h := newHarness(t, nil)
	items := []*issuancev1.IssueBatchRequest_Item{{Row: 1, SubjectData: `{"fullName":"Ada","farmerID":"FM-1"}`}}
	_, err := h.batch(t, &issuancev1.IssueBatchRequest{SchemaId: "farmer", Native: true, Items: items})
	wantCode(t, err, connect.CodeFailedPrecondition)

	h = nativeHarness(t)
	_, err = h.batch(t, &issuancev1.IssueBatchRequest{SchemaId: "farmer", Native: true, Channel: backendv1.Channel_CHANNEL_OID4VCI_PREAUTH, Items: items})
	wantCode(t, err, connect.CodeInvalidArgument)

	h.adapter.batchErr = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	sent, err := h.batch(t, &issuancev1.IssueBatchRequest{SchemaId: "farmer", Native: true, Items: items})
	if err != nil {
		t.Fatal(err)
	}
	if last := sent[len(sent)-1]; last.GetRejected() != 1 || !last.GetDone() {
		t.Fatalf("a failed stack call must fail every row: %v", last)
	}

	h = nativeHarness(t)
	h.adapter.batch = &backendv1.IssueBatchResponse{}
	sent, err = h.batch(t, &issuancev1.IssueBatchRequest{SchemaId: "farmer", Native: true, Items: items})
	if err != nil {
		t.Fatal(err)
	}
	if last := sent[len(sent)-1]; last.GetRejected() != 1 {
		t.Fatalf("a row the stack does not answer must fail: %v", last)
	}

	h = nativeHarness(t)
	h.schemas.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	_, err = h.batch(t, &issuancev1.IssueBatchRequest{SchemaId: "farmer", Native: true, Items: items})
	wantCode(t, err, connect.CodeUnavailable)
}
