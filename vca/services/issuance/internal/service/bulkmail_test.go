// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
)

// P6-C4 and ADR-060: a stack whose bulk import mails each holder an
// offer gets the rows with their addresses. No credential comes back,
// and each row the stack takes is an offer that the stack delivers.

// mailingImport returns a harness whose adapter lists a bulk import on
// the email channel.
func mailingImport(t *testing.T) *harness {
	t.Helper()
	h := didcommHarness(t, true)
	h.adapter.capabilities.Features = append(h.adapter.capabilities.Features, backendv1.Feature_FEATURE_BULK_NATIVE)
	h.adapter.capabilities.BulkImport = &backendv1.BulkImport{
		Channel: backendv1.Channel_CHANNEL_EMAIL, EmailColumn: "email_identifier",
		Formats: []commonv1.Format{commonv1.Format_FORMAT_ANONCREDS, commonv1.Format_FORMAT_LDP_VC},
	}
	return h
}

func mailed(row int64, email string) *issuancev1.IssueBatchRequest_Item {
	item := &issuancev1.IssueBatchRequest_Item{Row: row, SubjectData: `{"fullName":"Wanjiku Njeri","farmerID":"FM-0042"}`}
	if email != "" {
		item.Delivery = &issuancev1.Delivery{Channel: backendv1.Channel_CHANNEL_EMAIL, Email: email}
	}
	return item
}

// TestIssueBatchNativeMailsThroughTheStack: the rows go to the adapter
// with their addresses, in the format of the import, with no status
// entry. A row without an address fails alone.
func TestIssueBatchNativeMailsThroughTheStack(t *testing.T) {
	h := mailingImport(t)
	h.adapter.batch = &backendv1.IssueBatchResponse{Items: []*backendv1.IssueBatchResponse_Item{
		{Position: 0, Delivered: true},
		{Position: 1, Error: &commonv1.Error{Code: "DPG-ROW", Message: "the row has no valid email address for the offer"}},
	}}
	sent, err := h.batch(t, &issuancev1.IssueBatchRequest{
		SchemaId: "farmer", Channel: backendv1.Channel_CHANNEL_EMAIL, Native: true,
		Items: []*issuancev1.IssueBatchRequest_Item{mailed(1, "wanjiku@registry.gov.test"), mailed(2, ""), mailed(3, "otieno at registry")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.adapter.batches) != 1 {
		t.Fatalf("batches = %v", h.adapter.batches)
	}
	call := h.adapter.batches[0]
	if !slices.Equal(call.GetEmails(), []string{"wanjiku@registry.gov.test", "otieno at registry"}) || len(call.GetSpecs()) != 2 {
		t.Fatalf("call = %v", call)
	}
	spec := call.GetSpecs()[0]
	if spec.GetFormat() != commonv1.Format_FORMAT_ANONCREDS || spec.GetConfigurationId() != "Ra8F7Qx1:3:CL:Ra8F7Qx1:2:Farmer:1.0:default" || spec.GetStatus() != nil {
		t.Errorf("spec = %v", spec)
	}
	last := sent[len(sent)-1]
	if !last.GetDone() || last.GetAccepted() != 1 || last.GetRejected() != 2 {
		t.Fatalf("progress = %v", last)
	}
	page, err := h.service.GetBatch(context.Background(), connect.NewRequest(&issuancev1.GetBatchRequest{JobId: last.GetJobId()}))
	if err != nil {
		t.Fatal(err)
	}
	rows := page.Msg.GetRows()
	first := rows[0]
	if first.GetOffer().GetChannel() != backendv1.Channel_CHANNEL_EMAIL || first.GetOffer().GetState() != issuancev1.Offer_STATE_DELIVERED ||
		first.GetOffer().GetOfferUri() != "" {
		t.Errorf("row 1 = %v", first)
	}
	failed, err := h.service.GetBatch(context.Background(), connect.NewRequest(&issuancev1.GetBatchRequest{JobId: last.GetJobId(), FailedOnly: true}))
	if err != nil {
		t.Fatal(err)
	}
	var reasons []string
	for _, r := range failed.Msg.GetRows() {
		reasons = append(reasons, r.GetError().GetMessage())
	}
	if text := strings.Join(reasons, " | "); !strings.Contains(text, "no email address") {
		t.Errorf("failed rows = %v", reasons)
	}
	if h.recorder.last() == nil {
		t.Error("the mailed row has no issued record")
	}
}

// TestIssueBatchNativeMailRefusals: the channel is the one of the
// import, and the import issues its formats only.
func TestIssueBatchNativeMailRefusals(t *testing.T) {
	h := mailingImport(t)
	items := []*issuancev1.IssueBatchRequest_Item{mailed(1, "wanjiku@registry.gov.test")}
	_, err := h.batch(t, &issuancev1.IssueBatchRequest{SchemaId: "farmer", Native: true, Channel: backendv1.Channel_CHANNEL_PDF, Items: items})
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = h.batch(t, &issuancev1.IssueBatchRequest{SchemaId: "farmer", Native: true, Format: commonv1.Format_FORMAT_VC_SD_JWT, Items: items})
	wantCode(t, err, connect.CodeInvalidArgument)
	// Without a channel the batch takes the one of the import.
	sent, err := h.batch(t, &issuancev1.IssueBatchRequest{SchemaId: "farmer", Native: true, Items: items})
	if err != nil {
		t.Fatal(err)
	}
	if last := sent[len(sent)-1]; last.GetRejected() != 1 {
		// The fake adapter answers with a credential, not a delivery, so
		// the row fails: an import on the email channel returns none.
		t.Errorf("progress = %v", last)
	}
}
