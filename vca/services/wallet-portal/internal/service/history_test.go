// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"testing"
	"time"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

const requestLink = "openid4vp://?client_id=v&request_uri=https://verifier.example/r/1"

func records(t *testing.T, svc *service.Service) []*walletportalv1.PresentationRecord {
	t.Helper()
	resp, err := svc.ListPresentations(ctx(), connect.NewRequest(&walletportalv1.ListPresentationsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return resp.Msg.GetRecords()
}

// TestConfirmWritesRecord checks that a shared presentation leaves a
// record with the verifier, the shared claim names, and the result, and
// no claim value.
func TestConfirmWritesRecord(t *testing.T) {
	holder := &fakeHolder{credential: credential(t), accepted: true}
	svc := build(t, func(o *service.Options) { o.Holder, o.Fetch = holder, fetchRequest })
	confirm, err := svc.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: requestLink, SelectedCards: map[string]string{"licence": "c1"},
		Disclosed: map[string]*walletportalv1.PresentConfirmRequest_ClaimPaths{"licence": {Paths: []string{"given_name"}}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	got := records(t, svc)
	if len(got) != 1 {
		t.Fatalf("records = %v", got)
	}
	r := got[0]
	if r.GetVerifier() != "https://verifier.example" || r.GetVerifierName() != "Agency A" ||
		r.GetResult() != walletportalv1.PresentationRecord_RESULT_ACCEPTED ||
		len(r.GetClaims()) != 1 || r.GetClaims()[0] != "given_name" || !r.GetAt().AsTime().Equal(clock) {
		t.Fatalf("record = %v", r)
	}
	if confirm.Msg.GetRecord().GetId() != r.GetId() {
		t.Fatalf("confirm record = %v", confirm.Msg.GetRecord())
	}
	// A verifier that refuses and a wallet that fails leave records too.
	refused := build(t, func(o *service.Options) { o.Holder, o.Fetch = &fakeHolder{credential: credential(t)}, fetchRequest })
	if _, err := refused.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: requestLink, SelectedCards: map[string]string{"licence": "c1"},
	})); err != nil {
		t.Fatal(err)
	}
	if got := records(t, refused); len(got) != 1 || got[0].GetResult() != walletportalv1.PresentationRecord_RESULT_REJECTED {
		t.Fatalf("refused = %v", got)
	}
	down := build(t, func(o *service.Options) {
		o.Holder, o.Fetch = &fakeHolder{presentErr: errors.New("down")}, fetchRequest
	})
	if _, err := down.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: requestLink, SelectedCards: map[string]string{"licence": "c1"},
	})); err == nil {
		t.Fatal("want an error")
	}
	if got := records(t, down); len(got) != 1 || got[0].GetResult() != walletportalv1.PresentationRecord_RESULT_FAILED {
		t.Fatalf("down = %v", got)
	}
}

// TestDeclineWritesRecord checks the refusal: the wallet tells the
// verifier with the error access_denied, keeps a record with no claim,
// and forgets the request.
func TestDeclineWritesRecord(t *testing.T) {
	var target string
	var form url.Values
	svc := build(t, func(o *service.Options) {
		o.Fetch = fetchRequest
		o.Post = func(_ context.Context, to string, f url.Values) ([]byte, error) {
			target, form = to, f
			return nil, nil
		}
	})
	scan, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{Text: requestLink}))
	if err != nil {
		t.Fatal(err)
	}
	id := scan.Msg.GetDetected().GetPresentationId()
	resp, err := svc.PresentDecline(ctx(), connect.NewRequest(&walletportalv1.PresentDeclineRequest{PresentationId: id}))
	if err != nil {
		t.Fatal(err)
	}
	r := resp.Msg.GetRecord()
	if r.GetResult() != walletportalv1.PresentationRecord_RESULT_DECLINED || len(r.GetClaims()) != 0 ||
		r.GetVerifier() != "https://verifier.example" {
		t.Fatalf("record = %v", r)
	}
	if target != "https://verifier.example/direct_post" || form.Get("error") != "access_denied" || form.Get("state") != "s-1" {
		t.Fatalf("told %q %v", target, form)
	}
	if got := records(t, svc); len(got) != 1 || got[0].GetId() != r.GetId() {
		t.Fatalf("records = %v", got)
	}
	// The request is gone, so a second answer finds nothing.
	if _, err := svc.PresentDecline(ctx(), connect.NewRequest(&walletportalv1.PresentDeclineRequest{PresentationId: id})); err == nil {
		t.Fatal("want an error for a second answer")
	}
	// A verifier that does not answer still leaves the record.
	quiet := build(t, func(o *service.Options) {
		o.Fetch = fetchRequest
		o.Post = func(context.Context, string, url.Values) ([]byte, error) { return nil, errors.New("down") }
	})
	if _, err := quiet.PresentDecline(ctx(), connect.NewRequest(&walletportalv1.PresentDeclineRequest{PresentationId: requestLink})); err != nil {
		t.Fatal(err)
	}
	if _, err := quiet.PresentDecline(context.Background(), connect.NewRequest(&walletportalv1.PresentDeclineRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no session: %v", err)
	}
}

// TestListPresentationsNewestFirst checks the order, the page size, and
// that a record outlives the pending records.
func TestListPresentationsNewestFirst(t *testing.T) {
	at := clock
	svc := build(t, func(o *service.Options) {
		o.Fetch = fetchRequest
		o.Now = func() time.Time { return at }
		o.Post = func(context.Context, string, url.Values) ([]byte, error) { return nil, nil }
	})
	for i := 0; i < 3; i++ {
		if _, err := svc.PresentDecline(ctx(), connect.NewRequest(&walletportalv1.PresentDeclineRequest{PresentationId: requestLink})); err != nil {
			t.Fatal(err)
		}
		at = at.Add(time.Minute)
	}
	at = at.Add(30 * 24 * time.Hour)
	got := records(t, svc)
	if len(got) != 3 || !got[0].GetAt().AsTime().After(got[2].GetAt().AsTime()) {
		t.Fatalf("records = %v", got)
	}
	two, err := svc.ListPresentations(ctx(), connect.NewRequest(&walletportalv1.ListPresentationsRequest{
		Page: &commonv1.Pagination{PageSize: 2},
	}))
	if err != nil || len(two.Msg.GetRecords()) != 2 || two.Msg.GetPage().GetTotalSize() != 3 {
		t.Fatalf("two = %v, %v", two, err)
	}
	if _, err := svc.ListPresentations(context.Background(), connect.NewRequest(&walletportalv1.ListPresentationsRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no session: %v", err)
	}
}

// TestPasteReadsARequestObject checks that a pasted or uploaded request
// object, with no link, opens the consent screen.
func TestPasteReadsARequestObject(t *testing.T) {
	svc := build(t, nil)
	pasted, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: string(requestObject())}))
	if err != nil {
		t.Fatal(err)
	}
	found := pasted.Msg.GetDetected()
	if found.GetKind() != walletportalv1.Detected_KIND_PRESENTATION_REQUEST {
		t.Fatalf("detected = %v", found)
	}
	start, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{PresentationId: found.GetPresentationId()}))
	if err != nil || start.Msg.GetVerifier() != "https://verifier.example" {
		t.Fatalf("start = %v, %v", start, err)
	}
}

// TestHistoryKeepsTheNewest checks that a wallet keeps MaxHistory
// records and drops the oldest.
func TestHistoryKeepsTheNewest(t *testing.T) {
	n := 0
	svc := build(t, func(o *service.Options) {
		o.Fetch, o.PageSizeMax = fetchRequest, 500
		o.NewID = func() string { n++; return "r" + strconv.Itoa(n) }
	})
	for i := 0; i < service.MaxHistory+2; i++ {
		if _, err := svc.PresentDecline(ctx(), connect.NewRequest(&walletportalv1.PresentDeclineRequest{PresentationId: requestLink})); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := svc.ListPresentations(ctx(), connect.NewRequest(&walletportalv1.ListPresentationsRequest{
		Page: &commonv1.Pagination{PageSize: 500},
	}))
	if err != nil || resp.Msg.GetPage().GetTotalSize() != service.MaxHistory {
		t.Fatalf("total = %d, %v", resp.Msg.GetPage().GetTotalSize(), err)
	}
}
