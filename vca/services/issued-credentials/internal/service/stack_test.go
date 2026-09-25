// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/store"
)

// fakeStack is the DPG adapter of the pair: the features it lists, the
// changes it took, and its ledger.
type fakeStack struct {
	features map[backendv1.Feature]bool
	revokes  []*backendv1.StatusListBinding
	changes  []service.StackChange
	reasons  []string
	err      error
	ledger   []*backendv1.LedgerEntry
	asked    []*backendv1.ListIssuedCredentialsRequest
}

func (f *fakeStack) Has(_ context.Context, feature backendv1.Feature) bool {
	return f.features[feature]
}

func (f *fakeStack) Name(context.Context) string { return "First stack" }

func (f *fakeStack) Change(_ context.Context, c service.StackChange) error {
	if f.err != nil {
		return f.err
	}
	f.revokes = append(f.revokes, c.Binding)
	f.changes = append(f.changes, c)
	f.reasons = append(f.reasons, c.Reason)
	return nil
}

// Ledger pages the ledger two entries at a time.
func (f *fakeStack) Ledger(_ context.Context, req *backendv1.ListIssuedCredentialsRequest) (*backendv1.ListIssuedCredentialsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.asked = append(f.asked, req)
	start := 0
	if req.GetPage().GetPageToken() != "" {
		start = 2
	}
	end := min(start+2, len(f.ledger))
	out := &backendv1.ListIssuedCredentialsResponse{Credentials: f.ledger[start:end], Page: &commonv1.PageResult{TotalSize: int64(len(f.ledger))}}
	if end < len(f.ledger) {
		out.Page.NextPageToken = "2"
	}
	return out, nil
}

// withStack rebuilds the service of f over the same store with a stack.
func withStack(t *testing.T, f *fixture, stack service.Stack) {
	t.Helper()
	svc, err := service.New(service.Options{Store: f.store, Status: f.status, Stack: stack, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
}

// TestRevokeGoesThroughTheStackWhenListed is ADR-034 decision 5 for revocation: an
// adapter that lists FEATURE_REVOCATION revokes the credential itself,
// so the status service of VCA takes no call.
func TestRevokeGoesThroughTheStackWhenListed(t *testing.T) {
	f := newFixture(t)
	stack := &fakeStack{features: map[backendv1.Feature]bool{backendv1.Feature_FEATURE_REVOCATION: true}}
	withStack(t, f, stack)
	f.addLedger(t, "rec-1", "urn:uuid:ledger-1", 3)
	res, err := f.svc.Revoke(context.Background(), staff(&issuedv1.RevokeRequest{Id: "rec-1", Status: issuedv1.Status_STATUS_REVOKED, Reason: "Lost card"}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetRecord().GetStatus() != issuedv1.Status_STATUS_REVOKED || res.Msg.GetRecord().GetStatusReason() != "Lost card" {
		t.Fatalf("record = %v", res.Msg.GetRecord())
	}
	if len(stack.changes) != 1 || stack.revokes[0].GetIndex() != 3 || stack.reasons[0] != "Lost card" ||
		stack.changes[0].CredentialID != "urn:uuid:ledger-1" || stack.changes[0].Action != backendv1.RevokeRequest_ACTION_REVOKE {
		t.Fatalf("stack changes = %+v", stack.changes)
	}
	if len(f.status.calls) != 0 {
		t.Fatalf("the status service took %d calls", len(f.status.calls))
	}
	page, err := f.svc.Audit().Query(context.Background(), auditlog.Filter{Target: "rec-1"})
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("audit = %+v, %v", page, err)
	}
	if got := page.Records[0]; got.Actor != "kc|ada" || got.Detail != msg.T("audit.issued.stack", "revoked") {
		t.Fatalf("event = %+v", got)
	}
}

// TestRevokeUsesTheStatusServiceWithoutTheFeature keeps the VCA status
// services for a stack without FEATURE_REVOCATION, and for a suspension
// on any stack: the adapter revoke carries no suspension.
func TestRevokeUsesTheStatusServiceWithoutTheFeature(t *testing.T) {
	f := newFixture(t)
	stack := &fakeStack{features: map[backendv1.Feature]bool{}}
	withStack(t, f, stack)
	f.add(t, "rec-1", "farmer", 1, nil)
	if _, err := f.svc.Revoke(context.Background(), staff(&issuedv1.RevokeRequest{Id: "rec-1", Status: issuedv1.Status_STATUS_REVOKED, Reason: "Fraud"})); err != nil {
		t.Fatal(err)
	}
	if len(stack.revokes) != 0 || len(f.status.calls) != 1 || f.status.calls[0].GetValue() != service.StatusValueSet {
		t.Fatalf("stack %d, status %v", len(stack.revokes), f.status.calls)
	}

	listed := &fakeStack{features: map[backendv1.Feature]bool{backendv1.Feature_FEATURE_REVOCATION: true}}
	withStack(t, f, listed)
	f.add(t, "rec-2", "farmer", 2, nil)
	if _, err := f.svc.Revoke(context.Background(), staff(&issuedv1.RevokeRequest{Id: "rec-2", Status: issuedv1.Status_STATUS_SUSPENDED, Reason: "Review"})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Reinstate(context.Background(), staff(&issuedv1.ReinstateRequest{Id: "rec-2", Reason: "Cleared"})); err != nil {
		t.Fatal(err)
	}
	if len(listed.revokes) != 0 || len(f.status.calls) != 3 {
		t.Fatalf("stack %d, status %d", len(listed.revokes), len(f.status.calls))
	}
}

// TestStackRevokeFailureLeavesTheLog keeps the log unchanged when the
// stack refuses, as with the status service.
func TestStackRevokeFailureLeavesTheLog(t *testing.T) {
	f := newFixture(t)
	withStack(t, f, &fakeStack{features: map[backendv1.Feature]bool{backendv1.Feature_FEATURE_REVOCATION: true}, err: errors.New("down")})
	f.addLedger(t, "rec-1", "urn:uuid:ledger-1", 1)
	_, err := f.svc.Revoke(context.Background(), staff(&issuedv1.RevokeRequest{Id: "rec-1", Status: issuedv1.Status_STATUS_REVOKED, Reason: "Fraud"}))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("err = %v", err)
	}
	got, gerr := f.svc.Get(context.Background(), staff(&issuedv1.GetRequest{Id: "rec-1"}))
	if gerr != nil {
		t.Fatal(gerr)
	}
	if got.Msg.GetRecord().GetStatus() != issuedv1.Status_STATUS_ACTIVE {
		t.Fatalf("status = %v", got.Msg.GetRecord().GetStatus())
	}
}

// TestHistoryReadsTheAuditLogOfTheRecord returns the events of one
// record, oldest first, and nothing of another record.
func TestHistoryReadsTheAuditLogOfTheRecord(t *testing.T) {
	f := newFixture(t)
	f.add(t, "rec-1", "farmer", 1, nil)
	f.add(t, "rec-2", "farmer", 2, nil)
	ctx := context.Background()
	steps := []func() error{
		func() error {
			_, err := f.svc.Revoke(ctx, staff(&issuedv1.RevokeRequest{Id: "rec-1", Status: issuedv1.Status_STATUS_SUSPENDED, Reason: "Review"}))
			return err
		},
		func() error {
			_, err := f.svc.Revoke(ctx, staff(&issuedv1.RevokeRequest{Id: "rec-2", Status: issuedv1.Status_STATUS_REVOKED, Reason: "Lost"}))
			return err
		},
		func() error {
			_, err := f.svc.Reinstate(ctx, staff(&issuedv1.ReinstateRequest{Id: "rec-1", Reason: "Cleared"}))
			return err
		},
	}
	for i, step := range steps {
		f.now = clock.Add(time.Duration(i+1) * time.Minute)
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	events, err := f.svc.History(ctx, "rec-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Action != service.ActionSuspend || events[1].Action != service.ActionReinstate {
		t.Fatalf("history = %+v", events)
	}
	if _, err := f.svc.History(ctx, "rec-9"); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("history of an unknown record: %v", err)
	}
}

// sink collects the chunks of an export.
type sink struct{ buf bytes.Buffer }

func (s *sink) Send(m *issuedv1.ExportResponse) error {
	s.buf.Write(m.GetChunk())
	return nil
}

// TestExportWritesAuditEvent records who exported and how many records
// left the service.
func TestExportWritesAuditEvent(t *testing.T) {
	f := newFixture(t)
	f.add(t, "rec-1", "farmer", 1, map[string]string{"fullName": "Wanjiku Njeri"})
	f.add(t, "rec-2", "visitor", 2, nil)
	ctx := auditlog.WithActor(context.Background(), "kc|ada")
	var out sink
	if err := f.svc.ExportTo(ctx, &issuedv1.ExportRequest{Filter: &issuedv1.Filter{SchemaId: "farmer"}}, &out); err != nil {
		t.Fatal(err)
	}
	page, err := f.svc.Audit().Query(context.Background(), auditlog.Filter{Action: service.ActionExport})
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("audit = %+v, %v", page, err)
	}
	if got := page.Records[0]; got.Actor != "kc|ada" || got.Detail != msg.T("audit.issued.export", "1", "csv") {
		t.Fatalf("event = %+v", got)
	}
	err = f.svc.ExportTo(ctx, &issuedv1.ExportRequest{Encoding: issuedv1.ExportRequest_Encoding(9)}, &out)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad encoding: %v", err)
	}
	page, err = f.svc.Audit().Query(context.Background(), auditlog.Filter{Action: service.ActionExport, Outcome: auditlog.OutcomeFailure})
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("the failed export left no event: %+v", page)
	}
}

// TestSchemaIDsListsEverySchema gives the schema filter of the list page
// its options, sorted and once each.
func TestSchemaIDsListsEverySchema(t *testing.T) {
	st, err := store.Open(sharedstore.MemoryDoc())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	if got := svc.SchemaIDs(); len(got) != 0 {
		t.Fatalf("empty log gives %v", got)
	}
	f := newFixture(t)
	f.add(t, "rec-1", "visitor", 1, nil)
	f.add(t, "rec-2", "farmer", 2, nil)
	f.add(t, "rec-3", "visitor", 3, nil)
	if got := f.svc.SchemaIDs(); len(got) != 2 || got[0] != "farmer" || got[1] != "visitor" {
		t.Fatalf("schemas = %v", got)
	}
}

// TestExportMatchesTheSearchText exports the records of a search, so the
// export of a page holds the rows the page lists.
func TestExportMatchesTheSearchText(t *testing.T) {
	f := newFixture(t)
	f.add(t, "rec-1", "farmer", 1, map[string]string{"fullName": "Wanjiku Njeri"})
	f.add(t, "rec-2", "farmer", 2, map[string]string{"fullName": "Otieno Ouma"})
	var out sink
	if err := f.svc.ExportTo(context.Background(), &issuedv1.ExportRequest{Query: "wanjiku", Encoding: issuedv1.ExportRequest_ENCODING_JSON}, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.buf.String(); !strings.Contains(got, "rec-1") || strings.Contains(got, "rec-2") {
		t.Fatalf("export = %s", got)
	}
	err := f.svc.ExportTo(context.Background(), &issuedv1.ExportRequest{Query: strings.Repeat("x", 201)}, &out)
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("long query: %v", err)
	}
}

// TestGetReportsAnEndedValidityAsExpired reads a record the same way in
// a list and alone.
func TestGetReportsAnEndedValidityAsExpired(t *testing.T) {
	f := newFixture(t)
	r := f.add(t, "rec-1", "farmer", 1, nil)
	r.ID, r.ValidUntil, r.RecordHash, r.PreviousHash = "rec-2", clock.Add(time.Hour), "", ""
	if _, err := f.svc.AppendRecord(r); err != nil {
		t.Fatal(err)
	}
	f.now = clock.Add(2 * time.Hour)
	got, err := f.svc.Get(context.Background(), staff(&issuedv1.GetRequest{Id: "rec-2"}))
	if err != nil || got.Msg.GetRecord().GetStatus() != issuedv1.Status_STATUS_EXPIRED {
		t.Fatalf("record = %v, %v", got, err)
	}
}
