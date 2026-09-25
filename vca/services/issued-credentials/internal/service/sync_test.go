// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/service"
)

// addLedger appends a record that came from the ledger of the stack.
func (f *fixture) addLedger(t *testing.T, id, credentialID string, index int64) record.Record {
	t.Helper()
	got, err := f.svc.AppendRecord(record.Record{
		ID: id, SchemaID: "FarmerCredential", SchemaVersion: 1, SubjectRef: f.svc.SubjectRef("F-" + id),
		DPG: "First stack", IssuedAt: clock, DPGCredentialID: credentialID,
		Binding: record.Binding{Kind: record.KindBitstring, ListID: "https://stack.example/status/1", Index: index,
			PublishURL: "https://stack.example/status/1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestStackChangesOnlyItsLedgerRecords sends a revoke to the stack only
// for a record that came from its ledger. A record with a status entry of
// VCA goes to the status service even when the stack lists revocation.
func TestStackChangesOnlyItsLedgerRecords(t *testing.T) {
	f := newFixture(t)
	stack := &fakeStack{features: map[backendv1.Feature]bool{backendv1.Feature_FEATURE_REVOCATION: true}}
	withStack(t, f, stack)
	f.add(t, "rec-vca", "farmer", 1, nil)
	f.addLedger(t, "rec-ledger", "urn:uuid:ledger-1", 17)
	ctx := context.Background()
	for _, id := range []string{"rec-vca", "rec-ledger"} {
		if _, err := f.svc.Revoke(ctx, staff(&issuedv1.RevokeRequest{Id: id, Status: issuedv1.Status_STATUS_REVOKED, Reason: "Lost"})); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.status.calls) != 1 || len(stack.changes) != 1 || stack.changes[0].CredentialID != "urn:uuid:ledger-1" {
		t.Fatalf("status %d, stack %+v", len(f.status.calls), stack.changes)
	}
}

// TestSuspendThroughStackWithFeature suspends and reinstates a ledger
// record through the stack when it lists FEATURE_SUSPENSION, and through
// the status service when it lists revocation only.
func TestSuspendThroughStackWithFeature(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	stack := &fakeStack{features: map[backendv1.Feature]bool{
		backendv1.Feature_FEATURE_REVOCATION: true, backendv1.Feature_FEATURE_SUSPENSION: true,
	}}
	withStack(t, f, stack)
	f.addLedger(t, "rec-1", "urn:uuid:ledger-1", 17)
	if _, err := f.svc.Revoke(ctx, staff(&issuedv1.RevokeRequest{Id: "rec-1", Status: issuedv1.Status_STATUS_SUSPENDED, Reason: "Review"})); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.Reinstate(ctx, staff(&issuedv1.ReinstateRequest{Id: "rec-1", Reason: "Cleared"}))
	if err != nil || got.Msg.GetRecord().GetStatus() != issuedv1.Status_STATUS_ACTIVE {
		t.Fatalf("reinstate: %v %v", got, err)
	}
	if len(stack.changes) != 2 || stack.changes[0].Action != backendv1.RevokeRequest_ACTION_SUSPEND ||
		stack.changes[1].Action != backendv1.RevokeRequest_ACTION_REINSTATE || len(f.status.calls) != 0 {
		t.Fatalf("stack %+v, status %d", stack.changes, len(f.status.calls))
	}
	events, err := f.svc.History(ctx, "rec-1")
	if err != nil || len(events) != 2 {
		t.Fatalf("history %+v %v", events, err)
	}
	for _, e := range events {
		if e.Action == service.ActionReinstate && e.Detail != msg.T("audit.issued.stack", "active") {
			t.Fatalf("the reinstatement does not name the stack: %+v", e)
		}
	}

	g := newFixture(t)
	revokeOnly := &fakeStack{features: map[backendv1.Feature]bool{backendv1.Feature_FEATURE_REVOCATION: true}}
	withStack(t, g, revokeOnly)
	g.addLedger(t, "rec-1", "urn:uuid:ledger-1", 17)
	if _, err := g.svc.Revoke(ctx, staff(&issuedv1.RevokeRequest{Id: "rec-1", Status: issuedv1.Status_STATUS_SUSPENDED, Reason: "Review"})); err != nil {
		t.Fatal(err)
	}
	if len(revokeOnly.changes) != 0 || len(g.status.calls) != 1 {
		t.Fatalf("a suspension without the feature: stack %d, status %d", len(revokeOnly.changes), len(g.status.calls))
	}
}

// ledgerEntry returns one entry of the fake ledger.
func ledgerEntry(id string, index int64, day int) *backendv1.LedgerEntry {
	return &backendv1.LedgerEntry{
		CredentialId: id, CredentialType: "FarmerCredential,VerifiableCredential", StatusPurpose: "revocation",
		IssuedAt:  timestamppb.New(clock.AddDate(0, 0, day)),
		ExpiresAt: timestamppb.New(clock.AddDate(2, 0, day)),
		Status: &backendv1.StatusListBinding{Kind: backendv1.StatusListBinding_KIND_BITSTRING,
			ListId: "https://stack.example/status/1", Index: index, PublishUrl: "https://stack.example/status/1"},
	}
}

// TestSyncAddsLedgerEntries reads every page of the stack ledger and
// adds the entries the log lacks, once. The audit log names the actor
// and the counts.
func TestSyncAddsLedgerEntries(t *testing.T) {
	f := newFixture(t)
	stack := &fakeStack{features: map[backendv1.Feature]bool{backendv1.Feature_FEATURE_ISSUED_LEDGER: true},
		ledger: []*backendv1.LedgerEntry{ledgerEntry("urn:uuid:a", 17, -3), ledgerEntry("urn:uuid:b", 42, -2), ledgerEntry("urn:uuid:c", 58, -1)}}
	withStack(t, f, stack)
	f.addLedger(t, "rec-known", "urn:uuid:b", 42)
	ctx := auditlog.WithActor(context.Background(), "kc|ada")
	q := service.SyncQuery{CredentialType: "FarmerCredential", Attribute: "farmerID", Value: "F-1024"}
	rows, err := f.svc.Sync(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || !rows[0].Added || rows[1].Added || rows[1].RecordID != "rec-known" || !rows[2].Added {
		t.Fatalf("rows %+v", rows)
	}
	if len(stack.asked) != 2 || stack.asked[0].GetAttributes()["farmerID"] != "F-1024" || stack.asked[0].GetCredentialType() != "FarmerCredential" {
		t.Fatalf("the ledger took %+v", stack.asked)
	}
	got, err := f.svc.Get(ctx, staff(&issuedv1.GetRequest{Id: rows[0].RecordID}))
	if err != nil {
		t.Fatal(err)
	}
	r := got.Msg.GetRecord()
	if r.GetDpgCredentialId() != "urn:uuid:a" || r.GetStatusBinding().GetIndex() != 17 || r.GetSchemaId() != "FarmerCredential" ||
		r.GetDpg() != "First stack" || !r.GetIssuedAt().AsTime().Equal(clock.AddDate(0, 0, -3)) ||
		r.GetValidity().GetValidUntil() == nil || r.GetSubject().GetRef() != f.svc.SubjectRef("F-1024") {
		t.Fatalf("record %v", r)
	}
	again, err := f.svc.Sync(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range again {
		if row.Added {
			t.Fatalf("a second sync added %s", row.Entry.GetCredentialId())
		}
	}
	page, err := f.svc.Audit().Query(context.Background(), auditlog.Filter{Action: service.ActionSync})
	if err != nil || len(page.Records) != 2 || page.Records[0].Actor != "kc|ada" {
		t.Fatalf("audit %+v %v", page, err)
	}
	if page.Records[1].Detail != msg.T("audit.issued.sync", "3", "2") && page.Records[0].Detail != msg.T("audit.issued.sync", "3", "2") {
		t.Fatalf("audit detail %+v", page.Records)
	}
}

// TestSyncNeedsTheFeatureAndAnswers refuses a sync without the feature,
// without a query, and when the stack does not answer.
func TestSyncNeedsTheFeatureAndAnswers(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	q := service.SyncQuery{CredentialType: "FarmerCredential", Attribute: "farmerID", Value: "F-1024"}
	if _, err := f.svc.Sync(ctx, q); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("no stack: %v", err)
	}
	withStack(t, f, &fakeStack{features: map[backendv1.Feature]bool{}})
	if _, err := f.svc.Sync(ctx, q); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("no feature: %v", err)
	}
	withStack(t, f, &fakeStack{features: map[backendv1.Feature]bool{backendv1.Feature_FEATURE_ISSUED_LEDGER: true}})
	for _, bad := range []service.SyncQuery{{Attribute: "a", Value: "v"}, {CredentialType: "t", Value: "v"}, {CredentialType: "t", Attribute: "a"}} {
		if _, err := f.svc.Sync(ctx, bad); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("%+v: %v", bad, err)
		}
	}
	withStack(t, f, &fakeStack{features: map[backendv1.Feature]bool{backendv1.Feature_FEATURE_ISSUED_LEDGER: true}, err: errors.New("down")})
	if _, err := f.svc.Sync(ctx, q); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("down: %v", err)
	}
	refused := connect.NewError(connect.CodeInvalidArgument, errors.New("bad attribute"))
	withStack(t, f, &fakeStack{features: map[backendv1.Feature]bool{backendv1.Feature_FEATURE_ISSUED_LEDGER: true}, err: refused})
	if _, err := f.svc.Sync(ctx, q); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("refused: %v", err)
	}
	// An entry without an issuance time takes the time of the sync.
	f.now = clock.Add(time.Hour)
	withStack(t, f, &fakeStack{features: map[backendv1.Feature]bool{backendv1.Feature_FEATURE_ISSUED_LEDGER: true},
		ledger: []*backendv1.LedgerEntry{{CredentialId: "urn:uuid:bare"}}})
	rows, err := f.svc.Sync(ctx, q)
	if err != nil || len(rows) != 1 || !rows[0].Added {
		t.Fatalf("bare entry: %+v %v", rows, err)
	}
	got, err := f.svc.Get(ctx, staff(&issuedv1.GetRequest{Id: rows[0].RecordID}))
	if err != nil || !got.Msg.GetRecord().GetIssuedAt().AsTime().Equal(f.now) || got.Msg.GetRecord().GetStatusBinding() != nil {
		t.Fatalf("bare record %v %v", got, err)
	}
}
