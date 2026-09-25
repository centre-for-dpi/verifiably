// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
)

// staff returns a request that names an issuer operator as its actor.
func staff[T any](m *T) *connect.Request[T] {
	req := connect.NewRequest(m)
	req.Header().Set(auditlog.ActorHeader, "kc|ada")
	return req
}

// TestRevokeWritesAuditEvent records each revoke, suspend and
// reinstate with the record id, and a failure with its code. The event
// never holds the reason, which is free text of the operator.
func TestRevokeWritesAuditEvent(t *testing.T) {
	f := newFixture(t)
	f.add(t, "rec-1", "birth", 1, map[string]string{"name": "Jane"})
	f.add(t, "rec-2", "birth", 2, nil)
	ctx := context.Background()
	calls := []func() error{
		func() error {
			_, err := f.svc.Revoke(ctx, staff(&issuedv1.RevokeRequest{Id: "rec-1", Status: issuedv1.Status_STATUS_SUSPENDED, Reason: "Jane asked"}))
			return err
		},
		func() error {
			_, err := f.svc.Reinstate(ctx, staff(&issuedv1.ReinstateRequest{Id: "rec-1", Reason: "Jane came back"}))
			return err
		},
		func() error {
			_, err := f.svc.Revoke(ctx, staff(&issuedv1.RevokeRequest{Id: "rec-2", Status: issuedv1.Status_STATUS_REVOKED, Reason: "lost"}))
			return err
		},
		func() error {
			_, err := f.svc.Reinstate(ctx, connect.NewRequest(&issuedv1.ReinstateRequest{Id: "rec-2", Reason: "x"}))
			return err
		},
		func() error {
			_, err := f.svc.Revoke(ctx, staff(&issuedv1.RevokeRequest{Id: "rec-9", Status: issuedv1.Status_STATUS_REVOKED, Reason: "x"}))
			return err
		},
	}
	for i, call := range calls {
		f.now = clock.Add(time.Duration(i+1) * time.Second)
		if err := call(); (err == nil) != (i < 3) {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if _, err := f.svc.Get(ctx, staff(&issuedv1.GetRequest{Id: "rec-1"})); err != nil {
		t.Fatal(err)
	}
	page, err := f.svc.Audit().Query(ctx, auditlog.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i := len(page.Records) - 1; i >= 0; i-- {
		r := page.Records[i]
		got = append(got, strings.Join([]string{r.Action, r.Actor, r.Target, r.Outcome(), r.Detail}, "|"))
		if strings.Contains(r.Detail, "Jane") {
			t.Errorf("the event holds the reason: %+v", r)
		}
	}
	want := []string{
		"issued.Suspend|kc|ada|rec-1|success|" + msg.T("audit.issued.status", "suspended"),
		"issued.Reinstate|kc|ada|rec-1|success|" + msg.T("audit.issued.status", "active"),
		"issued.Revoke|kc|ada|rec-2|success|" + msg.T("audit.issued.status", "revoked"),
		"issued.Reinstate||rec-2|failure|" + msg.T("audit.reason.code", "failed_precondition"),
		"issued.Revoke|kc|ada|rec-9|failure|" + msg.T("audit.reason.code", "not_found"),
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
