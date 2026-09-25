// SPDX-License-Identifier: Apache-2.0

package auditlog_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
)

// TestRecordNamesTheCodeNotTheError keeps the error text, which can
// hold a claim value, out of the event (ADR-039 decision 3).
func TestRecordNamesTheCodeNotTheError(t *testing.T) {
	clock := start
	l := newLog(t, &clock)
	ctx := context.Background()
	h := http.Header{}
	h.Set(auditlog.ActorHeader, "kc|root")
	l.Record(ctx, h, "trust.UpsertEntry", "did:web:a", "", nil)
	l.Record(ctx, nil, "trust.DeleteEntry", "did:web:b", "", connect.NewError(connect.CodeNotFound, errors.New("no entry for Jane Doe")))
	l.Record(ctx, nil, "trust.DeleteEntry", "did:web:c", "", errors.New("plain Jane Doe"))
	l.Record(ctx, nil, "trust.UpsertEntry", "did:web:d", "Pending review.", nil)
	l.Record(auditlog.WithActor(ctx, "kc|ada"), http.Header{}, "issuance.Issue", "offer-1", "", nil)
	var none *auditlog.Log
	none.Record(ctx, h, "trust.UpsertEntry", "x", "", nil)
	page, err := l.Query(ctx, auditlog.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]auditlog.Record{}
	for _, r := range page.Records {
		got[r.Target] = r
	}
	if a := got["did:web:a"]; a.Actor != "kc|root" || !a.OK || a.Detail != "" {
		t.Errorf("a = %+v", a)
	}
	if b := got["did:web:b"]; b.OK || b.Detail != msg.T("audit.reason.code", "not_found") || b.Actor != "" {
		t.Errorf("b = %+v", b)
	}
	if c := got["did:web:c"]; c.Detail != msg.T("audit.reason.code", "unknown") {
		t.Errorf("c = %+v", c)
	}
	if d := got["did:web:d"]; d.Detail != "Pending review." {
		t.Errorf("d = %+v", d)
	}
	if e := got["offer-1"]; e.Actor != "kc|ada" {
		t.Errorf("the actor of the context = %+v", e)
	}
}
