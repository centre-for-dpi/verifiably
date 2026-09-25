// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/service"
)

// TestIssueWritesAuditEvent records each issue, one alone and each row
// of a batch, with the offer id, the schema, and the channel. The event
// never holds a claim of the subject.
func TestIssueWritesAuditEvent(t *testing.T) {
	var events *auditlog.Log
	h := newHarness(t, func(o *service.Options, _ *harness) {
		tick := fixedTime
		clock := func() time.Time { tick = tick.Add(time.Second); return tick }
		var err error
		if events, err = auditlog.New(store.Memory(), clock); err != nil {
			t.Fatal(err)
		}
		o.Audit = events
	})
	ctx := context.Background()
	req := connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId: "farmer", SubjectData: `{"fullName":"Ada Lovelace","farmerID":"FM-0001"}`,
		Delivery: &issuancev1.Delivery{Channel: backendv1.Channel_CHANNEL_OID4VCI_PREAUTH},
	})
	req.Header().Set(auditlog.ActorHeader, "kc|ada")
	one, err := h.service.Issue(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, ierr := h.service.Issue(ctx, connect.NewRequest(&issuancev1.IssueRequest{
		SchemaId: "farmer", SubjectData: `{"fullName":"No identifier"}`,
	})); ierr == nil {
		t.Fatal("a row without the identifier passed")
	}
	sent, err := h.batch(t, &issuancev1.IssueBatchRequest{
		SchemaId: "farmer", Channel: backendv1.Channel_CHANNEL_OID4VCI_PREAUTH,
		Items: []*issuancev1.IssueBatchRequest_Item{{Row: 1, SubjectData: `{"fullName":"Grace Hopper","farmerID":"FM-0002"}`}},
	})
	if err != nil || len(sent) == 0 {
		t.Fatalf("IssueBatch = %d, %v", len(sent), err)
	}
	page, err := events.Query(ctx, auditlog.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i := len(page.Records) - 1; i >= 0; i-- {
		r := page.Records[i]
		got = append(got, strings.Join([]string{r.Action, r.Actor, r.Target, r.Outcome(), r.Detail}, "|"))
		for _, claim := range []string{"Ada", "Grace", "FM-000"} {
			if strings.Contains(r.Detail, claim) || strings.Contains(r.Target, claim) {
				t.Errorf("the event holds a claim: %+v", r)
			}
		}
	}
	issued := msg.T("audit.issuance.issue", "farmer", "3", "oid4vci_preauth")
	want := []string{
		"issuance.Issue|kc|ada|" + one.Msg.GetOffer().GetId() + "|success|" + issued,
		"issuance.Issue||farmer|failure|" + msg.T("audit.reason.code", "invalid_argument"),
		// The batch job takes the id id-2, so its row gets id-3.
		"issuance.Issue||id-3|success|" + issued,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
