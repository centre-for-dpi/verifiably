// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
)

// TestStoreWritesAuditEvent records each stored result with its id and
// verdict, and a refused result with its code. The event holds no
// claim of the presentation.
func TestStoreWritesAuditEvent(t *testing.T) {
	svc := newService(t)
	ctx := context.Background()
	req := connect.NewRequest(&resultsv1.StoreRequest{Result: sample("", testNow)})
	req.Header().Set(auditlog.ActorHeader, "kc|grace")
	stored, err := svc.Store(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, serr := svc.Store(ctx, connect.NewRequest(&resultsv1.StoreRequest{})); serr == nil {
		t.Fatal("an empty result passed")
	}
	page, err := svc.Audit().Query(ctx, auditlog.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range page.Records {
		got = append(got, strings.Join([]string{r.Action, r.Actor, r.Target, r.Outcome(), r.Detail}, "|"))
		if strings.Contains(r.Detail, `"a"`) {
			t.Errorf("the event holds a claim: %+v", r)
		}
	}
	want := map[string]bool{
		"results.Store|kc|grace|" + stored.Msg.GetResult().GetId() + "|success|" + msg.T("audit.results.verdict", "valid"): true,
		"results.Store|||failure|" + msg.T("audit.reason.code", "invalid_argument"):                                        true,
	}
	if len(got) != 2 || !want[got[0]] || !want[got[1]] {
		t.Fatalf("events = %q", got)
	}
}
