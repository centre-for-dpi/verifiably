// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/etsi"
)

// asAdmin returns a request that names the admin as its actor.
func asAdmin[T any](m *T) *connect.Request[T] {
	req := connect.NewRequest(m)
	req.Header().Set(auditlog.ActorHeader, "kc|root")
	return req
}

// events returns the audit events of the service, oldest first, as
// action|actor|target|outcome|detail lines.
func events(t *testing.T, svc *Service) []string {
	t.Helper()
	page, err := svc.Audit().Query(context.Background(), auditlog.Filter{PageSize: auditlog.MaxPageSize})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(page.Records) - 1; i >= 0; i-- {
		r := page.Records[i]
		out = append(out, strings.Join([]string{r.Action, r.Actor, r.Target, r.Outcome(), r.Detail}, "|"))
	}
	return out
}

// TestTrustChangeWritesAuditEvent records each entry change and each
// registry change with the actor the caller names (ADR-039 decision 1).
// A read writes nothing.
func TestTrustChangeWritesAuditEvent(t *testing.T) {
	f := withFederation(t)
	ctx := context.Background()
	// Each call gets its own second, so the order of the events is fixed.
	tick := func() { *f.clock = f.clock.Add(time.Second) }
	if _, err := f.svc.UpsertEntry(ctx, asAdmin(&trustv1.UpsertEntryRequest{Entry: protoEntry("did:web:moh.example", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_PENDING)})); err != nil {
		t.Fatal(err)
	}
	tick()
	if _, err := f.svc.UpsertEntry(ctx, asAdmin(&trustv1.UpsertEntryRequest{Entry: protoEntry("did:web:moh.example", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE)})); err != nil {
		t.Fatal(err)
	}
	tick()
	if _, err := f.svc.UpsertEntry(ctx, asAdmin(&trustv1.UpsertEntryRequest{Entry: &trustv1.TrustEntry{}})); err == nil {
		t.Fatal("an empty entry passed")
	}
	tick()
	if _, err := f.svc.ListEntries(ctx, asAdmin(&trustv1.ListEntriesRequest{})); err != nil {
		t.Fatal(err)
	}
	tick()
	if _, err := f.svc.DeleteEntry(ctx, asAdmin(&trustv1.DeleteEntryRequest{Identifier: didID("did:web:moh.example")})); err != nil {
		t.Fatal(err)
	}
	tick()
	if _, err := f.svc.DeleteEntry(ctx, connect.NewRequest(&trustv1.DeleteEntryRequest{Identifier: didID("did:web:gone.example")})); err == nil {
		t.Fatal("a missing entry was deleted")
	}
	tick()
	srv, _ := external(t)
	added, err := f.svc.AddRegistry(ctx, asAdmin(&trustv1.AddRegistryRequest{Registry: &trustv1.Registry{
		Name: "Kenya trust registry", Method: trustv1.RegistryMethod_REGISTRY_METHOD_ETSI_LOTE_JSON, Url: srv.URL + etsi.PathJWS,
		Anchor:  &trustv1.Registry_Anchor{Anchor: &trustv1.Registry_Anchor_JwksUrl{JwksUrl: srv.URL + "/jwks.json"}},
		Refresh: durationpb.New(time.Hour),
	}}))
	if err != nil {
		t.Fatal(err)
	}
	tick()
	id := added.Msg.GetRegistry().GetId()
	if _, err := f.svc.SyncRegistry(ctx, asAdmin(&trustv1.SyncRegistryRequest{Id: id})); err != nil {
		t.Fatal(err)
	}
	tick()
	if _, err := f.svc.RemoveRegistry(ctx, asAdmin(&trustv1.RemoveRegistryRequest{Id: id})); err != nil {
		t.Fatal(err)
	}
	tick()
	if _, err := f.svc.ImportEtsi(ctx, asAdmin(&trustv1.ImportEtsiRequest{Xml: []byte("<not-a-list/>")})); err == nil {
		t.Fatal("a broken list passed")
	}
	tick()
	want := []string{
		"trust.UpsertEntry|kc|root|did:web:moh.example|success|" + msg.T("audit.trust.entry", "pending"),
		"trust.UpsertEntry|kc|root|did:web:moh.example|success|" + msg.T("audit.trust.entry", "active"),
		"trust.UpsertEntry|kc|root||failure|" + msg.T("audit.reason.code", "invalid_argument"),
		"trust.DeleteEntry|kc|root|did:web:moh.example|success|",
		"trust.DeleteEntry||did:web:gone.example|failure|" + msg.T("audit.reason.code", "not_found"),
		"trust.AddRegistry|kc|root|" + id + "|success|Kenya trust registry",
		"trust.SyncRegistry|kc|root|" + id + "|success|",
		"trust.RemoveRegistry|kc|root|" + id + "|success|",
		"trust.ImportEtsi|kc|root||failure|" + msg.T("audit.reason.code", "invalid_argument"),
	}
	if got := events(t, f.svc); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
