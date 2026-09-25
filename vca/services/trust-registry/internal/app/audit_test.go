// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	auditv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1/auditv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
)

// TestAuditServiceNeedsAdmin serves the audit store of the registry to
// the admin service token only, and keeps it in the audit directory.
func TestAuditServiceNeedsAdmin(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	cfg := load(t, map[string]string{
		"VCA_TRUST_RESOLVE_DIDS": "false", "VCA_TRUST_ADMIN_TOKEN": "admin-token", "VCA_TRUST_AUDIT_DIR": dir,
	})
	app, err := Build(cfg, quiet())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.Mux)
	defer srv.Close()
	ctx := context.Background()
	req := connect.NewRequest(&trustv1.UpsertEntryRequest{Entry: &trustv1.TrustEntry{
		Identifier:  &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: "did:web:moh.example"}},
		DisplayName: "Ministry of Health", Role: commonv1.Role_ROLE_ISSUER, Status: trustv1.Status_STATUS_ACTIVE,
	}})
	req.Header().Set(auditlog.ActorHeader, "kc|root")
	if _, uerr := trustv1connect.NewTrustServiceClient(srv.Client(), srv.URL).UpsertEntry(ctx, req); uerr != nil {
		t.Fatal(err)
	}
	query := func(token string) (*connect.Response[auditv1.QueryResponse], error) {
		r := connect.NewRequest(&auditv1.QueryRequest{})
		if token != "" {
			r.Header().Set("Authorization", "Bearer "+token)
		}
		return auditv1connect.NewAuditServiceClient(srv.Client(), srv.URL).Query(ctx, r)
	}
	for _, token := range []string{"", "someone"} {
		if _, qerr := query(token); connect.CodeOf(qerr) != connect.CodeUnauthenticated {
			t.Errorf("token %q: %v", token, err)
		}
	}
	res, err := query("admin-token")
	if err != nil {
		t.Fatal(err)
	}
	events := res.Msg.GetEvents()
	if len(events) != 1 || events[0].GetSourceService() != "trust-registry" || events[0].GetActor() != "kc|root" ||
		events[0].GetAction() != "trust.UpsertEntry" || events[0].GetTarget() != "did:web:moh.example" {
		t.Fatalf("events = %+v", events)
	}
	files, err := os.ReadDir(filepath.Join(dir, "audit"))
	if err != nil || len(files) != 1 {
		t.Fatalf("audit dir = %v, %v", files, err)
	}
}
