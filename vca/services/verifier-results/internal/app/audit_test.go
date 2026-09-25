// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	auditv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1/auditv1connect"
)

// TestAuditServiceNeedsAdmin serves the audit store to the admin
// service token only. A staff session of the verifier never opens it.
func TestAuditServiceNeedsAdmin(t *testing.T) {
	cfg := base(t)
	cfg.AdminToken = "admin-token"
	cfg.AuditDir = filepath.Join(t.TempDir(), "audit")
	a, err := Build(cfg, Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	client := auditv1connect.NewAuditServiceClient(srv.Client(), srv.URL)
	query := func(token string) error {
		req := connect.NewRequest(&auditv1.QueryRequest{})
		if token != "" {
			req.Header().Set("Authorization", "Bearer "+token)
		}
		_, err := client.Query(context.Background(), req)
		return err
	}
	if err := query("admin-token"); err != nil {
		t.Fatalf("admin token: %v", err)
	}
	for name, token := range map[string]string{"no token": "", "verifier staff": staff(t).Token(t, "kc|grace", "verifier-admin")} {
		if err := query(token); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s: %v", name, err)
		}
	}
}
