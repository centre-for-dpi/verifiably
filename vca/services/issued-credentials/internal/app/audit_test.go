// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	auditv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1/auditv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/app"
)

// TestAuditServiceNeedsAdmin serves the audit store to the admin
// service token only.
func TestAuditServiceNeedsAdmin(t *testing.T) {
	a := build(t, map[string]string{
		"VCA_ISSUED_ADMIN_TOKEN": "admin-token", "VCA_ISSUED_AUDIT_DIR": filepath.Join(t.TempDir(), "audit"),
	}, app.Deps{})
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	client := auditv1connect.NewAuditServiceClient(srv.Client(), srv.URL)
	for token, want := range map[string]connect.Code{"": connect.CodeUnauthenticated, "someone": connect.CodeUnauthenticated, "admin-token": 0} {
		req := connect.NewRequest(&auditv1.QueryRequest{})
		if token != "" {
			req.Header().Set("Authorization", "Bearer "+token)
		}
		if _, err := client.Query(context.Background(), req); connect.CodeOf(err) != want && (want != 0 || err != nil) {
			t.Errorf("token %q: %v", token, err)
		}
	}
}
