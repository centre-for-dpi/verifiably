// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	auditv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1/auditv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/app"
)

// TestAuditServiceNeedsAdmin serves the audit store to the admin
// service token only.
func TestAuditServiceNeedsAdmin(t *testing.T) {
	var buf bytes.Buffer
	a, err := app.Build(settings(t, map[string]string{
		"VCA_ISSUANCE_ADMIN_TOKEN": "admin-token", "VCA_ISSUANCE_AUDIT_DIR": filepath.Join(t.TempDir(), "audit"),
	}), deps(&buf))
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
		_, qerr := client.Query(context.Background(), req)
		return qerr
	}
	if err := query("admin-token"); err != nil {
		t.Fatalf("admin token: %v", err)
	}
	for _, token := range []string{"", "someone"} {
		if err := query(token); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("token %q: %v", token, err)
		}
	}
}

func TestBuildReportsABadAuditDir(t *testing.T) {
	blocking := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocking, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := app.Build(settings(t, map[string]string{"VCA_ISSUANCE_AUDIT_DIR": filepath.Join(blocking, "audit")}), deps(&buf)); err == nil {
		t.Fatal("Build accepted an audit directory inside a file")
	}
}
