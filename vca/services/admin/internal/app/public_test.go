// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"testing"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/internal/rpcguard"
)

// TestAnonymousRPCsAreRefused is ADR-047 decision 1. The reverse proxy
// publishes the AdminService of the admin, so every RPC refuses a
// caller with no credential. Two RPCs are open by design: ListCommands
// returns the help text, and OnboardAdmin binds the first admin with
// the one time bootstrap token.
func TestAnonymousRPCsAreRefused(t *testing.T) {
	a, err := app.Build(baseConfig(), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	problems, err := rpcguard.Check(a.Mux, adminv1connect.AdminServiceName, "ListCommands", "OnboardAdmin")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}
