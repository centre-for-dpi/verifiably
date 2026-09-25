// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/service"
)

// TestListIssuedCredentialsIsUnimplemented keeps the ledger sync off on
// this stack: the adapter lists no FEATURE_ISSUED_LEDGER.
func TestListIssuedCredentialsIsUnimplemented(t *testing.T) {
	_, err := new(service.Service).ListIssuedCredentials(context.Background(),
		connect.NewRequest(&backendv1.ListIssuedCredentialsRequest{CredentialType: "x"}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("code = %v", connect.CodeOf(err))
	}
}
