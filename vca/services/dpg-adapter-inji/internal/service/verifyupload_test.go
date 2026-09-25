// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/service"
)

// TestVerifyCredentialIsUnimplemented keeps the stack check of an upload
// off until the adapter lists FEATURE_VERIFY_UPLOAD.
func TestVerifyCredentialIsUnimplemented(t *testing.T) {
	_, err := new(service.Service).VerifyCredential(context.Background(),
		connect.NewRequest(&backendv1.VerifyCredentialRequest{Payload: []byte("x")}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("want unimplemented, got %v", err)
	}
}
