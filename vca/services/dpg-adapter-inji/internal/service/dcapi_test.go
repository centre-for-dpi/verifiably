// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/service"
)

// TestSubmitBrowserAnswerIsUnimplemented keeps the Digital Credentials
// API delivery off until the adapter lists FEATURE_DC_API_VERIFY.
func TestSubmitBrowserAnswerIsUnimplemented(t *testing.T) {
	_, err := new(service.Service).SubmitBrowserAnswer(context.Background(),
		connect.NewRequest(&backendv1.SubmitBrowserAnswerRequest{State: "s"}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("want unimplemented, got %v", err)
	}
}
