// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// TestDidcommProofRpcsAreUnimplemented: this DPG speaks no DIDComm, so
// it answers each DIDComm proof RPC of ADR-061 with Unimplemented.
func TestDidcommProofRpcsAreUnimplemented(t *testing.T) {
	var s *Service
	ctx := context.Background()
	_, e1 := s.ListProofRequests(ctx, connect.NewRequest(&backendv1.ListProofRequestsRequest{}))
	_, e2 := s.ListProofSchemas(ctx, connect.NewRequest(&backendv1.ListProofSchemasRequest{}))
	_, e3 := s.ListVerifierConnections(ctx, connect.NewRequest(&backendv1.ListVerifierConnectionsRequest{}))
	for i, err := range []error{e1, e2, e3} {
		if connect.CodeOf(err) != connect.CodeUnimplemented {
			t.Errorf("rpc %d: code = %v", i, connect.CodeOf(err))
		}
	}
}
