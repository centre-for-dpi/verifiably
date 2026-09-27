// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// TestDidcommWalletRpcsAreUnimplemented: the wallet of this DPG speaks
// no DIDComm, so it answers each DIDComm wallet RPC of ADR-062 with
// Unimplemented.
func TestDidcommWalletRpcsAreUnimplemented(t *testing.T) {
	var s *Service
	ctx := context.Background()
	_, e1 := s.OpenInvitation(ctx, connect.NewRequest(&backendv1.OpenInvitationRequest{}))
	_, e2 := s.ListWalletConnections(ctx, connect.NewRequest(&backendv1.ListWalletConnectionsRequest{}))
	_, e3 := s.ListInbox(ctx, connect.NewRequest(&backendv1.ListInboxRequest{}))
	for i, err := range []error{e1, e2, e3} {
		if connect.CodeOf(err) != connect.CodeUnimplemented {
			t.Errorf("rpc %d: code = %v", i, connect.CodeOf(err))
		}
	}
}
