// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// didcommWalletMessage says why the DIDComm wallet RPCs of ADR-062 are
// not available. The adapter does not list FEATURE_WALLET_DIDCOMM, so no
// holder page offers them for this stack.
const didcommWalletMessage = "the wallet of this DPG speaks no DIDComm; use an OID4VCI offer or an OID4VP request"

// OpenInvitation is not available. The wallet speaks no DIDComm.
func (s *Service) OpenInvitation(
	context.Context, *connect.Request[backendv1.OpenInvitationRequest],
) (*connect.Response[backendv1.OpenInvitationResponse], error) {
	return nil, unimplemented(didcommWalletMessage)
}

// ListWalletConnections is not available. The wallet keeps no DIDComm
// connection.
func (s *Service) ListWalletConnections(
	context.Context, *connect.Request[backendv1.ListWalletConnectionsRequest],
) (*connect.Response[backendv1.ListWalletConnectionsResponse], error) {
	return nil, unimplemented(didcommWalletMessage)
}

// ListInbox is not available. Nothing comes to the wallet over DIDComm.
func (s *Service) ListInbox(
	context.Context, *connect.Request[backendv1.ListInboxRequest],
) (*connect.Response[backendv1.ListInboxResponse], error) {
	return nil, unimplemented(didcommWalletMessage)
}
