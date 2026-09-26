// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// ListConnections is not available. Inji Certify speaks OID4VCI, not
// DIDComm, so it keeps no connection.
func (s *Service) ListConnections(
	context.Context, *connect.Request[backendv1.ListConnectionsRequest],
) (*connect.Response[backendv1.ListConnectionsResponse], error) {
	return nil, unimplemented("this DPG speaks no DIDComm, so it keeps no connection")
}
