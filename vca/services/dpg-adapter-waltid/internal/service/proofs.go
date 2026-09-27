// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// didcommProofMessage says why the DIDComm proof RPCs of ADR-061 are
// not available.
const didcommProofMessage = "this DPG speaks no DIDComm, so it sends no DIDComm proof request; use an OID4VP request"

// ListProofRequests is not available. The DPG speaks no DIDComm.
func (s *Service) ListProofRequests(
	context.Context, *connect.Request[backendv1.ListProofRequestsRequest],
) (*connect.Response[backendv1.ListProofRequestsResponse], error) {
	return nil, unimplemented(didcommProofMessage)
}

// ListProofSchemas is not available. The DPG asks for no AnonCreds
// proof.
func (s *Service) ListProofSchemas(
	context.Context, *connect.Request[backendv1.ListProofSchemasRequest],
) (*connect.Response[backendv1.ListProofSchemasResponse], error) {
	return nil, unimplemented(didcommProofMessage)
}

// ListVerifierConnections is not available. The DPG speaks no DIDComm,
// so it keeps no connection.
func (s *Service) ListVerifierConnections(
	context.Context, *connect.Request[backendv1.ListVerifierConnectionsRequest],
) (*connect.Response[backendv1.ListVerifierConnectionsResponse], error) {
	return nil, unimplemented(didcommProofMessage)
}
