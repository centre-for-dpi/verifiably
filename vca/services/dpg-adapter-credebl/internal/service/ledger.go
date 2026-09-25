// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// ListIssuedCredentials answers Unimplemented. The adapter does not list
// FEATURE_ISSUED_LEDGER, so the issued pages offer no sync from the stack.
func (s *Service) ListIssuedCredentials(
	context.Context, *connect.Request[backendv1.ListIssuedCredentialsRequest],
) (*connect.Response[backendv1.ListIssuedCredentialsResponse], error) {
	return nil, unimplemented("this adapter does not read a ledger of issued credentials from the DPG")
}
