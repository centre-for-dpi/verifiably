// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// VerifyCredential answers Unimplemented. The adapter does not list
// FEATURE_VERIFY_UPLOAD, so no page offers the stack check of an upload.
func (s *Service) VerifyCredential(
	context.Context, *connect.Request[backendv1.VerifyCredentialRequest],
) (*connect.Response[backendv1.VerifyCredentialResponse], error) {
	return nil, unimplemented("this adapter does not check an uploaded credential through the DPG")
}
