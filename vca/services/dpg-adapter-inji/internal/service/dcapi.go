// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// SubmitBrowserAnswer answers Unimplemented. The adapter does not list
// FEATURE_DC_API_VERIFY, so no request page offers the Digital
// Credentials API delivery for this stack.
func (s *Service) SubmitBrowserAnswer(
	context.Context, *connect.Request[backendv1.SubmitBrowserAnswerRequest],
) (*connect.Response[backendv1.SubmitBrowserAnswerResponse], error) {
	return nil, unimplemented("this adapter does not take a Digital Credentials API answer")
}
