// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

func TestListConnectionsIsUnimplemented(t *testing.T) {
	var s *Service
	_, err := s.ListConnections(context.Background(), connect.NewRequest(&backendv1.ListConnectionsRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("code = %v", connect.CodeOf(err))
	}
}
