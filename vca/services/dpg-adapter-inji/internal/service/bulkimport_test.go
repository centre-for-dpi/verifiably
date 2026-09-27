// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// TestBulkImportIsUnimplemented: the stack keeps no CSV import, so every
// RPC of the bulk import service answers Unimplemented (ADR-060).
func TestBulkImportIsUnimplemented(t *testing.T) {
	var s *Service
	ctx := context.Background()
	calls := map[string]func() error{
		"GetBulkTemplate": func() error {
			_, err := s.GetBulkTemplate(ctx, connect.NewRequest(&backendv1.GetBulkTemplateRequest{}))
			return err
		},
		"UploadBulkFile": func() error {
			_, err := s.UploadBulkFile(ctx, connect.NewRequest(&backendv1.UploadBulkFileRequest{}))
			return err
		},
		"PreviewBulkFile": func() error {
			_, err := s.PreviewBulkFile(ctx, connect.NewRequest(&backendv1.PreviewBulkFileRequest{}))
			return err
		},
		"IssueBulkFile": func() error {
			_, err := s.IssueBulkFile(ctx, connect.NewRequest(&backendv1.IssueBulkFileRequest{}))
			return err
		},
		"ListBulkFiles": func() error {
			_, err := s.ListBulkFiles(ctx, connect.NewRequest(&backendv1.ListBulkFilesRequest{}))
			return err
		},
		"ListBulkFileRows": func() error {
			_, err := s.ListBulkFileRows(ctx, connect.NewRequest(&backendv1.ListBulkFileRowsRequest{}))
			return err
		},
		"RetryBulkFile": func() error {
			_, err := s.RetryBulkFile(ctx, connect.NewRequest(&backendv1.RetryBulkFileRequest{}))
			return err
		},
	}
	for name, call := range calls {
		if code := connect.CodeOf(call()); code != connect.CodeUnimplemented {
			t.Errorf("%s code = %v", name, code)
		}
	}
}
