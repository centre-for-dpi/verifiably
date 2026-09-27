// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
)

// bulkImportMessage says why the bulk import service answers
// Unimplemented. The capability answer names no bulk import that mails
// each row, so the issue wizard offers no stack bulk import for this
// stack (ADR-060).
const bulkImportMessage = "Inji Certify issues each credential through OID4VCI and keeps no CSV import"

// GetBulkTemplate is not available. See bulkImportMessage.
func (s *Service) GetBulkTemplate(
	context.Context, *connect.Request[backendv1.GetBulkTemplateRequest],
) (*connect.Response[backendv1.GetBulkTemplateResponse], error) {
	return nil, unimplemented(bulkImportMessage)
}

// UploadBulkFile is not available. See bulkImportMessage.
func (s *Service) UploadBulkFile(
	context.Context, *connect.Request[backendv1.UploadBulkFileRequest],
) (*connect.Response[backendv1.UploadBulkFileResponse], error) {
	return nil, unimplemented(bulkImportMessage)
}

// PreviewBulkFile is not available. See bulkImportMessage.
func (s *Service) PreviewBulkFile(
	context.Context, *connect.Request[backendv1.PreviewBulkFileRequest],
) (*connect.Response[backendv1.PreviewBulkFileResponse], error) {
	return nil, unimplemented(bulkImportMessage)
}

// IssueBulkFile is not available. See bulkImportMessage.
func (s *Service) IssueBulkFile(
	context.Context, *connect.Request[backendv1.IssueBulkFileRequest],
) (*connect.Response[backendv1.IssueBulkFileResponse], error) {
	return nil, unimplemented(bulkImportMessage)
}

// ListBulkFiles is not available. See bulkImportMessage.
func (s *Service) ListBulkFiles(
	context.Context, *connect.Request[backendv1.ListBulkFilesRequest],
) (*connect.Response[backendv1.ListBulkFilesResponse], error) {
	return nil, unimplemented(bulkImportMessage)
}

// ListBulkFileRows is not available. See bulkImportMessage.
func (s *Service) ListBulkFileRows(
	context.Context, *connect.Request[backendv1.ListBulkFileRowsRequest],
) (*connect.Response[backendv1.ListBulkFileRowsResponse], error) {
	return nil, unimplemented(bulkImportMessage)
}

// RetryBulkFile is not available. See bulkImportMessage.
func (s *Service) RetryBulkFile(
	context.Context, *connect.Request[backendv1.RetryBulkFileRequest],
) (*connect.Response[backendv1.RetryBulkFileResponse], error) {
	return nil, unimplemented(bulkImportMessage)
}
