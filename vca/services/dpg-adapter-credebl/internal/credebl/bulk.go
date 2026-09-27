// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The bulk issuance calls of the api gateway (P6-C4, ADR-060): upload a
// CSV file, preview its rows, issue them, list the issued files and
// their rows, and retry the failed rows. The platform mails each holder
// an out of band offer, so the first column of a file holds the address
// of the holder. The sources are the issuance controller and service of
// the platform, read on 2026-09-27:
// https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/issuance/issuance.controller.ts
// https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/issuance/dtos/issuance.dto.ts
// https://raw.githubusercontent.com/credebl/platform/main/apps/issuance/src/issuance.service.ts
// https://raw.githubusercontent.com/credebl/platform/main/apps/issuance/src/issuance.repository.ts

// EmailColumn is the first column of a bulk file: the address of the
// holder (TemplateIdentifier.EMAIL_COLUMN of libs/enum/src/enum.ts).
const EmailColumn = "email_identifier"

// The schema types of a bulk file (SchemaType of libs/enum/src/enum.ts).
const (
	// BulkSchemaIndy names an AnonCreds credential definition.
	BulkSchemaIndy = "indy"
	// BulkSchemaW3C names a W3C JSON-LD schema by its address.
	BulkSchemaW3C = "w3c"
)

// The states of an issued file (FileUploadStatus of
// apps/api-gateway/src/enum.ts).
const (
	FileStarted     = "PROCESS_STARTED"
	FileCompleted   = "PROCESS_COMPLETED"
	FileInterrupted = "PROCESS_INTERRUPTED"
	FileRetried     = "PROCESS_REINITIATED"
	FilePartial     = "PARTIALLY_COMPLETED"
)

// bulkPath returns the path of one bulk call of the organisation.
func (c *Client) bulkPath(tail string, q url.Values) string {
	p := "/v1/orgs/" + url.PathEscape(c.orgID) + tail
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	return p
}

// UploadBulkFile hands a filled CSV file to the platform. The platform
// checks the columns against the schema and every address, and keeps
// the rows for a limited time. It returns the id of the upload.
func (c *Client) UploadBulkFile(ctx context.Context, schemaType, templateID, fileName string, content []byte) (string, error) {
	if c == nil {
		return "", ErrNoPlatform
	}
	if strings.TrimSpace(templateID) == "" || len(content) == 0 {
		return "", errors.New("credebl: a bulk upload needs the template and the file")
	}
	body, contentType, err := csvForm(fileName, content)
	if err != nil {
		return "", err
	}
	q := url.Values{"templateId": {templateID}, "schemaType": {schemaType}}
	var out envelope[string]
	req := dpgclient.Request{Method: http.MethodPost, Path: c.bulkPath("/bulk/upload", q), Body: body, ContentType: contentType, Accept: "application/json"}
	if err := c.send(ctx, req, &out); err != nil {
		return "", err
	}
	if out.Data == "" {
		return "", errors.New("credebl: the upload answer has no request id")
	}
	return out.Data, nil
}

// csvForm returns the multipart body of an upload: the file in the
// field file, and its name in the field fileName.
func csvForm(fileName string, content []byte) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("fileName", fileName); err != nil {
		return nil, "", fmt.Errorf("credebl: build the upload: %w", err)
	}
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename=%q`, fileName))
	h.Set("Content-Type", "text/csv")
	part, err := w.CreatePart(h)
	if err != nil {
		return nil, "", fmt.Errorf("credebl: build the upload: %w", err)
	}
	if _, err := part.Write(content); err != nil {
		return nil, "", fmt.Errorf("credebl: build the upload: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("credebl: build the upload: %w", err)
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

// BulkPage is the paging state of a bulk answer.
type BulkPage struct {
	// TotalItems is the number of items in all pages.
	TotalItems int `json:"totalItems"`
}

// BulkRow is one row of an upload: the column names and their values.
type BulkRow map[string]any

// previewPage is the answer of the preview. The gateway wraps the page
// of the issuance service in the member response.
type previewPage struct {
	BulkPage
	Data     []BulkRow `json:"data"`
	Response *struct {
		BulkPage
		Data []BulkRow `json:"data"`
	} `json:"response"`
}

// PreviewBulkFile reads one page of the rows of an upload. Page numbers
// start at one.
func (c *Client) PreviewBulkFile(ctx context.Context, requestID string, page, size int) ([]BulkRow, int, error) {
	if c == nil {
		return nil, 0, ErrNoPlatform
	}
	q := url.Values{"pageNumber": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}}
	var out envelope[previewPage]
	if err := c.call(ctx, http.MethodGet, c.bulkPath("/"+url.PathEscape(requestID)+"/preview", q), nil, &out); err != nil {
		return nil, 0, err
	}
	if r := out.Data.Response; r != nil {
		return r.Data, r.TotalItems, nil
	}
	return out.Data.Data, out.Data.TotalItems, nil
}

// IssueBulkFile starts the issue of every row of an upload. The
// platform queues one out of band offer by email per row and answers at
// once with a sentence.
func (c *Client) IssueBulkFile(ctx context.Context, requestID, credDefID string) (string, error) {
	if c == nil {
		return "", ErrNoPlatform
	}
	q := url.Values{}
	if credDefID != "" {
		q.Set("credDefId", credDefID)
	}
	var out envelope[string]
	if err := c.call(ctx, http.MethodPost, c.bulkPath("/"+url.PathEscape(requestID)+"/bulk", q), map[string]any{}, &out); err != nil {
		return "", err
	}
	return out.Data, nil
}

// BulkFile is one file the platform issued from.
type BulkFile struct {
	// ID is the id of the file.
	ID string `json:"id"`
	// Name is the name of the file.
	Name string `json:"name"`
	// Status is one of the File states.
	Status string `json:"status"`
	// CreatedAt is when the issue began.
	CreatedAt time.Time `json:"createDateTime"`
	// UpdatedAt is the last change of the issue.
	UpdatedAt time.Time `json:"lastChangedDateTime"`
	// FailedRecords counts the rows that failed or wait.
	FailedRecords int64 `json:"failedRecords"`
	// TotalRecords counts the rows.
	TotalRecords int64 `json:"totalRecords"`
	// Schema names the schema of the rows, when the platform finds it.
	Schema *struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"schema"`
}

// filePage is the answer of the file list.
type filePage struct {
	BulkPage
	Data []BulkFile `json:"data"`
}

// BulkFiles reads one page of the issued files of the organisation,
// newest first. The platform answers the status not found for none.
func (c *Client) BulkFiles(ctx context.Context, page, size int) ([]BulkFile, int, error) {
	if c == nil {
		return nil, 0, ErrNoPlatform
	}
	q := url.Values{"pageNumber": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}, "sortBy": {"desc"}}
	var out envelope[filePage]
	if err := c.call(ctx, http.MethodGet, c.bulkPath("/bulk/files", q), nil, &out); err != nil {
		if dpgclient.IsStatus(err, http.StatusNotFound) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	return out.Data.Data, out.Data.TotalItems, nil
}

// BulkFileRow is one row of an issued file.
type BulkFileRow struct {
	// ID is the id of the row.
	ID string `json:"id"`
	// ReferenceID is the address of the holder, once the platform
	// handled the row.
	ReferenceID string `json:"referenceId"`
	// IsError is true when the offer failed.
	IsError bool `json:"isError"`
	// Error is the reason of the failure, as JSON text.
	Error string `json:"error"`
	// Status is true when the offer went out.
	Status bool `json:"status"`
	// CredentialData holds the row until the offer goes out.
	CredentialData map[string]any `json:"credential_data"`
}

// Email returns the address of the holder of the row.
func (r BulkFileRow) Email() string {
	if r.ReferenceID != "" {
		return r.ReferenceID
	}
	if v, ok := r.CredentialData[EmailColumn].(string); ok {
		return v
	}
	return ""
}

// Reason returns the reason of a failed row as plain text. The platform
// keeps the error as JSON text.
func (r BulkFileRow) Reason() string {
	text := strings.TrimSpace(r.Error)
	var plain string
	if json.Unmarshal([]byte(text), &plain) == nil {
		return plain
	}
	var obj struct {
		Message string `json:"message"`
	}
	if json.Unmarshal([]byte(text), &obj) == nil && obj.Message != "" {
		return obj.Message
	}
	return text
}

// rowPage is the answer of the rows of a file.
type rowPage struct {
	BulkPage
	Data []BulkFileRow `json:"data"`
}

// BulkFileRows reads one page of the rows of one issued file.
func (c *Client) BulkFileRows(ctx context.Context, fileID string, page, size int) ([]BulkFileRow, int, error) {
	if c == nil {
		return nil, 0, ErrNoPlatform
	}
	q := url.Values{"pageNumber": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}, "sortBy": {"asc"}}
	var out envelope[rowPage]
	if err := c.call(ctx, http.MethodGet, c.bulkPath("/"+url.PathEscape(fileID)+"/bulk/file-data", q), nil, &out); err != nil {
		return nil, 0, err
	}
	return out.Data.Data, out.Data.TotalItems, nil
}

// RetryBulkFile issues the failed rows of one file again.
func (c *Client) RetryBulkFile(ctx context.Context, fileID string) (string, error) {
	if c == nil {
		return "", ErrNoPlatform
	}
	var out envelope[string]
	if err := c.call(ctx, http.MethodPost, c.bulkPath("/"+url.PathEscape(fileID)+"/retry/bulk", nil), map[string]any{}, &out); err != nil {
		return "", err
	}
	return out.Data, nil
}
