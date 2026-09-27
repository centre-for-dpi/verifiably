// SPDX-License-Identifier: Apache-2.0

package service

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The CSV bulk import of the platform (P6-C4, ADR-060). The platform
// reads a file whose first column is the address of the holder and the
// others the claims of a schema. It mails each row an out of band
// offer, so the import runs only with a mail provider. It issues the
// AnonCreds credentials of a credential definition and the W3C JSON-LD
// credentials of a schema of its schema file server.

// defaultBulkFile names a file that comes without a name.
const defaultBulkFile = "credentials.csv"

// errNoBulkImport says why a stack without mail has no bulk import.
var errNoBulkImport = errors.New(
	"the CREDEBL stack names no mail provider, and its bulk import mails each offer; set one in the stack .env")

// bulkImport returns the bulk import of the capability answer, or nil
// without a mail provider.
func (s *Service) bulkImport() *backendv1.BulkImport {
	if !s.mailOffers {
		return nil
	}
	return &backendv1.BulkImport{
		Channel:     backendv1.Channel_CHANNEL_EMAIL,
		Formats:     append([]commonv1.Format(nil), didcommFormats...),
		EmailColumn: credebl.EmailColumn,
	}
}

// features returns the features of the capability answer.
func (s *Service) features() []backendv1.Feature {
	out := []backendv1.Feature{
		backendv1.Feature_FEATURE_CREDENTIAL_CONFIG_API,
		backendv1.Feature_FEATURE_MULTI_TENANCY,
		backendv1.Feature_FEATURE_ISSUER_IDENTITY_PROVISION,
		// The issuance sessions of the agent give the state of an offer
		// and the issued credentials (P6-C5).
		backendv1.Feature_FEATURE_ISSUANCE_STATUS,
		backendv1.Feature_FEATURE_ISSUED_LEDGER,
		// The verifier asks for AnonCreds proofs with predicates over
		// DIDComm (P6-C6).
		backendv1.Feature_FEATURE_ANONCREDS_PROOF,
	}
	if s.mailOffers {
		out = append(out, backendv1.Feature_FEATURE_BULK_NATIVE)
	}
	return out
}

// bulkTarget is what the platform names a bulk file by.
type bulkTarget struct {
	schemaType string
	templateID string
	credDefID  string
}

// targetOf reads the configuration of a bulk call. It checks that the
// stack has a bulk import and that the format goes through it.
func (s *Service) targetOf(configuration string, format commonv1.Format) (bulkTarget, error) {
	if !s.mailOffers {
		return bulkTarget{}, connect.NewError(connect.CodeFailedPrecondition, errNoBulkImport)
	}
	configuration = strings.TrimSpace(configuration)
	if configuration == "" {
		return bulkTarget{}, connect.NewError(connect.CodeInvalidArgument, errors.New("a bulk file needs the configuration id"))
	}
	switch format {
	case commonv1.Format_FORMAT_ANONCREDS:
		return bulkTarget{schemaType: credebl.BulkSchemaIndy, templateID: configuration, credDefID: configuration}, nil
	case commonv1.Format_FORMAT_LDP_VC:
		return bulkTarget{schemaType: credebl.BulkSchemaW3C, templateID: configuration}, nil
	}
	return bulkTarget{}, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
		"the bulk import of CREDEBL issues AnonCreds and W3C JSON-LD, not the format %s", format))
}

// needImport checks that the stack has a bulk import.
func (s *Service) needImport() error {
	if !s.mailOffers {
		return connect.NewError(connect.CodeFailedPrecondition, errNoBulkImport)
	}
	return nil
}

// refused returns the error of a bulk call. A refusal of the platform
// carries its sentence, which the page shows to the operator.
func refused(action string, err error) *connect.Error {
	var se *dpgclient.StatusError
	if errors.As(err, &se) && se.Status >= 400 && se.Status < 500 {
		if reason := platformReason(se.Body); reason != "" {
			return connect.NewError(failed(action, err).Code(), fmt.Errorf("%s: the platform refused: %s", action, reason))
		}
	}
	return failed(action, err)
}

// platformReason reads the sentence of an error answer of the platform.
// The message is a sentence, or a list of them for a file with bad rows.
func platformReason(body string) string {
	var answer struct {
		Message json.RawMessage `json:"message"`
	}
	if json.Unmarshal([]byte(body), &answer) != nil {
		return ""
	}
	var text string
	if json.Unmarshal(answer.Message, &text) == nil {
		return text
	}
	var list []string
	if json.Unmarshal(answer.Message, &list) == nil {
		return strings.Join(list, "; ")
	}
	return ""
}

// GetBulkTemplate returns the header of a bulk file: the address column
// of the platform, then the claims of the schema. The platform checks
// both the names and the count of the columns.
func (s *Service) GetBulkTemplate(
	_ context.Context, req *connect.Request[backendv1.GetBulkTemplateRequest],
) (*connect.Response[backendv1.GetBulkTemplateResponse], error) {
	if _, err := s.targetOf(req.Msg.GetConfigurationId(), req.Msg.GetFormat()); err != nil {
		return nil, err
	}
	columns := []string{credebl.EmailColumn}
	seen := map[string]bool{credebl.EmailColumn: true}
	for _, claim := range req.Msg.GetClaims() {
		claim = strings.TrimSpace(claim)
		if claim == credebl.EmailColumn {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf(
				"the claim %s has the name of the address column of CREDEBL; rename it in the schema", claim))
		}
		if claim == "" || seen[claim] {
			continue
		}
		seen[claim] = true
		columns = append(columns, claim)
	}
	if len(columns) == 1 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a template needs the claims of the schema"))
	}
	content, err := csvOf([][]string{columns})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.GetBulkTemplateResponse{FileName: defaultBulkFile, Content: content, Columns: columns}), nil
}

// csvOf writes rows as a CSV file.
func csvOf(rows [][]string) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.WriteAll(rows); err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("write the CSV file: %w", err))
	}
	return buf.Bytes(), nil
}

// UploadBulkFile hands a filled file to the platform, which checks the
// columns and every address and keeps the rows for the preview.
func (s *Service) UploadBulkFile(
	ctx context.Context, req *connect.Request[backendv1.UploadBulkFileRequest],
) (*connect.Response[backendv1.UploadBulkFileResponse], error) {
	target, err := s.targetOf(req.Msg.GetConfigurationId(), req.Msg.GetFormat())
	if err != nil {
		return nil, err
	}
	if len(req.Msg.GetContent()) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the upload has no file"))
	}
	id, err := s.upload(ctx, target, req.Msg.GetFileName(), req.Msg.GetContent())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.UploadBulkFileResponse{UploadId: id}), nil
}

// upload hands one file to the platform.
func (s *Service) upload(ctx context.Context, target bulkTarget, name string, content []byte) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = defaultBulkFile
	}
	id, err := s.client.UploadBulkFile(ctx, target.schemaType, target.templateID, name, content)
	if err != nil {
		return "", refused("upload the bulk file", err)
	}
	return id, nil
}

// pageOf reads the page of a list request: the page number from one and
// the size within the cap.
func (s *Service) pageOf(p *commonv1.Pagination) (int, int, error) {
	size := int(p.GetPageSize())
	if size <= 0 || size > s.pageSizeMax {
		size = s.pageSizeMax
	}
	page := 1
	if token := p.GetPageToken(); token != "" {
		n, err := parseToken(token)
		if err != nil || n < 1 {
			return 0, 0, connect.NewError(connect.CodeInvalidArgument, errors.New("service: bad page token"))
		}
		page = n
	}
	return page, size, nil
}

// pageResult returns the paging state of one page.
func pageResult(page, size, total int) *commonv1.PageResult {
	out := &commonv1.PageResult{TotalSize: int64(total)}
	if page*size < total {
		out.NextPageToken = fmt.Sprintf("%d", page+1)
	}
	return out
}

// PreviewBulkFile reads one page of the rows of an upload.
func (s *Service) PreviewBulkFile(
	ctx context.Context, req *connect.Request[backendv1.PreviewBulkFileRequest],
) (*connect.Response[backendv1.PreviewBulkFileResponse], error) {
	if err := s.needImport(); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetUploadId())
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a preview needs the upload id"))
	}
	page, size, err := s.pageOf(req.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	rows, total, err := s.client.PreviewBulkFile(ctx, id, page, size)
	if err != nil {
		return nil, refused("read the rows of the upload", err)
	}
	out := &backendv1.PreviewBulkFileResponse{Page: pageResult(page, size, total)}
	for _, row := range rows {
		item := &backendv1.BulkPreviewRow{Claims: map[string]string{}}
		for name, value := range row {
			if name == credebl.EmailColumn {
				item.Email = anonCredsText(value)
				continue
			}
			item.Claims[name] = anonCredsText(value)
		}
		out.Rows = append(out.Rows, item)
	}
	return connect.NewResponse(out), nil
}

// IssueBulkFile starts the issue of every row of an upload.
func (s *Service) IssueBulkFile(
	ctx context.Context, req *connect.Request[backendv1.IssueBulkFileRequest],
) (*connect.Response[backendv1.IssueBulkFileResponse], error) {
	target, err := s.targetOf(req.Msg.GetConfigurationId(), req.Msg.GetFormat())
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetUploadId())
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("an issue needs the upload id"))
	}
	text, err := s.client.IssueBulkFile(ctx, id, target.credDefID)
	if err != nil {
		return nil, refused("issue the bulk file", err)
	}
	return connect.NewResponse(&backendv1.IssueBulkFileResponse{Message: text}), nil
}

// fileStates maps the states of an issued file onto the contract.
var fileStates = map[string]backendv1.BulkFile_State{
	credebl.FileStarted:     backendv1.BulkFile_STATE_STARTED,
	credebl.FileCompleted:   backendv1.BulkFile_STATE_COMPLETED,
	credebl.FilePartial:     backendv1.BulkFile_STATE_PARTIAL,
	credebl.FileInterrupted: backendv1.BulkFile_STATE_INTERRUPTED,
	credebl.FileRetried:     backendv1.BulkFile_STATE_RETRIED,
}

// ListBulkFiles reads one page of the issued files, newest first.
func (s *Service) ListBulkFiles(
	ctx context.Context, req *connect.Request[backendv1.ListBulkFilesRequest],
) (*connect.Response[backendv1.ListBulkFilesResponse], error) {
	if err := s.needImport(); err != nil {
		return nil, err
	}
	page, size, err := s.pageOf(req.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	files, total, err := s.client.BulkFiles(ctx, page, size)
	if err != nil {
		return nil, refused("list the bulk files", err)
	}
	out := &backendv1.ListBulkFilesResponse{Page: pageResult(page, size, total)}
	for _, f := range files {
		file := &backendv1.BulkFile{
			Id: f.ID, Name: f.Name, State: fileStates[f.Status],
			TotalRows: f.TotalRecords, FailedRows: f.FailedRecords,
			CreatedAt: timestamp(f.CreatedAt), UpdatedAt: timestamp(f.UpdatedAt),
		}
		if f.Schema != nil {
			file.SchemaName = f.Schema.Name
		}
		out.Files = append(out.Files, file)
	}
	return connect.NewResponse(out), nil
}

// ListBulkFileRows reads one page of the rows of one issued file.
func (s *Service) ListBulkFileRows(
	ctx context.Context, req *connect.Request[backendv1.ListBulkFileRowsRequest],
) (*connect.Response[backendv1.ListBulkFileRowsResponse], error) {
	if err := s.needImport(); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetFileId())
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the rows need the file id"))
	}
	page, size, err := s.pageOf(req.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	rows, total, err := s.client.BulkFileRows(ctx, id, page, size)
	if err != nil {
		return nil, refused("read the rows of the bulk file", err)
	}
	out := &backendv1.ListBulkFileRowsResponse{Page: pageResult(page, size, total)}
	for _, r := range rows {
		row := &backendv1.BulkFileRow{Id: r.ID, Email: r.Email(), Issued: r.Status && !r.IsError}
		if r.IsError {
			row.Error = r.Reason()
		}
		out.Rows = append(out.Rows, row)
	}
	return connect.NewResponse(out), nil
}

// RetryBulkFile issues the failed rows of one file again.
func (s *Service) RetryBulkFile(
	ctx context.Context, req *connect.Request[backendv1.RetryBulkFileRequest],
) (*connect.Response[backendv1.RetryBulkFileResponse], error) {
	if err := s.needImport(); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetFileId())
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a retry needs the file id"))
	}
	text, err := s.client.RetryBulkFile(ctx, id)
	if err != nil {
		return nil, refused("retry the bulk file", err)
	}
	return connect.NewResponse(&backendv1.RetryBulkFileResponse{Message: text}), nil
}

// IssueBatch issues many credentials through the bulk import: the specs
// become the rows of one file, which the platform checks and issues. The
// platform mails each holder an offer, so no credential comes back and
// each good row is delivered. A row without a good address, with claims
// that are no JSON object, or with a validity window fails alone.
func (s *Service) IssueBatch(
	ctx context.Context, req *connect.Request[backendv1.IssueBatchRequest],
) (*connect.Response[backendv1.IssueBatchResponse], error) {
	specs, emails := req.Msg.GetSpecs(), req.Msg.GetEmails()
	if len(specs) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the batch has no spec"))
	}
	if len(emails) != len(specs) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(
			"the bulk import of CREDEBL mails each offer, so the batch needs one address per spec"))
	}
	first := specs[0]
	for _, spec := range specs[1:] {
		if spec.GetConfigurationId() != first.GetConfigurationId() || spec.GetFormat() != first.GetFormat() {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(
				"a bulk file holds one credential configuration; split the batch"))
		}
	}
	target, err := s.targetOf(first.GetConfigurationId(), first.GetFormat())
	if err != nil {
		return nil, err
	}
	out := &backendv1.IssueBatchResponse{Items: make([]*backendv1.IssueBatchResponse_Item, len(specs))}
	var good []int
	var claims []map[string]any
	names := map[string]bool{}
	for i, spec := range specs {
		out.Items[i] = &backendv1.IssueBatchResponse_Item{Position: int32(i)} //nolint:gosec // i counts the specs of one request
		row, rerr := batchRow(spec, emails[i])
		if rerr != nil {
			out.Items[i].Error = &commonv1.Error{Code: "VCA-CREDEBL-BULK-ROW", Message: rerr.Error()}
			continue
		}
		for name := range row {
			names[name] = true
		}
		good = append(good, i)
		claims = append(claims, row)
	}
	if len(good) == 0 {
		return connect.NewResponse(out), nil
	}
	columns := make([]string, 0, len(names))
	for name := range names {
		columns = append(columns, name)
	}
	sort.Strings(columns)
	rows := [][]string{append([]string{credebl.EmailColumn}, columns...)}
	for k, i := range good {
		line := []string{strings.TrimSpace(emails[i])}
		for _, name := range columns {
			value, ok := claims[k][name]
			if !ok {
				line = append(line, "")
				continue
			}
			line = append(line, anonCredsText(value))
		}
		rows = append(rows, line)
	}
	content, err := csvOf(rows)
	if err != nil {
		return nil, err
	}
	id, err := s.upload(ctx, target, "", content)
	if err != nil {
		return nil, err
	}
	if _, err := s.client.IssueBulkFile(ctx, id, target.credDefID); err != nil {
		return nil, refused("issue the bulk file", err)
	}
	for _, i := range good {
		out.Items[i].Delivered = true
	}
	return connect.NewResponse(out), nil
}

// batchRow reads the claims of one spec of a batch and checks its
// address.
func batchRow(spec *backendv1.IssueSpec, email string) (map[string]any, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(email))
	if err != nil || addr.Name != "" {
		return nil, errors.New("the row has no valid email address for the offer")
	}
	if hasWindow(spec.GetValidity()) {
		return nil, errors.New("the bulk import of CREDEBL sets no validity window; issue the row without one")
	}
	claims := map[string]any{}
	dec := json.NewDecoder(strings.NewReader(strings.TrimSpace(spec.GetSubjectData())))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil || len(claims) == 0 {
		return nil, errors.New("subject_data must be a JSON object with the claims of the credential")
	}
	if _, clash := claims[credebl.EmailColumn]; clash {
		return nil, fmt.Errorf("the claim %s has the name of the address column of CREDEBL", credebl.EmailColumn)
	}
	return claims, nil
}
