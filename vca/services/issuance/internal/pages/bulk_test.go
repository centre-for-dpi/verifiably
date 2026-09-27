// SPDX-License-Identifier: Apache-2.0

package pages_test

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// P6-C4 and ADR-060: the bulk import of a stack that mails each holder
// an offer: the template, the upload, the preview, the issue, the
// history, and the retry.

// credDef is the credential definition of the AnonCreds farmer schema.
const credDef = "Ra8F7Qx1:3:CL:Ra8F7Qx1:2:Farmer:1.0:default" //nolint:gosec // G101: a credential definition id, not a credential.

// fakeBulk answers the bulk import of the adapter and records each
// request.
type fakeBulk struct {
	mu        sync.Mutex
	templates []*backendv1.GetBulkTemplateRequest
	uploads   []*backendv1.UploadBulkFileRequest
	previews  []*backendv1.PreviewBulkFileRequest
	issues    []*backendv1.IssueBulkFileRequest
	retries   []string
	uploadErr error
	issueErr  error
	filesErr  error
	retryErr  error
	files     []*backendv1.BulkFile
}

func (f *fakeBulk) GetBulkTemplate(_ context.Context, req *connect.Request[backendv1.GetBulkTemplateRequest]) (*connect.Response[backendv1.GetBulkTemplateResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.templates = append(f.templates, req.Msg)
	cols := append([]string{"email_identifier"}, req.Msg.GetClaims()...)
	return connect.NewResponse(&backendv1.GetBulkTemplateResponse{FileName: "credentials.csv", Content: []byte(strings.Join(cols, ",") + "\n"), Columns: cols}), nil
}

func (f *fakeBulk) UploadBulkFile(_ context.Context, req *connect.Request[backendv1.UploadBulkFileRequest]) (*connect.Response[backendv1.UploadBulkFileResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploads = append(f.uploads, req.Msg)
	if f.uploadErr != nil {
		return nil, f.uploadErr
	}
	return connect.NewResponse(&backendv1.UploadBulkFileResponse{UploadId: "upload-1"}), nil
}

func (f *fakeBulk) PreviewBulkFile(_ context.Context, req *connect.Request[backendv1.PreviewBulkFileRequest]) (*connect.Response[backendv1.PreviewBulkFileResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.previews = append(f.previews, req.Msg)
	if req.Msg.GetUploadId() == "gone" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(
			"read the rows of the upload: the platform refused: Timeout for reviewing data, re-upload your file and generate new request."))
	}
	return connect.NewResponse(&backendv1.PreviewBulkFileResponse{
		Rows: []*backendv1.BulkPreviewRow{
			{Email: "wanjiku@registry.gov.test", Claims: map[string]string{"fullName": "Wanjiku Njeri", "farmerID": "FM-0042"}},
			{Email: "otieno@registry.gov.test", Claims: map[string]string{"fullName": "Otieno Ouma", "farmerID": "FM-0043"}},
		},
		Page: &commonv1.PageResult{TotalSize: 45, NextPageToken: "3"},
	}), nil
}

func (f *fakeBulk) IssueBulkFile(_ context.Context, req *connect.Request[backendv1.IssueBulkFileRequest]) (*connect.Response[backendv1.IssueBulkFileResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issues = append(f.issues, req.Msg)
	if f.issueErr != nil {
		return nil, f.issueErr
	}
	return connect.NewResponse(&backendv1.IssueBulkFileResponse{Message: "Process initiated for bulk issuance"}), nil
}

func (f *fakeBulk) ListBulkFiles(context.Context, *connect.Request[backendv1.ListBulkFilesRequest]) (*connect.Response[backendv1.ListBulkFilesResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.filesErr != nil {
		return nil, f.filesErr
	}
	return connect.NewResponse(&backendv1.ListBulkFilesResponse{Files: f.files, Page: &commonv1.PageResult{TotalSize: int64(len(f.files))}}), nil
}

func (f *fakeBulk) ListBulkFileRows(_ context.Context, req *connect.Request[backendv1.ListBulkFileRowsRequest]) (*connect.Response[backendv1.ListBulkFileRowsResponse], error) {
	if req.Msg.GetFileId() == "missing" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no file"))
	}
	return connect.NewResponse(&backendv1.ListBulkFileRowsResponse{
		Rows: []*backendv1.BulkFileRow{
			{Id: "r1", Email: "wanjiku@registry.gov.test", Issued: true},
			{Id: "r2", Email: "otieno@registry.gov.test", Error: "Unable to send email to the user"},
			{Id: "r3", Email: "achieng@registry.gov.test"},
		},
		Page: &commonv1.PageResult{TotalSize: 3},
	}), nil
}

func (f *fakeBulk) RetryBulkFile(_ context.Context, req *connect.Request[backendv1.RetryBulkFileRequest]) (*connect.Response[backendv1.RetryBulkFileResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retries = append(f.retries, req.Msg.GetFileId())
	if f.retryErr != nil {
		return nil, f.retryErr
	}
	return connect.NewResponse(&backendv1.RetryBulkFileResponse{Message: "Process reinitiated for bulk issuance"}), nil
}

// bulkCaps is the answer of a stack with a bulk import that mails each
// row.
func bulkCaps() *backendv1.GetCapabilitiesResponse {
	caps := didcommCaps(true)
	caps.Features = append(caps.Features, backendv1.Feature_FEATURE_BULK_NATIVE)
	caps.BulkImport = &backendv1.BulkImport{
		Channel: backendv1.Channel_CHANNEL_EMAIL, EmailColumn: "email_identifier",
		Formats: []commonv1.Format{commonv1.Format_FORMAT_ANONCREDS, commonv1.Format_FORMAT_LDP_VC},
	}
	return caps
}

// anonFarmer is the farmer schema published as SD-JWT and AnonCreds,
// and as JSON-LD when ldp is true.
func anonFarmer(ldp bool) *schemav1.Schema {
	s := didcommFarmer(commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_ANONCREDS)
	s.ConfigurationIds = map[string]string{"anoncreds": credDef}
	if ldp {
		s.Formats = append(s.Formats, commonv1.Format_FORMAT_LDP_VC)
		s.ConfigurationIds["ldp_vc"] = "http://credebl-schema-file-server:4000/schemas/farmer"
	}
	return s
}

func bulkHarness(t *testing.T, ldp bool) (*harness, *fakeBulk) {
	t.Helper()
	h := newHarness(t)
	h.caps.caps = bulkCaps()
	h.snap.Peers[0].Capabilities = h.caps.caps
	h.schemas.published = []*schemav1.Schema{anonFarmer(ldp)}
	f := &fakeBulk{}
	h.opts.BulkImport = f
	h.build(t)
	return h, f
}

// upload posts a CSV file to the upload form.
func (h *harness) upload(t *testing.T, fields url.Values, name string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, vs := range fields {
		for _, v := range vs {
			if err := w.WriteField(k, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	if name != "" {
		part, err := w.CreateFormFile("file", name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/issue/bulk/upload", &buf)
	r.Header.Set("Content-Type", w.FormDataContentType())
	return h.do(t, r)
}

// TestStackBulkImportIsASource: the source step offers the bulk import
// of the stack for a schema it issues, and sends the choice to it.
func TestStackBulkImportIsASource(t *testing.T) {
	h, _ := bulkHarness(t, false)
	doc := body(t, h.get(t, "/issue/source?schema=farmer%402"))
	a11ytest.AssertPage(t, doc)
	if !strings.Contains(doc, `value="stack"`) || !strings.Contains(doc, waltidName+" bulk import") {
		t.Errorf("the source step lacks the bulk import\n%s", doc)
	}
	rec := h.get(t, "/issue/source?schema=farmer%402&source=stack")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/issue/bulk/?schema=farmer%402" {
		t.Errorf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	// A schema the import does not issue gets the claim form.
	h.schemas.published = []*schemav1.Schema{didcommFarmer(commonv1.Format_FORMAT_DC_SD_JWT)}
	doc = body(t, h.get(t, "/issue/source?schema=farmer%402"))
	if strings.Contains(doc, `value="stack"`) {
		t.Error("an SD-JWT schema offers the bulk import")
	}
	// A stack without the import offers none.
	plain := newHarness(t)
	plain.schemas.published = []*schemav1.Schema{anonFarmer(false)}
	plain.opts.BulkImport = &fakeBulk{}
	plain.build(t)
	if doc := body(t, plain.get(t, "/issue/source?schema=farmer%402")); strings.Contains(doc, `value="stack"`) {
		t.Error("a stack without the import offers it")
	}
	if rec := plain.get(t, "/issue/bulk/?schema=farmer%402"); rec.Code != http.StatusNotFound {
		t.Errorf("the import page of a stack without it: %d", rec.Code)
	}
}

// TestBulkUploadPreviewIssue is P6-C4 for the pages: the template names
// the claims, the upload goes to the stack, the preview shows the rows,
// and the issue starts the file.
func TestBulkUploadPreviewIssue(t *testing.T) {
	h, f := bulkHarness(t, true)
	doc := body(t, h.get(t, "/issue/bulk/?schema=farmer%402"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		"Bulk import steps", `enctype="multipart/form-data"`, `type="file"`, "email_identifier",
		`href="/issue/bulk/template?format=FORMAT_ANONCREDS&amp;schema=farmer%402"`, `<select id="format" name="format"`,
		`href="/issue/bulk/files"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the import page lacks %q", want)
		}
	}

	rec := h.get(t, "/issue/bulk/template?schema=farmer%402&format=FORMAT_ANONCREDS")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Disposition") != `attachment; filename="farmer-registration.csv"` ||
		!strings.HasPrefix(rec.Body.String(), "email_identifier,fullName,farmerID") {
		t.Errorf("template %d %q %q", rec.Code, rec.Header().Get("Content-Disposition"), rec.Body.String())
	}
	if req := f.templates[0]; req.GetConfigurationId() != credDef || req.GetFormat() != commonv1.Format_FORMAT_ANONCREDS {
		t.Errorf("template request = %v", req)
	}

	csv := []byte("email_identifier,fullName,farmerID\nwanjiku@registry.gov.test,Wanjiku Njeri,FM-0042\n")
	rec = h.upload(t, url.Values{"schema": {"farmer@2"}, "format": {"FORMAT_LDP_VC"}}, `C:\exports\farmers.csv`, csv)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("upload %d: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/issue/bulk/uploads/upload-1?format=FORMAT_LDP_VC&schema=farmer%402" {
		t.Errorf("location = %q", loc)
	}
	up := f.uploads[0]
	if up.GetFileName() != "farmers.csv" || string(up.GetContent()) != string(csv) || up.GetFormat() != commonv1.Format_FORMAT_LDP_VC ||
		up.GetConfigurationId() != "http://credebl-schema-file-server:4000/schemas/farmer" {
		t.Errorf("upload = %v", up)
	}

	doc = body(t, h.get(t, "/issue/bulk/uploads/upload-1?format=FORMAT_LDP_VC&schema=farmer%402&page=2"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		"Upload rows: 45", "wanjiku@registry.gov.test", "FM-0043", "Issue 45 credentials",
		`action="/issue/bulk/uploads/upload-1/issue"`, "Previous page", "Next page", "page=3",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the preview lacks %q", want)
		}
	}
	if f.previews[0].GetPage().GetPageToken() != "2" {
		t.Errorf("preview page = %v", f.previews[0].GetPage())
	}

	rec = h.post(t, "/issue/bulk/uploads/upload-1/issue", url.Values{"schema": {"farmer@2"}, "format": {"FORMAT_LDP_VC"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/issue/bulk/files?started=1" {
		t.Fatalf("issue %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if is := f.issues[0]; is.GetUploadId() != "upload-1" || is.GetFormat() != commonv1.Format_FORMAT_LDP_VC {
		t.Errorf("issue = %v", is)
	}
}

// TestBulkUploadRefusals: the page shows the sentence of the stack, and
// a form without a file or with a large file does not reach it.
func TestBulkUploadRefusals(t *testing.T) {
	h, f := bulkHarness(t, false)
	f.uploadErr = connect.NewError(connect.CodeInvalidArgument, errors.New(
		"upload the bulk file: the platform refused: Invalid emails found in the chosen file"))
	doc := body(t, h.upload(t, url.Values{"schema": {"farmer@2"}}, "farmers.csv", []byte("x")))
	a11ytest.AssertPage(t, doc)
	if !strings.Contains(doc, "The stack refused the file (Invalid emails found in the chosen file).") {
		t.Errorf("the refusal is missing\n%s", doc)
	}
	doc = body(t, h.upload(t, url.Values{"schema": {"farmer@2"}}, "", nil))
	if !strings.Contains(doc, "Choose a filled CSV file.") {
		t.Error("a form without a file passes")
	}
	big := bytes.Repeat([]byte("a"), (4<<20)+1)
	if large := body(t, h.upload(t, url.Values{"schema": {"farmer@2"}}, "big.csv", big)); !strings.Contains(large, "The file is larger than 4 MB.") {
		t.Error("a large file passes")
	}
	// A body far above the cap stops at the reader.
	huge := bytes.Repeat([]byte("a"), (5 << 20))
	if rec := h.upload(t, url.Values{"schema": {"farmer@2"}}, "huge.csv", huge); rec.Code != http.StatusBadRequest {
		t.Errorf("a huge file: %d", rec.Code)
	}
	if len(f.uploads) != 1 {
		t.Errorf("uploads = %d", len(f.uploads))
	}
	// A preview the stack forgot and an issue it refused go back to the
	// import page.
	doc = body(t, h.get(t, "/issue/bulk/uploads/gone?schema=farmer%402"))
	if !strings.Contains(doc, "re-upload your file and generate new request") {
		t.Errorf("an expired preview\n%s", doc)
	}
	f.issueErr = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	doc = body(t, h.post(t, "/issue/bulk/uploads/upload-1/issue", url.Values{"schema": {"farmer@2"}}))
	if !strings.Contains(doc, "The stack did not start the issue (down).") {
		t.Errorf("a failed issue\n%s", doc)
	}
	// No schema: back to the issue page. A bad upload form: 400.
	if rec := h.get(t, "/issue/bulk/"); rec.Code != http.StatusSeeOther {
		t.Errorf("no schema: %d", rec.Code)
	}
	r := httptest.NewRequest(http.MethodPost, "/issue/bulk/upload", strings.NewReader("x"))
	r.Header.Set("Content-Type", "multipart/form-data")
	if rec := h.do(t, r); rec.Code != http.StatusBadRequest {
		t.Errorf("a broken form: %d", rec.Code)
	}
}

// TestBulkHistoryAndRetry is P6-C4 for the pages: the history lists the
// files, a file lists its rows, and the retry sends the failed rows
// again.
func TestBulkHistoryAndRetry(t *testing.T) {
	h, f := bulkHarness(t, false)
	doc := body(t, h.get(t, "/issue/bulk/files?started=1"))
	a11ytest.AssertPage(t, doc)
	if !strings.Contains(doc, "No file yet") || !strings.Contains(doc, "The stack started the issue.") {
		t.Errorf("the empty history\n%s", doc)
	}
	f.files = []*backendv1.BulkFile{{
		Id: "file-1", Name: "farmers.csv", State: backendv1.BulkFile_STATE_PARTIAL, TotalRows: 3, FailedRows: 2,
		SchemaName: "Farmer", CreatedAt: timestamppb.New(time.Date(2026, 9, 27, 10, 12, 0, 0, time.UTC)),
	}, {Id: "file-2", State: backendv1.BulkFile_STATE_UNSPECIFIED}}
	doc = body(t, h.get(t, "/issue/bulk/files"))
	for _, want := range []string{`href="/issue/bulk/files/file-1"`, "farmers.csv", "Partly completed", "2026-09-27 10:12 UTC", ">file-2</a>", "Unknown"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the history lacks %q", want)
		}
	}
	doc = body(t, h.get(t, "/issue/bulk/files/file-1"))
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{"File rows: 3", "Sent", "Failed", "Waiting", "Unable to send email to the user", `action="/issue/bulk/files/file-1/retry"`} {
		if !strings.Contains(doc, want) {
			t.Errorf("the file page lacks %q", want)
		}
	}
	rec := h.post(t, "/issue/bulk/files/file-1/retry", url.Values{})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/issue/bulk/files/file-1?retry=started" || f.retries[0] != "file-1" {
		t.Fatalf("retry %d %q %v", rec.Code, rec.Header().Get("Location"), f.retries)
	}
	if doc := body(t, h.get(t, "/issue/bulk/files/file-1?retry=started")); !strings.Contains(doc, "The stack sends the failed rows again.") {
		t.Error("the retry has no toast")
	}
	f.retryErr = connect.NewError(connect.CodeInvalidArgument, errors.New("File details not found."))
	rec = h.post(t, "/issue/bulk/files/file-1/retry", url.Values{})
	if rec.Header().Get("Location") != "/issue/bulk/files/file-1?retry=failed" {
		t.Errorf("a refused retry goes to %q", rec.Header().Get("Location"))
	}
	if doc := body(t, h.get(t, "/issue/bulk/files/file-1?retry=failed")); !strings.Contains(doc, "The stack did not retry the file.") {
		t.Error("the failed retry has no toast")
	}
	if rec := h.get(t, "/issue/bulk/files/missing"); rec.Code != http.StatusNotFound {
		t.Errorf("a missing file: %d", rec.Code)
	}
	f.filesErr = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	if doc := body(t, h.get(t, "/issue/bulk/files")); !strings.Contains(doc, "did not answer") {
		t.Error("a stack that does not answer")
	}
}

// TestBulkPagesNeedTheRoleAndTheImport: a viewer gets 403 on every page,
// and a stack without the import 404.
func TestBulkPagesNeedTheRoleAndTheImport(t *testing.T) {
	h, _ := bulkHarness(t, false)
	h.sess.Roles = []string{"issuer-viewer"}
	for _, path := range []string{"/issue/bulk/?schema=farmer%402", "/issue/bulk/files", "/issue/bulk/files/file-1", "/issue/bulk/template?schema=farmer%402"} {
		if rec := h.get(t, path); rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	for _, path := range []string{"/issue/bulk/files/file-1/retry", "/issue/bulk/uploads/u/issue"} {
		if rec := h.post(t, path, url.Values{"schema": {"farmer@2"}}); rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	if rec := h.upload(t, url.Values{"schema": {"farmer@2"}}, "f.csv", []byte("x")); rec.Code != http.StatusForbidden {
		t.Errorf("upload: %d", rec.Code)
	}
	plain := newHarness(t)
	plain.opts.BulkImport = &fakeBulk{}
	plain.build(t)
	for _, path := range []string{"/issue/bulk/files", "/issue/bulk/files/file-1"} {
		if rec := plain.get(t, path); rec.Code != http.StatusNotFound {
			t.Errorf("%s without the import: %d", path, rec.Code)
		}
	}
	if rec := plain.post(t, "/issue/bulk/files/file-1/retry", url.Values{}); rec.Code != http.StatusNotFound {
		t.Errorf("retry without the import: %d", rec.Code)
	}
}
