// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/service"
)

// P6-C4 and ADR-060: the CSV bulk import of the platform. The platform
// mails each row an out of band offer, so it runs only with a mail
// provider.

// mailing returns the service of a stack with a mail provider.
func mailing(t *testing.T) (*service.Service, *fake.Server) {
	t.Helper()
	return newService(t, func(o *service.Options) { o.MailOffers = true })
}

// TestFeatureBulkNativeListed is P6-C4: the answer lists
// FEATURE_BULK_NATIVE and the bulk import on the email channel only
// with a mail provider.
func TestFeatureBulkNativeListed(t *testing.T) {
	for _, mail := range []bool{false, true} {
		svc, _ := newService(t, func(o *service.Options) { o.MailOffers = mail })
		resp, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		m := resp.Msg
		if slices.Contains(m.GetFeatures(), backendv1.Feature_FEATURE_BULK_NATIVE) != mail {
			t.Errorf("mail %v: features %v", mail, m.GetFeatures())
		}
		imp := m.GetBulkImport()
		if !mail {
			if imp != nil {
				t.Errorf("a stack without mail names a bulk import: %v", imp)
			}
			continue
		}
		if imp.GetChannel() != backendv1.Channel_CHANNEL_EMAIL || imp.GetEmailColumn() != "email_identifier" ||
			!slices.Equal(imp.GetFormats(), []commonv1.Format{commonv1.Format_FORMAT_ANONCREDS, commonv1.Format_FORMAT_LDP_VC}) {
			t.Errorf("bulk import = %v", imp)
		}
	}
}

// TestBulkUploadPreviewIssue is P6-C4: the template names the columns,
// the upload hands the file to the platform, the preview reads its rows,
// the issue starts it, and the history lists the file and its rows.
func TestBulkUploadPreviewIssue(t *testing.T) {
	svc, f := mailing(t)
	ctx := context.Background()
	tpl, err := svc.GetBulkTemplate(ctx, connect.NewRequest(&backendv1.GetBulkTemplateRequest{
		ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS, Claims: []string{"holder_name", "acres"},
	}))
	if err != nil {
		t.Fatalf("GetBulkTemplate: %v", err)
	}
	if string(tpl.Msg.GetContent()) != "email_identifier,holder_name,acres\n" ||
		!slices.Equal(tpl.Msg.GetColumns(), []string{"email_identifier", "holder_name", "acres"}) ||
		!strings.HasSuffix(tpl.Msg.GetFileName(), ".csv") {
		t.Errorf("template = %q %v %q", tpl.Msg.GetContent(), tpl.Msg.GetColumns(), tpl.Msg.GetFileName())
	}

	csv := []byte("email_identifier,holder_name,acres\nwanjiku@registry.gov.test,Wanjiku,12\n")
	up, err := svc.UploadBulkFile(ctx, connect.NewRequest(&backendv1.UploadBulkFileRequest{
		ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS, FileName: "farmers.csv", Content: csv,
	}))
	if err != nil {
		t.Fatalf("UploadBulkFile: %v", err)
	}
	if up.Msg.GetUploadId() != "3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f" {
		t.Errorf("upload id = %q", up.Msg.GetUploadId())
	}
	name, sent, err := f.Upload("/v1/orgs/org-1/bulk/upload")
	if err != nil || name != "farmers.csv" || string(sent) != string(csv) {
		t.Errorf("sent %q %q %v", name, sent, err)
	}
	if q := f.Query("/v1/orgs/org-1/bulk/upload"); q != "schemaType=indy&templateId="+strings.ReplaceAll(strings.ReplaceAll(credDef, ":", "%3A"), "/", "%2F") {
		t.Errorf("query = %q", q)
	}

	prev, err := svc.PreviewBulkFile(ctx, connect.NewRequest(&backendv1.PreviewBulkFileRequest{
		UploadId: up.Msg.GetUploadId(), Page: &commonv1.Pagination{PageSize: 1},
	}))
	if err != nil {
		t.Fatalf("PreviewBulkFile: %v", err)
	}
	rows := prev.Msg.GetRows()
	if len(rows) != 2 || rows[0].GetEmail() != "[holder one]@example.org" || rows[0].GetClaims()["holder_name"] != "[holder one]" ||
		len(rows[0].GetClaims()) != 1 || prev.Msg.GetPage().GetTotalSize() != 2 || prev.Msg.GetPage().GetNextPageToken() != "2" {
		t.Errorf("preview = %v", prev.Msg)
	}

	issued, err := svc.IssueBulkFile(ctx, connect.NewRequest(&backendv1.IssueBulkFileRequest{
		UploadId: up.Msg.GetUploadId(), ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS,
	}))
	if err != nil {
		t.Fatalf("IssueBulkFile: %v", err)
	}
	if issued.Msg.GetMessage() != "Process initiated for bulk issuance" {
		t.Errorf("message = %q", issued.Msg.GetMessage())
	}
	if !slices.Contains(f.Calls(), "POST /v1/orgs/org-1/3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f/bulk") {
		t.Errorf("calls = %v", f.Calls())
	}

	files, err := svc.ListBulkFiles(ctx, connect.NewRequest(&backendv1.ListBulkFilesRequest{}))
	if err != nil {
		t.Fatalf("ListBulkFiles: %v", err)
	}
	file := files.Msg.GetFiles()[0]
	if file.GetId() != "8e9f0a1b-2c3d-4e4f-9a5b-6c7d8e9f0a1b" || file.GetState() != backendv1.BulkFile_STATE_PARTIAL ||
		file.GetTotalRows() != 2 || file.GetFailedRows() != 1 || file.GetSchemaName() != "RegistrationCertificate" ||
		!file.GetCreatedAt().AsTime().Equal(timestamppb.New(file.GetCreatedAt().AsTime()).AsTime()) || file.GetName() != "[file one].csv" {
		t.Errorf("file = %v", file)
	}
	lines, err := svc.ListBulkFileRows(ctx, connect.NewRequest(&backendv1.ListBulkFileRowsRequest{FileId: file.GetId()}))
	if err != nil {
		t.Fatalf("ListBulkFileRows: %v", err)
	}
	got := lines.Msg.GetRows()
	if len(got) != 2 || !got[0].GetIssued() || got[0].GetEmail() != "[holder one]@example.org" ||
		got[1].GetIssued() || got[1].GetError() != "Unable to send email to the user" {
		t.Errorf("rows = %v", got)
	}
}

// TestBulkRetry is P6-C4: the retry hands the failed rows of a file to
// the platform again.
func TestBulkRetry(t *testing.T) {
	svc, f := mailing(t)
	resp, err := svc.RetryBulkFile(context.Background(), connect.NewRequest(&backendv1.RetryBulkFileRequest{FileId: "file-1"}))
	if err != nil {
		t.Fatalf("RetryBulkFile: %v", err)
	}
	if resp.Msg.GetMessage() != "Process reinitiated for bulk issuance" || !slices.Contains(f.Calls(), "POST /v1/orgs/org-1/file-1/retry/bulk") {
		t.Errorf("retry = %q, calls %v", resp.Msg.GetMessage(), f.Calls())
	}
	if _, err := svc.RetryBulkFile(context.Background(), connect.NewRequest(&backendv1.RetryBulkFileRequest{})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a retry without a file: %v", err)
	}
	f.SetStatus("/v1/orgs/org-1/file-1/retry/bulk", http.StatusBadRequest)
	if _, err := svc.RetryBulkFile(context.Background(), connect.NewRequest(&backendv1.RetryBulkFileRequest{FileId: "file-1"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a refused retry: %v", err)
	}
}

// TestBulkImportRefusals: the import needs a mail provider, a DIDComm
// format, the ids, and a file.
func TestBulkImportRefusals(t *testing.T) {
	ctx := context.Background()
	off, _ := newService(t, nil)
	if _, err := off.ListBulkFiles(ctx, connect.NewRequest(&backendv1.ListBulkFilesRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("an import without mail: %v", err)
	}
	svc, f := mailing(t)
	cases := map[string]func() error{
		"an SD-JWT template": func() error {
			_, err := svc.GetBulkTemplate(ctx, connect.NewRequest(&backendv1.GetBulkTemplateRequest{
				ConfigurationId: "Farmer", Format: commonv1.Format_FORMAT_DC_SD_JWT, Claims: []string{"a"},
			}))
			return err
		},
		"a template without claims": func() error {
			_, err := svc.GetBulkTemplate(ctx, connect.NewRequest(&backendv1.GetBulkTemplateRequest{
				ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS,
			}))
			return err
		},
		"a claim named as the email column": func() error {
			_, err := svc.GetBulkTemplate(ctx, connect.NewRequest(&backendv1.GetBulkTemplateRequest{
				ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS, Claims: []string{"email_identifier"},
			}))
			return err
		},
		"a template without a configuration": func() error {
			_, err := svc.GetBulkTemplate(ctx, connect.NewRequest(&backendv1.GetBulkTemplateRequest{
				Format: commonv1.Format_FORMAT_ANONCREDS, Claims: []string{"a"},
			}))
			return err
		},
		"an empty upload": func() error {
			_, err := svc.UploadBulkFile(ctx, connect.NewRequest(&backendv1.UploadBulkFileRequest{
				ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS,
			}))
			return err
		},
		"a preview without an upload": func() error {
			_, err := svc.PreviewBulkFile(ctx, connect.NewRequest(&backendv1.PreviewBulkFileRequest{}))
			return err
		},
		"a preview with a bad page": func() error {
			_, err := svc.PreviewBulkFile(ctx, connect.NewRequest(&backendv1.PreviewBulkFileRequest{
				UploadId: "u", Page: &commonv1.Pagination{PageToken: "x"},
			}))
			return err
		},
		"an issue without an upload": func() error {
			_, err := svc.IssueBulkFile(ctx, connect.NewRequest(&backendv1.IssueBulkFileRequest{
				ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS,
			}))
			return err
		},
		"rows without a file": func() error {
			_, err := svc.ListBulkFileRows(ctx, connect.NewRequest(&backendv1.ListBulkFileRowsRequest{}))
			return err
		},
	}
	for name, call := range cases {
		if code := connect.CodeOf(call()); code != connect.CodeInvalidArgument {
			t.Errorf("%s: code %v", name, code)
		}
	}
	// The platform refuses a file: the operator reads its sentence.
	f.SetStatus("/v1/orgs/org-1/bulk/upload", http.StatusBadRequest)
	_, err := svc.UploadBulkFile(ctx, connect.NewRequest(&backendv1.UploadBulkFileRequest{
		ConfigurationId: w3cSchema, Format: commonv1.Format_FORMAT_LDP_VC, FileName: "f.csv", Content: []byte("x"),
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a refused upload: %v", err)
	}
	// No file yet: an empty history.
	f.SetBulkFiles(fake.NoBulkFiles)
	files, err := svc.ListBulkFiles(ctx, connect.NewRequest(&backendv1.ListBulkFilesRequest{}))
	if err != nil || len(files.Msg.GetFiles()) != 0 {
		t.Errorf("files = %v, %v", files, err)
	}
}

// TestBulkJsonLdNamesTheSchema: a JSON-LD file names the schema by its
// address and no credential definition.
func TestBulkJsonLdNamesTheSchema(t *testing.T) {
	svc, f := mailing(t)
	ctx := context.Background()
	if _, err := svc.UploadBulkFile(ctx, connect.NewRequest(&backendv1.UploadBulkFileRequest{
		ConfigurationId: w3cSchema, Format: commonv1.Format_FORMAT_LDP_VC, Content: []byte("x"),
	})); err != nil {
		t.Fatal(err)
	}
	if q := f.Query("/v1/orgs/org-1/bulk/upload"); !strings.HasPrefix(q, "schemaType=w3c&templateId=http") {
		t.Errorf("query = %q", q)
	}
	name, _, err := f.Upload("/v1/orgs/org-1/bulk/upload")
	if err != nil || name != "credentials.csv" {
		t.Errorf("file name %q, %v", name, err)
	}
	if _, err := svc.IssueBulkFile(ctx, connect.NewRequest(&backendv1.IssueBulkFileRequest{
		UploadId: "u-1", ConfigurationId: w3cSchema, Format: commonv1.Format_FORMAT_LDP_VC,
	})); err != nil {
		t.Fatal(err)
	}
	if q := f.Query("/v1/orgs/org-1/u-1/bulk"); q != "" {
		t.Errorf("query = %q", q)
	}
}

// TestIssueBatchMailsEachRowThroughTheImport is P6-C4 for IssueBatch:
// the rows go to the platform as one CSV file, and a row without a good
// address fails alone.
func TestIssueBatchMailsEachRowThroughTheImport(t *testing.T) {
	svc, f := mailing(t)
	spec := func(claims string) *backendv1.IssueSpec {
		return &backendv1.IssueSpec{ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS, SubjectData: claims}
	}
	resp, err := svc.IssueBatch(context.Background(), connect.NewRequest(&backendv1.IssueBatchRequest{
		Specs: []*backendv1.IssueSpec{
			spec(`{"holder_name":"Wanjiku","acres":12}`),
			spec(`{"holder_name":"Otieno","acres":3}`),
			spec(`{"holder_name":"Achieng","acres":7}`),
		},
		Emails: []string{"wanjiku@registry.gov.test", "not an address", "achieng@registry.gov.test"},
	}))
	if err != nil {
		t.Fatalf("IssueBatch: %v", err)
	}
	items := resp.Msg.GetItems()
	if len(items) != 3 || !items[0].GetDelivered() || items[1].GetDelivered() || items[1].GetError() == nil ||
		!items[2].GetDelivered() || items[2].GetPosition() != 2 || items[0].GetCredential() != nil {
		t.Fatalf("items = %v", items)
	}
	_, sent, err := f.Upload("/v1/orgs/org-1/bulk/upload")
	if err != nil {
		t.Fatal(err)
	}
	want := "email_identifier,acres,holder_name\nwanjiku@registry.gov.test,12,Wanjiku\nachieng@registry.gov.test,7,Achieng\n"
	if string(sent) != want {
		t.Errorf("file = %q, want %q", sent, want)
	}
	if !slices.Contains(f.Calls(), "POST /v1/orgs/org-1/3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f/bulk") {
		t.Errorf("calls = %v", f.Calls())
	}
}

// TestIssueBatchRefusals: a batch names one configuration, one address
// per spec, claims as a JSON object, and no validity window.
func TestIssueBatchRefusals(t *testing.T) {
	svc, f := mailing(t)
	ctx := context.Background()
	anon := func(claims string) *backendv1.IssueSpec {
		return &backendv1.IssueSpec{ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS, SubjectData: claims}
	}
	cases := map[string]*backendv1.IssueBatchRequest{
		"no spec":         {},
		"no address":      {Specs: []*backendv1.IssueSpec{anon(`{"a":"1"}`)}},
		"two configs":     {Specs: []*backendv1.IssueSpec{anon(`{"a":"1"}`), {ConfigurationId: "other", Format: commonv1.Format_FORMAT_ANONCREDS, SubjectData: `{"a":"1"}`}}, Emails: []string{"a@example.org", "b@example.org"}},
		"an SD-JWT batch": {Specs: []*backendv1.IssueSpec{{ConfigurationId: "Farmer", Format: commonv1.Format_FORMAT_DC_SD_JWT, SubjectData: `{"a":"1"}`}}, Emails: []string{"a@example.org"}},
	}
	for name, req := range cases {
		if _, err := svc.IssueBatch(ctx, connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Rows that fail alone: bad claims and a validity window. With no
	// good row left, nothing reaches the platform.
	window := anon(`{"a":"1"}`)
	window.Validity = &commonv1.ValidityWindow{ValidUntil: timestamppb.Now()}
	resp, err := svc.IssueBatch(ctx, connect.NewRequest(&backendv1.IssueBatchRequest{
		Specs:  []*backendv1.IssueSpec{anon(`not json`), window},
		Emails: []string{"a@example.org", "b@example.org"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range resp.Msg.GetItems() {
		if item.GetError() == nil || item.GetDelivered() {
			t.Errorf("item = %v", item)
		}
	}
	if slices.Contains(f.Calls(), "POST /v1/orgs/org-1/bulk/upload") {
		t.Error("a batch without a good row reached the platform")
	}
	// The platform refuses the file: the call fails.
	f.SetStatus("/v1/orgs/org-1/bulk/upload", http.StatusBadRequest)
	if _, err := svc.IssueBatch(ctx, connect.NewRequest(&backendv1.IssueBatchRequest{
		Specs: []*backendv1.IssueSpec{anon(`{"a":"1"}`)}, Emails: []string{"a@example.org"},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a refused file: %v", err)
	}
	// Without a mail provider the stack has no bulk import.
	off, _ := newService(t, nil)
	if _, err := off.IssueBatch(ctx, connect.NewRequest(&backendv1.IssueBatchRequest{
		Specs: []*backendv1.IssueSpec{anon(`{"a":"1"}`)}, Emails: []string{"a@example.org"},
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a batch without mail: %v", err)
	}
}

// TestBulkCallsReportThePlatformFailure: a platform that fails gives
// the code Unavailable on every call.
func TestBulkCallsReportThePlatformFailure(t *testing.T) {
	svc, f := mailing(t)
	ctx := context.Background()
	for _, path := range []string{
		"/v1/orgs/org-1/u-1/preview", "/v1/orgs/org-1/u-1/bulk", "/v1/orgs/org-1/bulk/files",
		"/v1/orgs/org-1/f-1/bulk/file-data", "/v1/orgs/org-1/bulk/upload",
	} {
		f.SetStatus(path, http.StatusBadGateway)
	}
	calls := map[string]func() error{
		"preview": func() error {
			_, err := svc.PreviewBulkFile(ctx, connect.NewRequest(&backendv1.PreviewBulkFileRequest{UploadId: "u-1"}))
			return err
		},
		"issue": func() error {
			_, err := svc.IssueBulkFile(ctx, connect.NewRequest(&backendv1.IssueBulkFileRequest{
				UploadId: "u-1", ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS,
			}))
			return err
		},
		"files": func() error {
			_, err := svc.ListBulkFiles(ctx, connect.NewRequest(&backendv1.ListBulkFilesRequest{}))
			return err
		},
		"rows": func() error {
			_, err := svc.ListBulkFileRows(ctx, connect.NewRequest(&backendv1.ListBulkFileRowsRequest{FileId: "f-1"}))
			return err
		},
		"batch": func() error {
			_, err := svc.IssueBatch(ctx, connect.NewRequest(&backendv1.IssueBatchRequest{
				Specs:  []*backendv1.IssueSpec{{ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS, SubjectData: `{"a":"1"}`}},
				Emails: []string{"a@example.org"},
			}))
			return err
		},
	}
	for name, call := range calls {
		if code := connect.CodeOf(call()); code != connect.CodeUnavailable {
			t.Errorf("%s: code %v", name, code)
		}
	}
	// The issue of a batch fails after the upload.
	f.SetStatus("/v1/orgs/org-1/3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f/bulk", http.StatusBadGateway)
	if _, err := svc.IssueBatch(ctx, connect.NewRequest(&backendv1.IssueBatchRequest{
		Specs:  []*backendv1.IssueSpec{{ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS, SubjectData: `{"a":"1","b":"2"}`}, {ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS, SubjectData: `{"a":"3"}`}},
		Emails: []string{"a@example.org", "b@example.org"},
	})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("batch issue: %v", err)
	}
	_, sent, err := f.Upload("/v1/orgs/org-1/bulk/upload")
	if err != nil || string(sent) != "email_identifier,a,b\na@example.org,1,2\nb@example.org,3,\n" {
		t.Errorf("a row without a claim leaves its cell empty: %q %v", sent, err)
	}
	// Bad pages, and the email column as a claim.
	for name, call := range map[string]func() error{
		"files page": func() error {
			_, lerr := svc.ListBulkFiles(ctx, connect.NewRequest(&backendv1.ListBulkFilesRequest{Page: &commonv1.Pagination{PageToken: "0"}}))
			return lerr
		},
		"rows page": func() error {
			_, lerr := svc.ListBulkFileRows(ctx, connect.NewRequest(&backendv1.ListBulkFileRowsRequest{FileId: "f", Page: &commonv1.Pagination{PageToken: "x"}}))
			return lerr
		},
	} {
		if code := connect.CodeOf(call()); code != connect.CodeInvalidArgument {
			t.Errorf("%s: code %v", name, code)
		}
	}
	resp, err := svc.IssueBatch(ctx, connect.NewRequest(&backendv1.IssueBatchRequest{
		Specs:  []*backendv1.IssueSpec{{ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS, SubjectData: `{"email_identifier":"x"}`}},
		Emails: []string{"a@example.org"},
	}))
	if err != nil || resp.Msg.GetItems()[0].GetError() == nil {
		t.Errorf("a claim named as the email column: %v %v", resp, err)
	}
}

// TestBulkImportWithoutMailRefusesEveryCall: without a mail provider
// every call of the import fails before it reaches the platform.
func TestBulkImportWithoutMailRefusesEveryCall(t *testing.T) {
	svc, f := newService(t, nil)
	ctx := context.Background()
	calls := []func() error{
		func() error {
			_, err := svc.PreviewBulkFile(ctx, connect.NewRequest(&backendv1.PreviewBulkFileRequest{UploadId: "u"}))
			return err
		},
		func() error {
			_, err := svc.ListBulkFileRows(ctx, connect.NewRequest(&backendv1.ListBulkFileRowsRequest{FileId: "f"}))
			return err
		},
		func() error {
			_, err := svc.RetryBulkFile(ctx, connect.NewRequest(&backendv1.RetryBulkFileRequest{FileId: "f"}))
			return err
		},
		func() error {
			_, err := svc.UploadBulkFile(ctx, connect.NewRequest(&backendv1.UploadBulkFileRequest{ConfigurationId: credDef, Format: commonv1.Format_FORMAT_ANONCREDS, Content: []byte("x")}))
			return err
		},
	}
	for i, call := range calls {
		if code := connect.CodeOf(call()); code != connect.CodeFailedPrecondition {
			t.Errorf("call %d: code %v", i, code)
		}
	}
	if len(f.Calls()) != 0 {
		t.Errorf("calls = %v", f.Calls())
	}
}
