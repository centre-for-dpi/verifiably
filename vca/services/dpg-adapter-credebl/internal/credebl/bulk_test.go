// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// P6-C4 and ADR-060: the bulk issuance calls of the api gateway.

// bulkServer answers the bulk calls from the fixtures of testdata/doc
// and records each request.
type bulkServer struct {
	srv      *httptest.Server
	calls    []string
	file     []byte
	fileName string
	fields   map[string]string
	status   map[string]int
}

func newBulkServer(t *testing.T) *bulkServer {
	t.Helper()
	b := &bulkServer{fields: map[string]string{}, status: map[string]int{}}
	files := map[string]string{
		"POST /v1/orgs/org-1/bulk/upload":          "bulk-upload-created.json",
		"GET /v1/orgs/org-1/req-1/preview":         "bulk-preview.json",
		"POST /v1/orgs/org-1/req-1/bulk":           "bulk-issue-started.json",
		"GET /v1/orgs/org-1/bulk/files":            "bulk-files.json",
		"GET /v1/orgs/org-1/file-1/bulk/file-data": "bulk-file-rows.json",
		"POST /v1/orgs/org-1/file-1/retry/bulk":    "bulk-retry-started.json",
	}
	// The refusal of an upload with a bad address.
	refusals := map[string]string{"POST /v1/orgs/org-1/bulk/upload": "bulk-upload-refused.json"}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
			return
		}
		key := r.Method + " " + r.URL.Path
		b.calls = append(b.calls, key+"?"+r.URL.RawQuery)
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Errorf("the upload is no multipart form: %v", err)
			}
			for name, v := range r.MultipartForm.Value {
				b.fields[name] = v[0]
			}
			f, h, err := r.FormFile("file")
			if err != nil {
				t.Fatalf("the upload has no file: %v", err)
			}
			b.fileName = h.Filename
			b.file, err = io.ReadAll(f)
			if err != nil {
				t.Fatal(err)
			}
		}
		if code := b.status[key]; code != 0 {
			w.WriteHeader(code)
			name, ok := refusals[key]
			if !ok {
				return
			}
			data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "doc", name)) // #nosec G304 -- a fixed test path
			if err != nil {
				t.Fatal(err)
			}
			mustWrite(t, w, data)
			return
		}
		name, ok := files[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "doc", name)) // #nosec G304 -- a fixed test path
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(t, w, data)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func TestUploadBulkFileSendsTheCSV(t *testing.T) {
	b := newBulkServer(t)
	c := newClient(b.srv, nil)
	csv := []byte("email_identifier,holder_name\nwanjiku@registry.gov.test,Wanjiku\n")
	id, err := c.UploadBulkFile(context.Background(), BulkSchemaIndy, "cred-def-1", "farmers.csv", csv)
	if err != nil {
		t.Fatal(err)
	}
	if id != "3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f" {
		t.Errorf("id = %q", id)
	}
	if string(b.file) != string(csv) || b.fileName != "farmers.csv" || b.fields["fileName"] != "farmers.csv" {
		t.Errorf("file %q %q %v", b.fileName, b.file, b.fields)
	}
	if b.calls[0] != "POST /v1/orgs/org-1/bulk/upload?schemaType=indy&templateId=cred-def-1" {
		t.Errorf("call = %q", b.calls[0])
	}
}

func TestUploadBulkFileRefusals(t *testing.T) {
	b := newBulkServer(t)
	c := newClient(b.srv, nil)
	ctx := context.Background()
	if _, err := c.UploadBulkFile(ctx, BulkSchemaIndy, "", "f.csv", []byte("x")); err == nil {
		t.Error("an upload without a template passed")
	}
	if _, err := c.UploadBulkFile(ctx, BulkSchemaIndy, "cred-def-1", "f.csv", nil); err == nil {
		t.Error("an empty upload passed")
	}
	b.status["POST /v1/orgs/org-1/bulk/upload"] = http.StatusBadRequest
	_, err := c.UploadBulkFile(ctx, BulkSchemaIndy, "cred-def-1", "f.csv", []byte("x"))
	if !dpgclient.IsStatus(err, http.StatusBadRequest) || !strings.Contains(err.Error(), "Invalid emails found in the chosen file") {
		t.Errorf("err = %v", err)
	}
	var nilClient *Client
	if _, err := nilClient.UploadBulkFile(ctx, BulkSchemaIndy, "cred-def-1", "f.csv", []byte("x")); !errors.Is(err, ErrNoPlatform) {
		t.Errorf("nil client err = %v", err)
	}
}

func TestUploadBulkFileNeedsARequestID(t *testing.T) {
	for _, body := range []string{`{"statusCode":201,"data":""}`, `not json`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/auth/signin" {
				mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
				return
			}
			mustWrite(t, w, []byte(body))
		}))
		c := newClient(srv, nil)
		if _, err := c.UploadBulkFile(context.Background(), BulkSchemaW3C, "https://schemas.example/s", "f.csv", []byte("x")); err == nil {
			t.Errorf("the answer %q passed", body)
		}
		srv.Close()
	}
}

func TestPreviewBulkFileReadsTheWrappedPage(t *testing.T) {
	b := newBulkServer(t)
	c := newClient(b.srv, nil)
	rows, total, err := c.PreviewBulkFile(context.Background(), "req-1", 2, 5)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(rows) != 2 || rows[1][EmailColumn] != "[holder two]@example.org" || rows[0]["holder_name"] != "[holder one]" {
		t.Errorf("rows = %v total = %d", rows, total)
	}
	if b.calls[0] != "GET /v1/orgs/org-1/req-1/preview?pageNumber=2&pageSize=5" {
		t.Errorf("call = %q", b.calls[0])
	}
}

func TestPreviewBulkFileReadsAPlainPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
			return
		}
		mustWrite(t, w, []byte(`{"data":{"totalItems":1,"data":[{"email_identifier":"a@example.org"}]}}`))
	}))
	defer srv.Close()
	rows, total, err := newClient(srv, nil).PreviewBulkFile(context.Background(), "req-plain", 1, 10)
	if err != nil || total != 1 || rows[0][EmailColumn] != "a@example.org" {
		t.Errorf("rows = %v %d %v", rows, total, err)
	}
}

func TestIssueAndRetryBulkFile(t *testing.T) {
	b := newBulkServer(t)
	c := newClient(b.srv, nil)
	ctx := context.Background()
	text, err := c.IssueBulkFile(ctx, "req-1", "cred-def-1")
	if err != nil || text != "Process initiated for bulk issuance" {
		t.Fatalf("issue = %q %v", text, err)
	}
	if b.calls[0] != "POST /v1/orgs/org-1/req-1/bulk?credDefId=cred-def-1" {
		t.Errorf("call = %q", b.calls[0])
	}
	text, err = c.RetryBulkFile(ctx, "file-1")
	if err != nil || text != "Process reinitiated for bulk issuance" {
		t.Fatalf("retry = %q %v", text, err)
	}
	// A JSON-LD file names no credential definition.
	b.calls = nil
	if _, err := c.IssueBulkFile(ctx, "req-1", ""); err != nil {
		t.Fatal(err)
	}
	if b.calls[0] != "POST /v1/orgs/org-1/req-1/bulk?" {
		t.Errorf("call = %q", b.calls[0])
	}
}

func TestBulkFilesAndRows(t *testing.T) {
	b := newBulkServer(t)
	c := newClient(b.srv, nil)
	ctx := context.Background()
	files, total, err := c.BulkFiles(ctx, 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	f := files[0]
	if total != 1 || f.ID != "8e9f0a1b-2c3d-4e4f-9a5b-6c7d8e9f0a1b" || f.Status != FilePartial ||
		f.TotalRecords != 2 || f.FailedRecords != 1 || f.Schema.Name != "RegistrationCertificate" || f.CreatedAt.IsZero() {
		t.Errorf("file = %+v", f)
	}
	rows, total, err := c.BulkFileRows(ctx, "file-1", 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || !rows[0].Status || rows[0].Email() != "[holder one]@example.org" || rows[0].Reason() != "" {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if !rows[1].IsError || rows[1].Reason() != "Unable to send email to the user" {
		t.Errorf("row 1 = %+v reason %q", rows[1], rows[1].Reason())
	}
	if b.calls[1] != "GET /v1/orgs/org-1/file-1/bulk/file-data?pageNumber=1&pageSize=20&sortBy=asc" {
		t.Errorf("call = %q", b.calls[1])
	}
}

func TestBulkFileRowReadsItsParts(t *testing.T) {
	row := BulkFileRow{CredentialData: map[string]any{EmailColumn: "b@example.org"}, Error: `{"message":"The agent is down"}`}
	if row.Email() != "b@example.org" || row.Reason() != "The agent is down" {
		t.Errorf("email %q reason %q", row.Email(), row.Reason())
	}
	row = BulkFileRow{Error: "plain text"}
	if row.Email() != "" || row.Reason() != "plain text" {
		t.Errorf("email %q reason %q", row.Email(), row.Reason())
	}
}

func TestBulkFilesNoneIsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	files, total, err := newClient(srv, nil).BulkFiles(context.Background(), 1, 20)
	if err != nil || files != nil || total != 0 {
		t.Errorf("files = %v %d %v", files, total, err)
	}
}

func TestBulkCallsFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			mustWrite(t, w, []byte(`{"data":{"access_token":"t"}}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	c := newClient(srv, nil)
	ctx := context.Background()
	if _, _, err := c.PreviewBulkFile(ctx, "r", 1, 1); err == nil {
		t.Error("preview passed")
	}
	if _, err := c.IssueBulkFile(ctx, "r", ""); err == nil {
		t.Error("issue passed")
	}
	if _, _, err := c.BulkFiles(ctx, 1, 1); err == nil {
		t.Error("files passed")
	}
	if _, _, err := c.BulkFileRows(ctx, "f", 1, 1); err == nil {
		t.Error("rows passed")
	}
	if _, err := c.RetryBulkFile(ctx, "f"); err == nil {
		t.Error("retry passed")
	}
	var nilClient *Client
	if _, _, err := nilClient.PreviewBulkFile(ctx, "r", 1, 1); !errors.Is(err, ErrNoPlatform) {
		t.Error("nil preview")
	}
	if _, err := nilClient.IssueBulkFile(ctx, "r", ""); !errors.Is(err, ErrNoPlatform) {
		t.Error("nil issue")
	}
	if _, _, err := nilClient.BulkFiles(ctx, 1, 1); !errors.Is(err, ErrNoPlatform) {
		t.Error("nil files")
	}
	if _, _, err := nilClient.BulkFileRows(ctx, "f", 1, 1); !errors.Is(err, ErrNoPlatform) {
		t.Error("nil rows")
	}
	if _, err := nilClient.RetryBulkFile(ctx, "f"); !errors.Is(err, ErrNoPlatform) {
		t.Error("nil retry")
	}
}
