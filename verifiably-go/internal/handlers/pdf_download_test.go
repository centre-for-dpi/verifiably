package handlers

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"unsafe"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/adapters/injicertify"
)

// pdfRegistryAdapter mimics the adapter registry: it embeds a nil
// backend.Adapter (unexpected calls panic) and exposes AllAdapters.
type pdfRegistryAdapter struct {
	backend.Adapter
	all []backend.Adapter
}

func (r *pdfRegistryAdapter) AllAdapters() []backend.Adapter { return r.all }

// pdfSeedBlob stashes bytes under id in an injicertify adapter's private
// blob map — the only production writer is the full pre-auth IssueAsPDF
// flow, which needs a live Inji Certify. The handler under test only reads
// through the exported PDFBlob accessor.
func pdfSeedBlob(t *testing.T, a *injicertify.Adapter, id string, b []byte) {
	t.Helper()
	f := reflect.ValueOf(a).Elem().FieldByName("pdfBlobs")
	m := reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
	m.SetMapIndex(reflect.ValueOf(id), reflect.ValueOf(b))
}

func pdfInjiAdapter(t *testing.T) *injicertify.Adapter {
	t.Helper()
	a, err := injicertify.New(injicertify.Config{BaseURL: "http://certify.example"}, "Example Certify")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func pdfReq(id, query string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/issuer/issue/pdf/"+id+query, nil)
	req.SetPathValue("id", id)
	return req
}

func TestDownloadPDF_MissingID(t *testing.T) {
	h := &H{Adapter: &pdfRegistryAdapter{}}
	rec := httptest.NewRecorder()
	h.DownloadPDF(rec, pdfReq("", ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestDownloadPDF_UnknownIDAndNonRegistryAdapter(t *testing.T) {
	// Adapter without AllAdapters → walk yields nil → 404.
	h := &H{Adapter: &testAdapter{}}
	rec := httptest.NewRecorder()
	h.DownloadPDF(rec, pdfReq("abc", ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("plain adapter: status = %d, want 404", rec.Code)
	}
	if got := h.walkInjicertifyAdapters(); got != nil {
		t.Errorf("walk on non-registry adapter = %v, want nil", got)
	}

	// Registry with an injicertify adapter that does not know the id → 404.
	inji := pdfInjiAdapter(t)
	h = &H{Adapter: &pdfRegistryAdapter{all: []backend.Adapter{&testAdapter{}, inji}}}
	rec = httptest.NewRecorder()
	h.DownloadPDF(rec, pdfReq("abc", ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id: status = %d, want 404", rec.Code)
	}
	if got := h.walkInjicertifyAdapters(); len(got) != 1 || got[0] != inji {
		t.Errorf("walk should return only the injicertify adapter, got %v", got)
	}
}

func TestDownloadPDF_StreamsBlob(t *testing.T) {
	inji := pdfInjiAdapter(t)
	pdfSeedBlob(t, inji, "cred-1", []byte("%PDF-1.4 example"))
	h := &H{Adapter: &pdfRegistryAdapter{all: []backend.Adapter{inji}}}

	rec := httptest.NewRecorder()
	h.DownloadPDF(rec, pdfReq("cred-1", ""))
	if rec.Code != http.StatusOK || rec.Body.String() != "%PDF-1.4 example" {
		t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="credential-cred-1.pdf"` {
		t.Errorf("Content-Disposition = %q", cd)
	}

	rec = httptest.NewRecorder()
	h.DownloadPDF(rec, pdfReq("cred-1", "?inline=1"))
	if cd := rec.Header().Get("Content-Disposition"); cd != `inline; filename="credential-cred-1.pdf"` {
		t.Errorf("inline Content-Disposition = %q", cd)
	}
}
