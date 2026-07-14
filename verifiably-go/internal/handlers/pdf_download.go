package handlers

// pdf_download.go — serves a PDF credential blob stashed by an adapter's
// IssueAsPDF implementation. The adapter sets IssueAsPDFResult.DownloadID
// when it has real bytes; this handler walks the registered adapters to
// find one that knows the id, then streams the bytes as application/pdf.

import (
	"net/http"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/adapters/injicertify"
)

// DownloadPDF is GET /issuer/issue/pdf/{id}. The adapter registry is
// walked (injicertify is the only current provider) so we don't couple
// the route to a specific vendor. If no adapter knows the id, 404.
func (h *H) DownloadPDF(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	// The Adapter interface doesn't expose PDFBlob — only injicertify
	// stores PDFs today. A type assertion on each registered adapter is
	// the lowest-ceremony dispatch until a second vendor needs the same
	// capability; then lift PDFBlob onto a narrow interface in /backend.
	type pdfProvider interface {
		PDFBlob(id string) ([]byte, bool)
	}
	for _, ad := range h.walkInjicertifyAdapters() {
		if p, ok := any(ad).(pdfProvider); ok {
			if b, ok := p.PDFBlob(id); ok {
				// inline=1 lets the on-screen preview embed the PDF in an
				// <iframe> (browsers render inline PDFs but download them under
				// an attachment disposition). The download link omits the param
				// so it still saves to disk.
				disposition := "attachment"
				if r.URL.Query().Get("inline") == "1" {
					disposition = "inline"
				}
				w.Header().Set("Content-Type", "application/pdf")
				w.Header().Set("Content-Disposition", disposition+"; filename=\"credential-"+id+".pdf\"")
				_, _ = w.Write(b)
				return
			}
		}
	}
	http.NotFound(w, r)
}

// walkInjicertifyAdapters is a thin helper that tolerates the registry
// wrapping the adapter. Handlers don't import the registry package, so we
// pluck the Adapter through the backend interface where feasible. In
// practice the pdf-capable adapters are all *injicertify.Adapter — we
// reach them via the same pattern OffersHandler uses in cmd/server.
func (h *H) walkInjicertifyAdapters() []*injicertify.Adapter {
	type hasAll interface {
		AllAdapters() []backend.Adapter
	}
	if r, ok := any(h.Adapter).(hasAll); ok {
		out := make([]*injicertify.Adapter, 0, 2)
		for _, ad := range r.AllAdapters() {
			if a, ok := ad.(*injicertify.Adapter); ok {
				out = append(out, a)
			}
		}
		return out
	}
	return nil
}
