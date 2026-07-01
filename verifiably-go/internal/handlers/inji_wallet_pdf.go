package handlers

// inji_wallet_pdf.go — download a claimed Inji credential as a QR-on-PDF.
//
// Reuses the pre-auth issuance path's PixelPass encoder + gofpdf layout
// (exported from internal/adapters/injicertify) so a credential already sitting
// in the holder's in-app wallet can be saved as the same verifiable,
// Inji-Verify-scannable artifact the issuer's "As a PDF" mode produces.

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/verifiably/verifiably-go/internal/adapters/injicertify"
)

// DownloadInjiClaimedPDF streams a wallet credential as a one-page A4 PDF whose
// QR embeds the VC in MOSIP PixelPass format (scannable by Inji Verify), with
// the credential's human-readable claims printed above it.
//
// GET /holder/wallet/inji/credentials/{id}/pdf — {id} is the stable vcID.
func (h *H) DownloadInjiClaimedPDF(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	id := r.PathValue("id")
	var vc string
	for _, v := range sess.InjiClaimedVCs {
		if vcID(v) == id {
			vc = v
			break
		}
	}
	if vc == "" {
		http.NotFound(w, r)
		return
	}

	parsed := parseClaimedVC(vc)
	title := "Verifiable Credential"
	if n, _ := parsed["ClaimedName"].(string); n != "" {
		title = n
	}
	issuer, _ := parsed["Issuer"].(string)

	// Human-readable claim rows from credentialSubject, key-sorted for a stable
	// layout (matches the wallet card, where text/template renders map keys
	// sorted).
	fields := map[string]string{}
	var order []string
	if cs, ok := parsed["Subject"].(map[string]any); ok {
		for k, v := range cs {
			fields[k] = fmt.Sprintf("%v", v)
			order = append(order, k)
		}
		sort.Strings(order)
	}

	qrPayload, err := injicertify.EncodePixelPassQR([]byte(vc))
	if err != nil {
		http.Error(w, "encode qr: "+err.Error(), http.StatusInternalServerError)
		return
	}
	pdfBytes, err := injicertify.RenderCredentialPDF(title, issuer, qrPayload, fields, order)
	if err != nil {
		http.Error(w, "render pdf: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="credential-`+id+`.pdf"`)
	_, _ = w.Write(pdfBytes)
}
