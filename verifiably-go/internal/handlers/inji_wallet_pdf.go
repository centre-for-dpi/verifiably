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

	// Best-effort QR: PixelPass-encode the credential and render it with a QR,
	// letting qr.Encode itself decide whether the payload fits QR version 40 — we
	// fall back only when it genuinely overflows. A W3C ldp_vc typically fits; an
	// SD-JWT VC carries an x5c chain that overflows even v40, so it falls back to a
	// QR-less PDF (claims + full credential text + a holder note) rather than 500-ing.
	var pdfBytes []byte
	if qrPayload, qErr := injicertify.EncodePixelPassQR([]byte(vc)); qErr == nil {
		if b, rErr := injicertify.RenderCredentialPDF(title, issuer, qrPayload, fields, order); rErr == nil {
			pdfBytes = b
		}
	}
	if pdfBytes == nil {
		// Format-aware note: only an SD-JWT is inherently un-scannable. A W3C
		// credential that lands here is merely large — never claim it is an SD-JWT.
		note := "This credential is too large to embed in a scannable QR code. The " +
			"full credential is printed below and remains in your wallet — present it " +
			"digitally rather than by scanning this page."
		if !injiIsW3C(vc) {
			note = "This credential is an SD-JWT, which is too large to embed in a " +
				"scannable QR code (a known limitation of the SD-JWT format). The full " +
				"credential is printed below and remains in your wallet — present it " +
				"digitally rather than by scanning this page."
		}
		credText, _ := parsed["VC"].(string)
		if credText == "" {
			credText = vc
		}
		b, err := injicertify.RenderCredentialPDFNoQR(title, issuer, note, fields, order, credText)
		if err != nil {
			http.Error(w, "render pdf: "+err.Error(), http.StatusInternalServerError)
			return
		}
		pdfBytes = b
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="credential-`+id+`.pdf"`)
	_, _ = w.Write(pdfBytes)
}
