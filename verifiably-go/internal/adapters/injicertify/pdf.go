package injicertify

// pdf.go — direct-to-PDF issuance for Inji Certify pre-auth.
//
// Flow when the operator picks "As a PDF" at /issuer/mode with an Inji
// Certify Pre-Auth DPG:
//
//   1. POST /v1/certify/pre-authorized-data with the claims → credential
//      offer URI with a pre-auth code.
//   2. POST /v1/certify/oauth/token (grant_type=pre-authorized_code) →
//      access_token + c_nonce.
//   3. POST /v1/certify/issuance/credential with an adapter-signed proof
//      JWT (ES256, jwk-only header, no `iss` per OID4VCI §7.2.1.1 for
//      anonymous pre-auth) → signed VC.
//   4. Render a one-page A4 PDF: title, issuer line, the subject's
//      human-readable claims, and a QR that embeds the raw VC. Stash the
//      bytes on the adapter; /issuer/issue/pdf/{id} serves them.
//
// The proof is signed with an adapter-held P-256 keypair — the subject
// never types anything or holds a wallet. The PDF IS the credential; the
// QR inside it is the machine-readable form (the same VC any OID4VCI
// wallet would receive), the rest of the page is for human eyes.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
	qr "github.com/skip2/go-qrcode"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/injidid"
)

// tokenResponse is the relevant slice of Inji's /oauth/token reply.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	CNonce      string `json:"c_nonce"`
}

// IssueAsPDFPreAuth drives the full pre-auth dance server-side and returns
// both an IssueAsPDFResult (metadata the UI displays) and the stored
// DownloadID that the serve-pdf route uses. Called from IssueAsPDF below
// only when cfg.Mode == ModePreAuth.
func (a *Adapter) issueAsPDFPreAuth(ctx context.Context, req backend.IssueRequest) (backend.IssueAsPDFResult, error) {
	if a.cfg.Mode != ModePreAuth {
		return backend.IssueAsPDFResult{}, backend.ErrNotSupported
	}
	a.initPdfKey()

	// 1. Stage the offer.
	claims := map[string]any{}
	for k, v := range req.SubjectData {
		claims[k] = v
	}
	if len(claims) == 0 {
		claims["fullName"] = "Demo Holder"
	}
	staged := preAuthorizedDataRequest{
		CredentialConfigurationId: req.Schema.ID,
		Claims:                    claims,
	}
	var stageResp preAuthorizedDataResponse
	if err := a.client.DoJSON(ctx, http.MethodPost, "/v1/certify/pre-authorized-data", staged, &stageResp, nil); err != nil {
		return backend.IssueAsPDFResult{}, fmt.Errorf("stage pre-auth offer: %w", err)
	}

	// 2. Extract the pre-auth code from the offer JSON Inji hosts.
	offerJSONURL, err := extractOfferDataURL(stageResp.CredentialOfferURI, a.cfg.InternalBaseURL, a.cfg.PublicBaseURL)
	if err != nil {
		return backend.IssueAsPDFResult{}, err
	}
	code, issuerURL, err := fetchPreAuthCode(ctx, offerJSONURL)
	if err != nil {
		return backend.IssueAsPDFResult{}, err
	}
	// 3. Redeem the pre-auth code for an access token.
	tok, err := a.redeemPreAuthCode(ctx, code)
	if err != nil {
		return backend.IssueAsPDFResult{}, err
	}

	// 4. Build a proof JWT and POST the credential request. The proof `aud` MUST
	// equal Certify's credential_issuer (mosip_certify_domain_url). issuerURL is
	// exactly that — the credential_issuer the offer advertised — so it's correct
	// in BOTH modes: the docker-internal host in legacy host:port mode, and the
	// public subdomain once PREAUTH_PUBLIC_URL is set. Previously hardcoded to
	// InternalBaseURL, which broke the PDF path the moment the domain went public.
	issuerIdentifier := strings.TrimRight(issuerURL, "/")
	if issuerIdentifier == "" {
		issuerIdentifier = strings.TrimRight(a.cfg.InternalBaseURL, "/")
	}
	if issuerIdentifier == "" {
		issuerIdentifier = strings.TrimRight(a.cfg.BaseURL, "/")
	}
	proof, err := a.buildProofJWT(issuerIdentifier, tok.CNonce)
	if err != nil {
		return backend.IssueAsPDFResult{}, fmt.Errorf("sign proof: %w", err)
	}
	vc, format, err := a.requestCredential(ctx, tok.AccessToken, req.Schema.ID, proof)
	if err != nil {
		return backend.IssueAsPDFResult{}, err
	}
	_ = format
	// Feed the VC through the pre-auth observer so
	// /inji-proxy-preauth/.well-known/did.json (served as
	// did:web:certify-preauth-nginx) includes whichever kid this
	// pre-auth instance used to sign. Primary observer is untouched —
	// the two DIDs have separate key sets.
	injidid.Preauth.Remember([]byte(vc))

	// 5. Encode the VC into MOSIP PixelPass format (CBOR → zlib → base45)
	// so Inji Verify's QR decoder accepts it. Raw JSON starting with `{`
	// trips its base45 decoder with "Invalid character at position 0".
	qrPayload, err := encodePixelPass([]byte(vc))
	if err != nil {
		return backend.IssueAsPDFResult{}, fmt.Errorf("encode pixelpass: %w", err)
	}

	// 6. Render the PDF and stash it for the download route.
	pdfBytes, err := renderCredentialPDF(req.Schema.Name, a.Vendor, qrPayload, req.SubjectData, fieldOrder(req))
	if err != nil {
		return backend.IssueAsPDFResult{}, fmt.Errorf("render pdf: %w", err)
	}
	id := randomID()
	a.mu.Lock()
	if a.pdfBlobs == nil {
		a.pdfBlobs = map[string][]byte{}
	}
	a.pdfBlobs[id] = pdfBytes
	a.mu.Unlock()

	_ = format // reserved for future per-format rendering branches
	return backend.IssueAsPDFResult{
		IssuerName:    a.Vendor,
		IssuerDID:     issuerDIDFromVC(vc, a.cfg.DB.DIDUrl), // the credential's ACTUAL signing DID
		PayloadSizeKB: (len(vc) + 512) / 1024,
		Fields:        req.SubjectData,
		DownloadID:    id,
	}, nil
}

// issuerDIDFromVC reads the issuer DID from the freshly-signed VC for the PDF's
// (informational) issuer line, so it reflects the credential's REAL issuer
// instead of a hardcoded guess. The pre-auth instance now signs under its own
// public did:web (did:web:inji-certify-preauth.<domain>), not the primary
// instance's did:web:certify-nginx. `issuer` may be a bare DID string or an
// {id,...} object; fall back to the configured DB.DIDUrl, then a generic label.
func issuerDIDFromVC(vc, fallback string) string {
	var doc struct {
		Issuer json.RawMessage `json:"issuer"`
	}
	if json.Unmarshal([]byte(vc), &doc) == nil && len(doc.Issuer) > 0 {
		var s string
		if json.Unmarshal(doc.Issuer, &s) == nil && s != "" {
			return s
		}
		var obj struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(doc.Issuer, &obj) == nil && obj.ID != "" {
			return obj.ID
		}
	}
	if fallback != "" {
		return fallback
	}
	return "Inji Certify (Pre-Auth)"
}

// extractOfferDataURL unwraps the openid-credential-offer:// envelope Inji
// returns, then swaps the public host for the docker-internal one so this
// process (inside the verifiably-go container) can actually GET the offer
// JSON. Falls back to the raw URL on parse failure.
func extractOfferDataURL(offerURI, internal, public string) (string, error) {
	if offerURI == "" {
		return "", fmt.Errorf("pre-auth response had empty credential_offer_uri")
	}
	u, err := url.Parse(offerURI)
	if err == nil {
		if inner := u.Query().Get("credential_offer_uri"); inner != "" {
			offerURI = inner
		}
	}
	if internal != "" && public != "" {
		offerURI = strings.ReplaceAll(offerURI, public, internal)
	}
	return offerURI, nil
}

// fetchPreAuthCode fetches the offer JSON Inji staged and extracts the
// pre-authorized_code + credential_issuer.
func fetchPreAuthCode(ctx context.Context, url string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("fetch offer: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("offer fetch %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var offer struct {
		CredentialIssuer string `json:"credential_issuer"`
		Grants           map[string]struct {
			PreAuthorizedCode string `json:"pre-authorized_code"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(body, &offer); err != nil {
		return "", "", fmt.Errorf("parse offer: %w", err)
	}
	grant, ok := offer.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
	if !ok || grant.PreAuthorizedCode == "" {
		return "", "", fmt.Errorf("offer had no pre-authorized_code grant")
	}
	return grant.PreAuthorizedCode, offer.CredentialIssuer, nil
}

// redeemPreAuthCode POSTs to Inji's token endpoint and returns the parsed
// response. Inji serves the pre-auth token endpoint under
// /v1/certify/oauth/token (NOT /v1/certify/issuance/token).
func (a *Adapter) redeemPreAuthCode(ctx context.Context, code string) (*tokenResponse, error) {
	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {code},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(a.cfg.BaseURL, "/")+"/v1/certify/oauth/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token: %s", truncate(string(body), 200))
	}
	return &tok, nil
}

// requestCredential POSTs the proof + access token to Inji's credential
// endpoint and returns the raw VC (string/JWT form) plus the format string.
// For ldp_vc credentials Inji returns a JSON-LD VC object; for
// vc+sd-jwt it returns a compact SD-JWT string. We pass both through as a
// string since the QR just encodes bytes.
func (a *Adapter) requestCredential(ctx context.Context, accessToken, configID, proofJWT string) (string, string, error) {
	// Fetch Inji's metadata generically so we can read @context verbatim
	// from credential_definition — the typed adapter-level DTO doesn't
	// capture that field, and Inji's isValidLdpVCRequest requires
	// set-equality between the request's @context and the advertised one.
	mreq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(a.cfg.BaseURL, "/")+"/v1/certify/issuance/.well-known/openid-credential-issuer", nil)
	if err != nil {
		return "", "", err
	}
	mresp, err := http.DefaultClient.Do(mreq)
	if err != nil {
		return "", "", fmt.Errorf("fetch metadata: %w", err)
	}
	defer mresp.Body.Close()
	mbody, _ := io.ReadAll(mresp.Body)
	if mresp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("metadata %d", mresp.StatusCode)
	}
	var meta map[string]any
	if err := json.Unmarshal(mbody, &meta); err != nil {
		return "", "", fmt.Errorf("parse metadata: %w", err)
	}
	configs, _ := meta["credential_configurations_supported"].(map[string]any)
	cfgAny, ok := configs[configID]
	if !ok {
		return "", "", fmt.Errorf("configuration %q not advertised by issuer", configID)
	}
	cfg, _ := cfgAny.(map[string]any)
	format, _ := cfg["format"].(string)

	reqBody := map[string]any{
		"format": format,
		"proof": map[string]any{
			"proof_type": "jwt",
			"jwt":        proofJWT,
		},
	}
	if format == "ldp_vc" {
		if cd, ok := cfg["credential_definition"].(map[string]any); ok {
			out := map[string]any{}
			if t, ok := cd["type"]; ok {
				out["type"] = t
			}
			if c, ok := cd["@context"]; ok {
				out["@context"] = c
			}
			reqBody["credential_definition"] = out
		}
	} else if vct, ok := cfg["vct"].(string); ok && vct != "" {
		reqBody["vct"] = vct
	}
	reqBytes, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(a.cfg.BaseURL, "/")+"/v1/certify/issuance/credential",
		bytes.NewReader(reqBytes))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("credential %d: %s", resp.StatusCode, truncate(string(body), 300))
	}

	// Response shape: {"credential": "...", "format": "...", ...}. For
	// ldp_vc the credential field is a JSON object; for SD-JWT / JWT it's
	// a compact string. We pass whatever it is through verbatim.
	var wrapper struct {
		Credential json.RawMessage `json:"credential"`
		Format     string          `json:"format"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return "", "", fmt.Errorf("parse credential response: %w", err)
	}
	vc := string(wrapper.Credential)
	// If the credential came as a JSON-encoded string, unwrap the quotes.
	if len(vc) >= 2 && vc[0] == '"' && vc[len(vc)-1] == '"' {
		var s string
		_ = json.Unmarshal(wrapper.Credential, &s)
		vc = s
	}
	return vc, wrapper.Format, nil
}

// buildProofJWT signs an ES256 JWT with the adapter-held P-256 key and
// returns its compact serialization. Header: {typ, alg, jwk}. Payload:
// {aud, iat, exp, nonce}. NO `iss` or `sub` — anonymous pre-auth context
// per OID4VCI §7.2.1.1. NO `kid` alongside `jwk` — avoids the
// PROOF_HEADER_AMBIGUOUS_KEY gate in Inji.
func (a *Adapter) buildProofJWT(audience, cNonce string) (string, error) {
	if a.pdfKey == nil {
		return "", fmt.Errorf("adapter pdf key not initialized")
	}
	pub := a.pdfKey.PublicKey
	xB := pub.X.Bytes()
	yB := pub.Y.Bytes()
	// P-256 coordinates are 32 bytes; left-pad if a leading zero got trimmed.
	xB = leftPad(xB, 32)
	yB = leftPad(yB, 32)
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xB),
		"y":   base64.RawURLEncoding.EncodeToString(yB),
	}
	header := map[string]any{
		"typ": "openid4vci-proof+jwt",
		"alg": "ES256",
		"jwk": jwk,
	}
	now := time.Now().Unix()
	payload := map[string]any{
		"aud": audience,
		"iat": now,
		"exp": now + 300,
	}
	if cNonce != "" {
		payload["nonce"] = cNonce
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, a.pdfKey, hash[:])
	if err != nil {
		return "", err
	}
	sig := append(leftPad(r.Bytes(), 32), leftPad(s.Bytes(), 32)...)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// initPdfKey lazily generates the adapter's proof-signing keypair. Same
// key re-used across PDF issuances in this process; restarting the
// verifiably-go container rotates it. Good enough for a demo; a prod
// deployment would persist + rotate.
func (a *Adapter) initPdfKey() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pdfKey != nil {
		return
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err == nil {
		a.pdfKey = k
	}
}

// PDFBlob returns the stored bytes for a previously-issued PDF credential,
// keyed by the id emitted in IssueAsPDFResult.DownloadID. Served to the
// browser through /issuer/issue/pdf/{id}.
func (a *Adapter) PDFBlob(id string) ([]byte, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.pdfBlobs[id]
	return b, ok
}

// renderCredentialPDF lays out a one-page A4 credential: centered title,
// issuer line, human-readable claim rows, and a QR encoding the
// PixelPass-formatted VC. Pure gofpdf + go-qrcode.
//
// QR is rendered at 1024×1024 PNG with error-correction Medium. High
// resolution matters because (a) the QR version for a typical VC is
// high-density, and (b) Inji Verify's upload path rejects files below
// 10KB — with the default 512×512 the PDF lands around 7KB. 1024×1024
// pushes the PNG alone past 10KB, so the final PDF clears the minimum
// comfortably while staying well under the 5MB ceiling.
func renderCredentialPDF(title, issuer, qrPayload string, fields map[string]string, order []string) ([]byte, error) {
	if len(qrPayload) == 0 {
		return nil, fmt.Errorf("empty credential")
	}
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	// Header: issuer name + title.
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(120, 120, 120)
	pdf.CellFormat(0, 6, issuer, "", 1, "C", false, 0, "")
	pdf.SetFont("Helvetica", "B", 22)
	pdf.SetTextColor(40, 40, 40)
	pdf.CellFormat(0, 14, title, "", 1, "C", false, 0, "")
	pdf.Ln(4)

	// Divider.
	pdf.SetDrawColor(200, 200, 200)
	pdf.Line(30, pdf.GetY(), 180, pdf.GetY())
	pdf.Ln(6)

	// Claim rows.
	pdf.SetFont("Helvetica", "", 11)
	pdf.SetTextColor(70, 70, 70)
	keys := order
	if len(keys) == 0 {
		for k := range fields {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		v := fields[k]
		if v == "" {
			continue
		}
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(50, 7, humanizeKey(k)+":", "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 11)
		pdf.CellFormat(0, 7, v, "", 1, "L", false, 0, "")
	}
	pdf.Ln(6)

	// QR code. High recovery level (30% damage tolerance) both hardens
	// the QR against print-scan noise AND inflates the PNG — a deliberate
	// side effect that helps the final PDF clear Inji Verify's 10KB file
	// upload floor (their UI rejects anything under 10KB). 2048×2048 PNG
	// rendered at 90mm on the page gives plenty of margin in both
	// directions.
	png, err := qr.Encode(qrPayload, qr.High, 2048)
	if err != nil {
		return nil, fmt.Errorf("encode qr: %w", err)
	}
	imgName := "vc-qr"
	pdf.RegisterImageOptionsReader(imgName, gofpdf.ImageOptions{ImageType: "PNG"}, bytes.NewReader(png))
	const qrSize = 90.0 // mm — larger placement matches the higher-res source
	x := (210.0 - qrSize) / 2
	y := pdf.GetY()
	pdf.ImageOptions(imgName, x, y, qrSize, qrSize, false, gofpdf.ImageOptions{ImageType: "PNG"}, 0, "")
	pdf.SetY(y + qrSize + 4)
	pdf.SetFont("Helvetica", "I", 8)
	pdf.SetTextColor(140, 140, 140)
	pdf.CellFormat(0, 5, "Scan with Inji Verify (or any OID4VCI-compatible tool) to import this credential.", "", 1, "C", false, 0, "")
	pdf.Ln(4)

	// Footer.
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(160, 160, 160)
	pdf.CellFormat(0, 5, fmt.Sprintf("Issued %s via %s", time.Now().UTC().Format(time.RFC3339), issuer), "", 1, "C", false, 0, "")

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// fieldOrder returns the list of field names from the schema in the order
// declared by the issuer — preserves the human-friendly layout.
func fieldOrder(req backend.IssueRequest) []string {
	out := make([]string, 0, len(req.Schema.FieldsSpec))
	for _, f := range req.Schema.FieldsSpec {
		out = append(out, f.Name)
	}
	return out
}

// humanizeKey turns "fullName"/"full_name" into "Full Name" for display.
func humanizeKey(k string) string {
	k = strings.ReplaceAll(k, "_", " ")
	var b strings.Builder
	for i, r := range k {
		if i > 0 && r >= 'A' && r <= 'Z' && i-1 < len(k) && k[i-1] >= 'a' && k[i-1] <= 'z' {
			b.WriteRune(' ')
		}
		if i == 0 && r >= 'a' && r <= 'z' {
			r = r - 32
		}
		b.WriteRune(r)
	}
	return b.String()
}

func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

var _ = big.NewInt // keep math/big referenced even if future refactors trim usage.
