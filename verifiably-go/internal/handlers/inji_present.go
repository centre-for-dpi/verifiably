// F21 — OID4VP present from the in-app Inji web wallet to Inji Verify.
//
// The in-app Inji holder (/holder/wallet/inji) was hold-only. This adds a
// "Present to Inji Verify" flow for a held SD-JWT credential. verifiably plays
// BOTH roles of the round-trip so the demo is self-contained:
//   - verifier: creates the OID4VP request at Inji Verify via the Inji Verify
//     adapter (h.Adapter.RequestPresentation with VerifierDpg "Inji Verify").
//   - holder: fetches the signed request object (JAR), builds a vc+sd-jwt
//     vp_token = issuer SD-JWT + held disclosures + a fresh KB-JWT bound to the
//     request's nonce/aud (signed with the retained holder key), and
//     direct-posts it to the request's response_uri.
// It then polls the verdict via the same FetchPresentationResult the verifier
// UI uses and renders it.
package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// injiVerifyVendor is the backends.json vendor key for the Inji Verify adapter
// (matches the "Inji Verify" special-case already used in verifier.go).
const injiVerifyVendor = "Inji Verify"

// marshalECKeyPEM / parseECKeyPEM serialise the retained holder key.
func marshalECKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

func parseECKeyPEM(s string) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(s))
	if blk == nil {
		return nil, fmt.Errorf("inji present: holder key is not PEM")
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}

// injiSDJWTVct decodes the base-payload `vct` claim of a compact SD-JWT.
func injiSDJWTVct(compact string) string {
	seg := strings.Split(strings.Split(compact, "~")[0], ".")
	if len(seg) < 2 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(seg[1])
	if err != nil {
		return ""
	}
	var payload map[string]any
	if json.Unmarshal(b, &payload) != nil {
		return ""
	}
	if v, ok := payload["vct"].(string); ok {
		return v
	}
	return ""
}

// injiSDJWTDisclosureFields returns the disclosed claim names of a compact
// SD-JWT (each disclosure is base64url([salt, name, value]); a trailing KB-JWT
// has two dots and is skipped).
func injiSDJWTDisclosureFields(compact string) []string {
	out := []string{}
	for _, d := range strings.Split(compact, "~")[1:] {
		if d == "" || strings.Count(d, ".") == 2 {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(d)
		if err != nil {
			continue
		}
		var arr []any
		if json.Unmarshal(raw, &arr) == nil && len(arr) == 3 {
			if name, ok := arr[1].(string); ok {
				out = append(out, name)
			}
		}
	}
	return out
}

// injiBuildVPToken assembles a vc+sd-jwt vp_token from a held compact SD-JWT: the
// issuer-signed JWT, all held disclosures, and a fresh KB-JWT whose sd_hash
// covers the presentation and whose nonce/aud bind it to this verifier request.
// Any KB-JWT already on the held token is dropped and replaced.
func injiBuildVPToken(compact string, key *ecdsa.PrivateKey, nonce, aud string) (string, error) {
	parts := strings.Split(compact, "~")
	if len(parts) == 0 || parts[0] == "" {
		return "", fmt.Errorf("inji present: empty SD-JWT")
	}
	presentation := parts[0] + "~"
	for _, d := range parts[1:] {
		if d == "" || strings.Count(d, ".") == 2 { // skip empties + any existing KB-JWT
			continue
		}
		presentation += d + "~"
	}
	sum := sha256.Sum256([]byte(presentation))
	sdHash := base64.RawURLEncoding.EncodeToString(sum[:])
	kb, err := signES256(key,
		map[string]any{"alg": "ES256", "typ": "kb+jwt"},
		map[string]any{"nonce": nonce, "aud": aud, "iat": time.Now().Unix(), "sd_hash": sdHash})
	if err != nil {
		return "", err
	}
	return presentation + kb, nil
}

// injiJAR is the slim view of Inji Verify's signed request object (JAR) that the
// holder needs to respond.
type injiJAR struct {
	Nonce       string
	Aud         string // client_id — the KB-JWT audience
	ResponseURI string
	State       string
	PDID        string
	DescID      string
}

// fetchInjiVPRequest dereferences the request_uri embedded in an openid4vp://
// URI and decodes the signed request object's payload.
func (h *H) fetchInjiVPRequest(ctx context.Context, requestURI string) (injiJAR, error) {
	var jar injiJAR
	u, err := url.Parse(requestURI)
	if err != nil {
		return jar, fmt.Errorf("parse request uri: %w", err)
	}
	ru := u.Query().Get("request_uri")
	if ru == "" {
		return jar, fmt.Errorf("no request_uri in %q", requestURI)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ru, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return jar, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	segs := strings.Split(string(body), ".")
	if len(segs) < 2 {
		return jar, fmt.Errorf("request object is not a JWT (%d bytes)", len(body))
	}
	payload, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		return jar, fmt.Errorf("decode request object: %w", err)
	}
	var claims struct {
		Nonce                  string `json:"nonce"`
		ClientID               string `json:"client_id"`
		ResponseURI            string `json:"response_uri"`
		State                  string `json:"state"`
		PresentationDefinition struct {
			ID               string `json:"id"`
			InputDescriptors []struct {
				ID string `json:"id"`
			} `json:"input_descriptors"`
		} `json:"presentation_definition"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return jar, fmt.Errorf("parse request object: %w", err)
	}
	jar = injiJAR{
		Nonce:       claims.Nonce,
		Aud:         claims.ClientID,
		ResponseURI: claims.ResponseURI,
		State:       claims.State,
		PDID:        claims.PresentationDefinition.ID,
	}
	if len(claims.PresentationDefinition.InputDescriptors) > 0 {
		jar.DescID = claims.PresentationDefinition.InputDescriptors[0].ID
	}
	if jar.ResponseURI == "" || jar.Nonce == "" {
		return jar, fmt.Errorf("request object missing nonce/response_uri")
	}
	return jar, nil
}

// injiDirectPost submits the vp_token to Inji Verify's response_uri
// (response_mode=direct_post, application/x-www-form-urlencoded).
func (h *H) injiDirectPost(ctx context.Context, jar injiJAR, vpToken string) error {
	submission := map[string]any{
		"id":            "sub-" + randB64(8),
		"definition_id": jar.PDID,
		"descriptor_map": []map[string]any{
			{"id": jar.DescID, "format": "vc+sd-jwt", "path": "$"},
		},
	}
	psub, _ := json.Marshal(submission)
	form := url.Values{
		"vp_token":                {vpToken},
		"presentation_submission": {string(psub)},
		"state":                   {jar.State},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, jar.ResponseURI, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("direct-post %d: %s", resp.StatusCode, truncateForLog(string(b), 200))
	}
	return nil
}

// SubmitInjiPresent presents one held in-app Inji SD-JWT credential to Inji
// Verify over OID4VP and renders the verdict fragment.
func (h *H) SubmitInjiPresent(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	id := r.PathValue("id")

	var compact string
	for _, vc := range sess.InjiClaimedVCs {
		if vcID(vc) == id {
			compact = vc
			break
		}
	}
	keyPEM := sess.InjiHolderKeys[id]
	if compact == "" || keyPEM == "" || !strings.Contains(compact, "~") {
		h.renderInjiPresentResult(w, r, id, nil,
			"This credential can't be presented over OID4VP — it isn't an SD-JWT, or its holder key wasn't retained. Re-claim it, then present.")
		return
	}
	key, err := parseECKeyPEM(keyPEM)
	if err != nil {
		h.renderInjiPresentResult(w, r, id, nil, "holder key: "+err.Error())
		return
	}

	ctx := r.Context()
	tpl := vctypes.OID4VPTemplate{
		Title:      "In-app Inji credential",
		Fields:     injiSDJWTDisclosureFields(compact),
		Format:     "sd_jwt_vc (IETF)",
		Vct:        injiSDJWTVct(compact),
		WireFormat: "vc+sd-jwt",
	}
	res, err := h.Adapter.RequestPresentation(ctx, backend.PresentationRequest{
		VerifierDpg: injiVerifyVendor,
		Template:    &tpl,
	})
	if err != nil {
		h.renderInjiPresentResult(w, r, id, nil, "request presentation: "+err.Error())
		return
	}
	jar, err := h.fetchInjiVPRequest(ctx, res.RequestURI)
	if err != nil {
		h.renderInjiPresentResult(w, r, id, nil, "fetch request: "+err.Error())
		return
	}
	vpToken, err := injiBuildVPToken(compact, key, jar.Nonce, jar.Aud)
	if err != nil {
		h.renderInjiPresentResult(w, r, id, nil, "build vp_token: "+err.Error())
		return
	}
	if err := h.injiDirectPost(ctx, jar, vpToken); err != nil {
		h.renderInjiPresentResult(w, r, id, nil, err.Error())
		return
	}
	verdict, err := h.Adapter.FetchPresentationResult(ctx, res.State, "custom")
	if err != nil {
		h.renderInjiPresentResult(w, r, id, nil, "fetch result: "+err.Error())
		return
	}
	h.renderInjiPresentResult(w, r, id, &verdict, "")
}

// renderInjiPresentResult renders the OID4VP present verdict fragment.
func (h *H) renderInjiPresentResult(w http.ResponseWriter, r *http.Request, id string, verdict *backend.VerificationResult, errMsg string) {
	data := map[string]any{"ID": id, "Error": errMsg}
	if verdict != nil {
		data["Valid"] = verdict.Valid
		data["Disclosed"] = verdict.DisclosedFields
		data["Method"] = verdict.Method
		data["Format"] = verdict.Format
	}
	h.renderFragment(w, r, "fragment_inji_present_result", map[string]any{"Body": data, "Lang": h.langFor(r)})
}
