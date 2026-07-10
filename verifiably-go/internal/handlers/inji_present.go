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
	"regexp"
	"sort"
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
	// Consent/matching fields parsed from the presentation_definition's first
	// input_descriptor (F24 — the holder-side consent flow needs them).
	DescName        string   // input_descriptor.name — the verifier's label for the requested credential
	Format          string   // requested format key ("vc+sd-jwt" / "ldp_vp" / "jwt_vc_json")
	RequestedFields []string // claim names requested (from constraints.fields paths, excluding $.vct)
	VctPattern      string   // the $.vct filter.pattern, when present (SD-JWT matching)
}

// injiFieldNameFromPaths returns the claim name from a PD field's JSONPath list
// (e.g. ["$.last_name","$.credentialSubject.last_name"] -> "last_name",
// ["$.vct"] -> "vct"): the last dotted segment of the first usable path.
func injiFieldNameFromPaths(paths []string) string {
	for _, p := range paths {
		p = strings.TrimPrefix(p, "$.")
		if i := strings.LastIndex(p, "."); i >= 0 {
			p = p[i+1:]
		}
		if p != "" {
			return p
		}
	}
	return ""
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
				ID          string                     `json:"id"`
				Name        string                     `json:"name"`
				Format      map[string]json.RawMessage `json:"format"`
				Constraints struct {
					Fields []struct {
						Path   []string `json:"path"`
						Filter struct {
							Pattern string `json:"pattern"`
						} `json:"filter"`
					} `json:"fields"`
				} `json:"constraints"`
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
		d := claims.PresentationDefinition.InputDescriptors[0]
		jar.DescID = d.ID
		jar.DescName = d.Name
		for k := range d.Format {
			jar.Format = k // one format entry per descriptor
		}
		seen := map[string]bool{}
		for _, f := range d.Constraints.Fields {
			name := injiFieldNameFromPaths(f.Path)
			if name == "vct" {
				if f.Filter.Pattern != "" {
					jar.VctPattern = f.Filter.Pattern
				}
				continue
			}
			if name != "" && !seen[name] {
				seen[name] = true
				jar.RequestedFields = append(jar.RequestedFields, name)
			}
		}
	}
	if jar.ResponseURI == "" || jar.Nonce == "" {
		return jar, fmt.Errorf("request object missing nonce/response_uri")
	}
	return jar, nil
}

// injiDirectPost submits the vp_token to Inji Verify's response_uri
// (response_mode=direct_post, application/x-www-form-urlencoded). descFormat is
// the presentation_submission descriptor format — "vc+sd-jwt" for an SD-JWT
// KB-JWT vp_token, "ldp_vp" for a JSON-LD VerifiablePresentation.
func (h *H) injiDirectPost(ctx context.Context, jar injiJAR, vpToken, descFormat string) error {
	submission := map[string]any{
		"id":            "sub-" + randB64(8),
		"definition_id": jar.PDID,
		"descriptor_map": []map[string]any{
			{"id": jar.DescID, "format": descFormat, "path": "$"},
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

// injiIsW3C reports whether a held credential is a W3C JSON-LD object (ldp_vc)
// rather than a compact SD-JWT (issuer-jwt~disclosure~…).
func injiIsW3C(held string) bool { return strings.HasPrefix(strings.TrimSpace(held), "{") }

// injiW3CTitle returns the credential's human type (the non-"VerifiableCredential"
// entry of `type`), for the request template + the pair-leg label.
func injiW3CTitle(held string) string {
	var vc map[string]any
	if json.Unmarshal([]byte(held), &vc) != nil {
		return "In-app Inji credential"
	}
	switch t := vc["type"].(type) {
	case []any:
		for _, v := range t {
			if s, _ := v.(string); s != "" && s != "VerifiableCredential" {
				return s
			}
		}
	case string:
		if t != "" && t != "VerifiableCredential" {
			return t
		}
	}
	return "In-app Inji credential"
}

// injiW3CFields returns the credential's disclosed claim names (credentialSubject
// keys except `id`), sorted for a deterministic request.
func injiW3CFields(held string) []string {
	var vc map[string]any
	if json.Unmarshal([]byte(held), &vc) != nil {
		return nil
	}
	cs, _ := vc["credentialSubject"].(map[string]any)
	out := make([]string, 0, len(cs))
	for k := range cs {
		if k != "id" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// injiBuildW3CVPToken wraps a held W3C ldp_vc in an UNSIGNED VerifiablePresentation
// and returns it as a JSON string. Inji Verify accepts an ldp_vp without a
// VP-level proof (proven empirically) — it verifies the wrapped credential's own
// issuer Data-Integrity proof — so no holder key / VP signature is needed, and
// existing ES256-bound Inji W3C credentials present as-is.
func injiBuildW3CVPToken(held string) (string, error) {
	var vc map[string]any
	if err := json.Unmarshal([]byte(held), &vc); err != nil {
		return "", fmt.Errorf("inji present: W3C credential is not JSON: %w", err)
	}
	vp := map[string]any{
		"@context": []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		"type":                 []string{"VerifiablePresentation"},
		"verifiableCredential": []any{vc},
	}
	if cs, ok := vc["credentialSubject"].(map[string]any); ok {
		if holder, _ := cs["id"].(string); holder != "" {
			vp["holder"] = holder
		}
	}
	b, err := json.Marshal(vp)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// injiPresentLabel labels a held credential in the pair result: its vct (SD-JWT)
// or its type (W3C).
func injiPresentLabel(held string) string {
	if injiIsW3C(held) {
		return injiW3CTitle(held)
	}
	return injiSDJWTVct(held)
}

// injiHeldFieldValue returns a held credential's value for a claim name — from
// credentialSubject for W3C, or from the matching SD-JWT disclosure. Empty when
// the credential doesn't carry the claim.
func injiHeldFieldValue(held, field string) string {
	if injiIsW3C(held) {
		var vc map[string]any
		if json.Unmarshal([]byte(held), &vc) == nil {
			if cs, ok := vc["credentialSubject"].(map[string]any); ok {
				if v, ok := cs[field]; ok {
					return fmt.Sprintf("%v", v)
				}
			}
		}
		return ""
	}
	for _, d := range strings.Split(held, "~")[1:] {
		if d == "" || strings.Count(d, ".") == 2 {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(d)
		if err != nil {
			continue
		}
		var arr []any
		if json.Unmarshal(raw, &arr) == nil && len(arr) == 3 {
			if name, _ := arr[1].(string); name == field {
				return fmt.Sprintf("%v", arr[2])
			}
		}
	}
	return ""
}

// injiMatchHeld reports whether a held credential satisfies the verifier's
// request: the format must line up (vc+sd-jwt↔SD-JWT, ldp_vp↔W3C) and, for
// SD-JWT, the held vct must match the request's $.vct pattern. Returns a
// human-readable reason when it doesn't (rendered on the consent card).
func injiMatchHeld(jar injiJAR, held string) (bool, string) {
	isW3C := injiIsW3C(held)
	switch jar.Format {
	case "vc+sd-jwt":
		if isW3C {
			return false, "the verifier is requesting an SD-JWT credential, but this one is W3C (ldp_vc)"
		}
	case "ldp_vp":
		if !isW3C {
			return false, "the verifier is requesting a W3C (ldp_vp) credential, but this one is an SD-JWT"
		}
	}
	if !isW3C && jar.VctPattern != "" {
		vct := injiSDJWTVct(held)
		if ok, err := regexp.MatchString(jar.VctPattern, vct); err != nil || !ok {
			return false, fmt.Sprintf("this credential's type does not match what the verifier asked for (%s)", vct)
		}
	}
	return true, ""
}

// injiPresentPreview builds the consent-card model for presenting `held` against
// the resolved request `jar` — the verifier, the credential, the requested
// claims (with the values that would be shared), and whether they're compatible.
func injiPresentPreview(jar injiJAR, credID, held string) backend.PresentationPreview {
	title := jar.DescName
	if title == "" {
		title = injiPresentLabel(held)
	}
	compatible, reason := injiMatchHeld(jar, held)
	fields := make([]backend.PresentationField, 0, len(jar.RequestedFields))
	for _, name := range jar.RequestedFields {
		fields = append(fields, backend.PresentationField{
			Name:     name,
			Value:    injiHeldFieldValue(held, name),
			Required: true,
		})
	}
	return backend.PresentationPreview{
		VerifierClientID:   jar.Aud,
		CredentialID:       credID,
		CredentialTitle:    title,
		Fields:             fields,
		RequestedFormat:    jar.Format,
		Compatible:         compatible,
		IncompatibleReason: reason,
		Disclosure:         "none", // the Inji present shares the whole credential
	}
}

// presentHeldToInjiVerify runs the OID4VP holder leg for one held credential:
// create the request at Inji Verify (via the Inji Verify adapter), fetch the
// signed request object, build the vp_token, direct-post it, and return the
// polled verdict. Branches on format — SD-JWT → a key-bound KB-JWT vp_token;
// W3C ldp_vc → an unsigned ldp_vp. Shared by the single present (F21/F23) and
// the delegated pair (F22/F23).
func (h *H) presentHeldToInjiVerify(ctx context.Context, held string, key *ecdsa.PrivateKey) (backend.VerificationResult, error) {
	var tpl vctypes.OID4VPTemplate
	var descFormat string
	buildToken := func(injiJAR) (string, error) { return "", fmt.Errorf("inji present: unsupported format") }
	if injiIsW3C(held) {
		tpl = vctypes.OID4VPTemplate{
			Title:      injiW3CTitle(held),
			Fields:     injiW3CFields(held),
			Format:     "w3c_vcdm_2",
			WireFormat: "ldp_vp",
		}
		descFormat = "ldp_vp"
		buildToken = func(injiJAR) (string, error) { return injiBuildW3CVPToken(held) }
	} else {
		tpl = vctypes.OID4VPTemplate{
			Title:      "In-app Inji credential",
			Fields:     injiSDJWTDisclosureFields(held),
			Format:     "sd_jwt_vc (IETF)",
			Vct:        injiSDJWTVct(held),
			WireFormat: "vc+sd-jwt",
		}
		descFormat = "vc+sd-jwt"
		buildToken = func(jar injiJAR) (string, error) { return injiBuildVPToken(held, key, jar.Nonce, jar.Aud) }
	}
	res, err := h.Adapter.RequestPresentation(ctx, backend.PresentationRequest{
		VerifierDpg: injiVerifyVendor,
		Template:    &tpl,
	})
	if err != nil {
		return backend.VerificationResult{}, fmt.Errorf("request presentation: %w", err)
	}
	jar, err := h.fetchInjiVPRequest(ctx, res.RequestURI)
	if err != nil {
		return backend.VerificationResult{}, fmt.Errorf("fetch request: %w", err)
	}
	vpToken, err := buildToken(jar)
	if err != nil {
		return backend.VerificationResult{}, fmt.Errorf("build vp_token: %w", err)
	}
	if err := h.injiDirectPost(ctx, jar, vpToken, descFormat); err != nil {
		return backend.VerificationResult{}, err
	}
	verdict, err := h.Adapter.FetchPresentationResult(ctx, res.State, "custom")
	if err != nil {
		return backend.VerificationResult{}, fmt.Errorf("fetch result: %w", err)
	}
	return verdict, nil
}

// injiHeldPresentable looks up a held in-app Inji credential by id that can be
// presented over OID4VP: an SD-JWT (with its retained holder key, for the KB-JWT)
// or a W3C ldp_vc (no key — presented as an unsigned ldp_vp). key is nil for W3C.
func injiHeldPresentable(sess *Session, id string) (held string, key *ecdsa.PrivateKey, ok bool) {
	for _, vc := range sess.InjiClaimedVCs {
		if vcID(vc) == id {
			held = vc
			break
		}
	}
	if held == "" {
		return "", nil, false
	}
	if injiIsW3C(held) {
		return held, nil, true
	}
	keyPEM := sess.InjiHolderKeys[id]
	if keyPEM == "" || !strings.Contains(held, "~") {
		return "", nil, false
	}
	k, err := parseECKeyPEM(keyPEM)
	if err != nil {
		return "", nil, false
	}
	return held, k, true
}

// SubmitInjiPresentPair presents EVERY held presentable SD-JWT credential to
// Inji Verify as its own single-credential OID4VP VP (the F21 leg, once per
// credential), then combines the results: the held set is evaluated by the
// DPG-agnostic delegation evaluator into ONE delegated-access verdict (linkage /
// invocation / capability / revocation). This is the "two single VPs, combined"
// delegated-pair route — Inji Verify can't honour a true multi-credential pair
// request (injiverify/adapter.go), so verifiably presents each leg singly and
// reasons over the pair itself.
func (h *H) SubmitInjiPresentPair(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)

	type held struct {
		id, compact string
		key         *ecdsa.PrivateKey
	}
	var creds []held
	for _, vc := range sess.InjiClaimedVCs {
		id := vcID(vc)
		if c, k, ok := injiHeldPresentable(sess, id); ok {
			creds = append(creds, held{id: id, compact: c, key: k})
		}
	}
	if len(creds) < 2 {
		h.renderInjiPresentPair(w, r, nil, nil,
			"A delegated pair needs at least two presentable credentials in your wallet — a subject identity and a delegation (a credential with an onBehalfOf field). Claim both, then try again.")
		return
	}

	ctx := r.Context()
	allValid := true
	legs := make([]map[string]any, 0, len(creds))
	compacts := make([]string, 0, len(creds))
	for _, c := range creds {
		verdict, err := h.presentHeldToInjiVerify(ctx, c.compact, c.key)
		legOK := err == nil && verdict.Valid
		if !legOK {
			allValid = false
		}
		leg := map[string]any{"Vct": injiPresentLabel(c.compact), "OK": legOK}
		if err != nil {
			leg["Err"] = err.Error()
		}
		legs = append(legs, leg)
		compacts = append(compacts, c.compact)
	}

	// Combine: evaluate the presented set for delegated access. Each credential's
	// authenticity was just checked by Inji Verify; attachDelegationVerdict adds
	// the temporal + revocation gates and the delegation semantics.
	res := backend.VerificationResult{
		Credentials:   normalizeClaimedInjiCreds(compacts),
		HolderBinding: &backend.HolderBinding{Confirmed: true},
		Valid:         allValid && len(compacts) > 0,
	}
	h.attachDelegationVerdict(r, &res)
	h.renderInjiPresentPair(w, r, legs, &res, "")
}

// renderInjiPresentPair renders the delegated-pair verdict fragment: the per-leg
// Inji Verify outcomes plus the combined delegated-access card.
func (h *H) renderInjiPresentPair(w http.ResponseWriter, r *http.Request, legs []map[string]any, res *backend.VerificationResult, errMsg string) {
	data := map[string]any{"Legs": legs, "Error": errMsg}
	if res != nil {
		data["Delegation"] = res.Delegation
		data["AllValid"] = res.Valid
	}
	h.renderFragment(w, r, "fragment_inji_present_pair", map[string]any{"Body": data, "Lang": h.langFor(r)})
}

// ─── F24: real consent-based OID4VP present (respond to a verifier's request) ──

// injiNormalizeRequestURI cleans a pasted OID4VP request: unescapes &amp; (if
// copied from HTML) and wraps a bare request_uri (an https URL) in an
// openid4vp:// envelope so fetchInjiVPRequest's query parse finds it.
func injiNormalizeRequestURI(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "&amp;", "&")
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return "openid4vp://authorize?request_uri=" + url.QueryEscape(s)
	}
	return s
}

// injiCredTitle is a compact human title for the wallet picker: the type for
// W3C, the vct's last path segment for SD-JWT.
func injiCredTitle(vc string) string {
	if injiIsW3C(vc) {
		return injiW3CTitle(vc)
	}
	vct := injiSDJWTVct(vc)
	if i := strings.LastIndex(vct, "/"); i >= 0 && i+1 < len(vct) {
		return vct[i+1:]
	}
	return vct
}

// injiPresentableCredsForPicker returns the held presentable Inji credentials as
// {ID, Title, Format} rows for the "Present a request" picker.
func (h *H) injiPresentableCredsForPicker(sess *Session) []map[string]any {
	out := []map[string]any{}
	for _, vc := range sess.InjiClaimedVCs {
		id := vcID(vc)
		if _, _, ok := injiHeldPresentable(sess, id); !ok {
			continue
		}
		format := "vc+sd-jwt"
		if injiIsW3C(vc) {
			format = "ldp_vp"
		}
		out = append(out, map[string]any{"ID": id, "Title": injiCredTitle(vc), "Format": format})
	}
	return out
}

// injiBuildVPTokenFor builds the vp_token for a held credential bound to the
// request's nonce/aud, returning the token and its presentation_submission
// format. SD-JWT → KB-JWT vp_token (vc+sd-jwt); W3C → unsigned ldp_vp.
func injiBuildVPTokenFor(held string, key *ecdsa.PrivateKey, jar injiJAR) (string, string, error) {
	if injiIsW3C(held) {
		tok, err := injiBuildW3CVPToken(held)
		return tok, "ldp_vp", err
	}
	tok, err := injiBuildVPToken(held, key, jar.Nonce, jar.Aud)
	return tok, "vc+sd-jwt", err
}

// ShowInjiPresentRequest renders the "Present a request" entry screen: paste the
// verifier's openid4vp:// request + pick a held credential. This is the real
// OID4VP holder UX (the verifier generates the request elsewhere; the wallet
// resolves it, shows consent, and submits) — as opposed to the one-click demo.
func (h *H) ShowInjiPresentRequest(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	h.render(w, r, "holder_inji_present", h.pageData(sess, map[string]any{
		"Credentials":           h.injiPresentableCredsForPicker(sess),
		"PreselectCredentialID": r.URL.Query().Get("credential"),
	}))
}

// ConfirmInjiPresentRequest resolves the verifier's request + the picked
// credential and renders the consent card (what will be disclosed to whom).
func (h *H) ConfirmInjiPresentRequest(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	credID := r.FormValue("credential_id")
	reqURI := injiNormalizeRequestURI(r.FormValue("request_uri"))
	if credID == "" || reqURI == "" {
		h.errorToast(w, r, "Pick a credential and paste the verifier's request URI")
		return
	}
	held, _, ok := injiHeldPresentable(sess, credID)
	if !ok {
		h.errorToast(w, r, "That credential can't be presented over OID4VP.")
		return
	}
	jar, err := h.fetchInjiVPRequest(r.Context(), reqURI)
	if err != nil {
		h.errorToast(w, r, "Couldn't read the verifier's request: "+err.Error())
		return
	}
	h.renderFragment(w, r, "fragment_inji_present_consent", map[string]any{
		"Preview":    injiPresentPreview(jar, credID, held),
		"RequestURI": reqURI,
		"Lang":       h.langFor(r),
	})
}

// SubmitInjiPresentRequest builds the presentation for the picked credential and
// direct-posts it to the verifier's response_uri (the holder clicked Disclose).
func (h *H) SubmitInjiPresentRequest(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	credID := r.FormValue("credential_id")
	reqURI := injiNormalizeRequestURI(r.FormValue("request_uri"))
	if credID == "" || reqURI == "" {
		h.errorToast(w, r, "Pick a credential and paste the verifier's request URI")
		return
	}
	held, key, ok := injiHeldPresentable(sess, credID)
	if !ok {
		h.errorToast(w, r, "That credential can't be presented over OID4VP.")
		return
	}
	jar, err := h.fetchInjiVPRequest(r.Context(), reqURI)
	if err != nil {
		h.errorToast(w, r, "Couldn't read the verifier's request: "+err.Error())
		return
	}
	if match, reason := injiMatchHeld(jar, held); !match {
		h.errorToast(w, r, reason)
		return
	}
	vpToken, descFormat, err := injiBuildVPTokenFor(held, key, jar)
	if err != nil {
		h.errorToast(w, r, "Build presentation: "+err.Error())
		return
	}
	if err := h.injiDirectPost(r.Context(), jar, vpToken, descFormat); err != nil {
		h.errorToast(w, r, "Submit presentation: "+err.Error())
		return
	}
	title := jar.DescName
	if title == "" {
		title = injiCredTitle(held)
	}
	h.renderFragment(w, r, "fragment_inji_present_shared", map[string]any{
		"Title":            title,
		"VerifierClientID": jar.Aud,
		"Lang":             h.langFor(r),
	})
}

// DeclineInjiPresent cancels the consent interstitial.
func (h *H) DeclineInjiPresent(w http.ResponseWriter, r *http.Request) {
	h.renderFragment(w, r, "fragment_inji_present_declined", map[string]any{"Lang": h.langFor(r)})
}
