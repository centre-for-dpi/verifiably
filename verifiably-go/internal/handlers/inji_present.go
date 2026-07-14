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

// injiDescriptor is one input_descriptor of the presentation_definition: the
// credential the verifier is asking for in one slot of the request.
type injiDescriptor struct {
	ID              string   // input_descriptor.id — echoed in the presentation_submission descriptor_map
	Name            string   // input_descriptor.name — the verifier's label for this credential
	Format          string   // requested format key ("vc+sd-jwt" / "ldp_vp" / "jwt_vc_json")
	RequestedFields []string // claim names requested (constraints.fields paths, excluding $.vct)
	VctPattern      string   // the $.vct filter.pattern, when present (SD-JWT matching)
}

// injiJAR is the slim view of Inji Verify's signed request object (JAR) that the
// holder needs to respond.
type injiJAR struct {
	Nonce       string
	Aud         string // client_id — the KB-JWT audience
	ResponseURI string
	State       string
	PDID        string
	// Descriptors is EVERY input_descriptor of the presentation_definition — so a
	// delegated-access PAIR request (identity + delegation) is presented as a real
	// multi-credential VP, not just the first descriptor. len==1 is the ordinary
	// single-credential request.
	Descriptors []injiDescriptor
	// DescID/DescName/Format/RequestedFields/VctPattern mirror Descriptors[0] for
	// the single-credential path + backward-compat.
	DescID          string
	DescName        string
	Format          string
	RequestedFields []string
	VctPattern      string
}

// primary returns the first descriptor (the single-credential request's slot),
// reconstructing it from the mirrored scalars if Descriptors wasn't populated.
func (jar injiJAR) primary() injiDescriptor {
	if len(jar.Descriptors) > 0 {
		return jar.Descriptors[0]
	}
	return injiDescriptor{ID: jar.DescID, Name: jar.DescName, Format: jar.Format, RequestedFields: jar.RequestedFields, VctPattern: jar.VctPattern}
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
	for _, d := range claims.PresentationDefinition.InputDescriptors {
		desc := injiDescriptor{ID: d.ID, Name: d.Name}
		for k := range d.Format {
			desc.Format = k // one format entry per descriptor
		}
		seen := map[string]bool{}
		for _, f := range d.Constraints.Fields {
			name := injiFieldNameFromPaths(f.Path)
			if name == "vct" {
				if f.Filter.Pattern != "" {
					desc.VctPattern = f.Filter.Pattern
				}
				continue
			}
			if name != "" && !seen[name] {
				seen[name] = true
				desc.RequestedFields = append(desc.RequestedFields, name)
			}
		}
		jar.Descriptors = append(jar.Descriptors, desc)
	}
	if len(jar.Descriptors) > 0 { // mirror the first descriptor onto the scalars
		d := jar.Descriptors[0]
		jar.DescID, jar.DescName, jar.Format, jar.RequestedFields, jar.VctPattern = d.ID, d.Name, d.Format, d.RequestedFields, d.VctPattern
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
	return h.postVPResponse(ctx, jar, vpToken, []map[string]any{
		{"id": jar.DescID, "format": descFormat, "path": "$"},
	})
}

// injiDirectPostMulti submits a single VerifiablePresentation carrying MULTIPLE
// credentials (a delegated-access pair) with one descriptor_map entry per matched
// leg: format ldp_vp at "$" with a path_nested pointing into the i-th element of
// the presentation's verifiableCredential array. This is the shape Inji Verify's
// multi-input_descriptor verify accepts (proven by the F25 pair flow). legs must
// be in the same order as the credentials in vpToken's verifiableCredential array.
func (h *H) injiDirectPostMulti(ctx context.Context, jar injiJAR, vpToken string, legs []injiMatch) error {
	dm := make([]map[string]any, 0, len(legs))
	for i, leg := range legs {
		dm = append(dm, map[string]any{
			"id":     leg.Desc.ID,
			"format": "ldp_vp",
			"path":   "$",
			"path_nested": map[string]any{
				"format": "ldp_vc",
				"path":   fmt.Sprintf("$.verifiableCredential[%d]", i),
			},
		})
	}
	return h.postVPResponse(ctx, jar, vpToken, dm)
}

// postVPResponse direct-posts a vp_token + presentation_submission (built from the
// given descriptor_map) to Inji Verify's response_uri
// (response_mode=direct_post, application/x-www-form-urlencoded).
func (h *H) postVPResponse(ctx context.Context, jar injiJAR, vpToken string, descriptorMap []map[string]any) error {
	submission := map[string]any{
		"id":             "sub-" + randB64(8),
		"definition_id":  jar.PDID,
		"descriptor_map": descriptorMap,
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
	return injiBuildW3CVPTokenMulti([]string{held})
}

// injiBuildW3CVPTokenMulti wraps one OR MORE held W3C ldp_vc credentials in a
// single unsigned VerifiablePresentation (verifiableCredential array in the given
// order) — used for a delegated-access pair. The holder is taken from the first
// credential's credentialSubject.id. Element order MUST match the descriptor_map's
// path_nested indices (see injiDirectPostMulti).
func injiBuildW3CVPTokenMulti(helds []string) (string, error) {
	vcs := make([]any, 0, len(helds))
	holder := ""
	for _, held := range helds {
		var vc map[string]any
		if err := json.Unmarshal([]byte(held), &vc); err != nil {
			return "", fmt.Errorf("inji present: W3C credential is not JSON: %w", err)
		}
		vcs = append(vcs, vc)
		if holder == "" {
			if cs, ok := vc["credentialSubject"].(map[string]any); ok {
				if h, _ := cs["id"].(string); h != "" {
					holder = h
				}
			}
		}
	}
	vp := map[string]any{
		"@context": []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		"type":                 []string{"VerifiablePresentation"},
		"verifiableCredential": vcs,
	}
	if holder != "" {
		vp["holder"] = holder
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
	return injiMatchDescriptor(jar.primary(), held)
}

// injiMatchDescriptor reports whether a held credential is FORMAT-compatible with
// one descriptor (vc+sd-jwt↔SD-JWT, ldp_vp↔W3C, plus the SD-JWT $.vct pattern). It
// deliberately does NOT require the requested claim fields to be present — an
// absent field just renders as "(not in this credential)" on the consent card.
func injiMatchDescriptor(desc injiDescriptor, held string) (bool, string) {
	isW3C := injiIsW3C(held)
	switch desc.Format {
	case "vc+sd-jwt":
		if isW3C {
			return false, "the verifier is requesting an SD-JWT credential, but this one is W3C (ldp_vc)"
		}
	case "ldp_vp":
		if !isW3C {
			return false, "the verifier is requesting a W3C (ldp_vp) credential, but this one is an SD-JWT"
		}
	}
	if !isW3C && desc.VctPattern != "" {
		vct := injiSDJWTVct(held)
		if ok, err := regexp.MatchString(desc.VctPattern, vct); err != nil || !ok {
			return false, fmt.Sprintf("this credential's type does not match what the verifier asked for (%s)", vct)
		}
	}
	return true, ""
}

// injiDescriptorFits is the stricter check used to AUTO-ASSIGN one held credential
// to a descriptor in a multi-credential request: format-compatible AND (for W3C)
// every requested field is present in credentialSubject. The field-presence test
// is what lets the identity descriptor (testa_id/last_name) pick the identity
// credential and the delegation descriptor (onBehalfOf) pick the delegation one.
func injiDescriptorFits(desc injiDescriptor, held string) bool {
	if ok, _ := injiMatchDescriptor(desc, held); !ok {
		return false
	}
	if injiIsW3C(held) && len(desc.RequestedFields) > 0 {
		var vc map[string]any
		if json.Unmarshal([]byte(held), &vc) != nil {
			return false
		}
		cs, _ := vc["credentialSubject"].(map[string]any)
		for _, f := range desc.RequestedFields {
			if _, present := cs[f]; !present {
				return false
			}
		}
	}
	return true
}

// injiPresentPreview builds the consent-card model for presenting `held` against
// the resolved request `jar` — the verifier, the credential, the requested
// claims (with the values that would be shared), and whether they're compatible.
func injiPresentPreview(jar injiJAR, credID, held string) backend.PresentationPreview {
	return injiPresentPreviewDesc(jar.primary(), jar.Aud, credID, held)
}

// injiPresentPreviewDesc builds the consent-card model for one descriptor + the
// held credential matched to it (the verifier, the credential, the requested
// claims with the values that would be shared, compatibility).
func injiPresentPreviewDesc(desc injiDescriptor, aud, credID, held string) backend.PresentationPreview {
	title := desc.Name
	if title == "" {
		title = injiPresentLabel(held)
	}
	compatible, reason := injiMatchDescriptor(desc, held)
	fields := make([]backend.PresentationField, 0, len(desc.RequestedFields))
	for _, name := range desc.RequestedFields {
		fields = append(fields, backend.PresentationField{
			Name:     name,
			Value:    injiHeldFieldValue(held, name),
			Required: true,
		})
	}
	return backend.PresentationPreview{
		VerifierClientID:   aud,
		CredentialID:       credID,
		CredentialTitle:    title,
		Fields:             fields,
		RequestedFormat:    desc.Format,
		Compatible:         compatible,
		IncompatibleReason: reason,
		Disclosure:         "none", // the Inji present shares the whole credential
	}
}

// injiMatch is one descriptor of a multi-credential request paired with the held
// credential auto-assigned to it (Found=false when the holder holds no match).
type injiMatch struct {
	Desc   injiDescriptor
	CredID string
	Held   string
	Found  bool
}

// injiAutoMatch greedily assigns each descriptor a distinct held, presentable
// credential that fits it (injiDescriptorFits), in descriptor order. A held cred
// is used for at most one descriptor. This is what turns a delegated-pair request
// into the two credentials to present, with no manual picking.
func (h *H) injiAutoMatch(sess *Session, jar injiJAR) []injiMatch {
	used := map[string]bool{}
	out := make([]injiMatch, 0, len(jar.Descriptors))
	for _, desc := range jar.Descriptors {
		m := injiMatch{Desc: desc}
		for _, vc := range sess.InjiClaimedVCs {
			id := vcID(vc)
			if used[id] {
				continue
			}
			if _, _, ok := injiHeldPresentable(sess, id); !ok {
				continue
			}
			if injiDescriptorFits(desc, vc) {
				m.CredID, m.Held, m.Found = id, vc, true
				used[id] = true
				break
			}
		}
		out = append(out, m)
	}
	return out
}

// injiMultiPreview builds the per-credential consent previews for a multi-cred
// request, the ordered matched credential ids, and whether every descriptor found
// a compatible held credential.
func (h *H) injiMultiPreview(sess *Session, jar injiJAR) (previews []backend.PresentationPreview, credIDs []string, allMatched bool) {
	allMatched = true
	for _, m := range h.injiAutoMatch(sess, jar) {
		if !m.Found {
			allMatched = false
			title := m.Desc.Name
			if title == "" {
				title = "requested credential"
			}
			fields := make([]backend.PresentationField, 0, len(m.Desc.RequestedFields))
			for _, name := range m.Desc.RequestedFields {
				fields = append(fields, backend.PresentationField{Name: name, Required: true})
			}
			previews = append(previews, backend.PresentationPreview{
				VerifierClientID:   jar.Aud,
				CredentialTitle:    title,
				Fields:             fields,
				RequestedFormat:    m.Desc.Format,
				Compatible:         false,
				IncompatibleReason: "you don't hold a credential matching this part of the request",
				Disclosure:         "none",
			})
			continue
		}
		pv := injiPresentPreviewDesc(m.Desc, jar.Aud, m.CredID, m.Held)
		if !pv.Compatible {
			allMatched = false
		}
		previews = append(previews, pv)
		credIDs = append(credIDs, m.CredID)
	}
	return previews, credIDs, allMatched
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
	reqURI := injiNormalizeRequestURI(r.FormValue("request_uri"))
	if reqURI == "" {
		h.errorToast(w, r, "Paste the verifier's request URI")
		return
	}
	jar, err := h.fetchInjiVPRequest(r.Context(), reqURI)
	if err != nil {
		h.errorToast(w, r, "Couldn't read the verifier's request: "+err.Error())
		return
	}
	// Multi-credential request (e.g. a delegated-access pair): auto-match the
	// holder's held credentials to the descriptors — no manual pick — and show a
	// per-credential consent card.
	if len(jar.Descriptors) > 1 {
		previews, credIDs, allMatched := h.injiMultiPreview(sess, jar)
		h.renderFragment(w, r, "fragment_inji_present_consent", map[string]any{
			"Previews":         previews,
			"CredIDs":          credIDs,
			"AllMatched":       allMatched,
			"Multi":            true,
			"RequestURI":       reqURI,
			"VerifierClientID": jar.Aud,
			"Lang":             h.langFor(r),
		})
		return
	}
	// Single-credential request: use the credential the holder picked.
	credID := r.FormValue("credential_id")
	if credID == "" {
		h.errorToast(w, r, "Pick a credential to present")
		return
	}
	held, _, ok := injiHeldPresentable(sess, credID)
	if !ok {
		h.errorToast(w, r, "That credential can't be presented over OID4VP.")
		return
	}
	pv := injiPresentPreview(jar, credID, held)
	h.renderFragment(w, r, "fragment_inji_present_consent", map[string]any{
		"Previews":         []backend.PresentationPreview{pv},
		"CredIDs":          []string{credID},
		"AllMatched":       pv.Compatible,
		"Multi":            false,
		"RequestURI":       reqURI,
		"VerifierClientID": jar.Aud,
		"Lang":             h.langFor(r),
	})
}

// SubmitInjiPresentRequest builds the presentation for the picked credential and
// direct-posts it to the verifier's response_uri (the holder clicked Disclose).
func (h *H) SubmitInjiPresentRequest(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	reqURI := injiNormalizeRequestURI(r.FormValue("request_uri"))
	if reqURI == "" {
		h.errorToast(w, r, "Paste the verifier's request URI")
		return
	}
	jar, err := h.fetchInjiVPRequest(r.Context(), reqURI)
	if err != nil {
		h.errorToast(w, r, "Couldn't read the verifier's request: "+err.Error())
		return
	}
	if len(jar.Descriptors) > 1 {
		h.submitInjiMulti(w, r, sess, jar)
		return
	}

	credID := r.FormValue("credential_id")
	if credID == "" {
		h.errorToast(w, r, "Pick a credential to present")
		return
	}
	held, key, ok := injiHeldPresentable(sess, credID)
	if !ok {
		h.errorToast(w, r, "That credential can't be presented over OID4VP.")
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

// submitInjiMulti presents a multi-credential request (a delegated-access pair) as
// ONE VerifiablePresentation carrying every auto-matched credential. W3C only for
// now — a multi-credential SD-JWT presentation is a separate (KB-JWT-per-cred)
// construction, so it is refused with a clear message rather than mis-built.
func (h *H) submitInjiMulti(w http.ResponseWriter, r *http.Request, sess *Session, jar injiJAR) {
	legs := make([]injiMatch, 0, len(jar.Descriptors))
	for _, m := range h.injiAutoMatch(sess, jar) {
		if !m.Found {
			h.errorToast(w, r, "You don't hold all the credentials this request needs.")
			return
		}
		if !injiIsW3C(m.Held) {
			h.errorToast(w, r, "Multi-credential presentation is currently supported for W3C credentials only.")
			return
		}
		legs = append(legs, m)
	}
	helds := make([]string, len(legs))
	titles := make([]string, len(legs))
	for i, l := range legs {
		helds[i] = l.Held
		titles[i] = injiPresentLabel(l.Held)
	}
	vpToken, err := injiBuildW3CVPTokenMulti(helds)
	if err != nil {
		h.errorToast(w, r, "Build presentation: "+err.Error())
		return
	}
	if err := h.injiDirectPostMulti(r.Context(), jar, vpToken, legs); err != nil {
		h.errorToast(w, r, "Submit presentation: "+err.Error())
		return
	}
	h.renderFragment(w, r, "fragment_inji_present_shared", map[string]any{
		"Title":            strings.Join(titles, " + "),
		"VerifierClientID": jar.Aud,
		"Lang":             h.langFor(r),
	})
}

// DeclineInjiPresent cancels the consent interstitial.
func (h *H) DeclineInjiPresent(w http.ResponseWriter, r *http.Request) {
	h.renderFragment(w, r, "fragment_inji_present_declined", map[string]any{"Lang": h.langFor(r)})
}
