package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/vp"
	"github.com/verifiably/verifiably-go/vctypes"
)

type apiInjiDelegationSetupRequest struct {
	IndividualID   string   `json:"individualId"`             // the eSignet mock-identity id (login UIN)
	PIN            string   `json:"pin"`                      // the holder's eSignet PIN
	SubjectType    string   `json:"subjectType,omitempty"`    // default BirthCertificate
	DelegationType string   `json:"delegationType,omitempty"` // default DelegatedAccessCredential
	SubjectRef     string   `json:"subjectRef,omitempty"`     // linkage anchor; default = individualId
	GivenName      string   `json:"givenName,omitempty"`
	Role           string   `json:"role,omitempty"`
	AllowedAction  []string `json:"allowedAction,omitempty"`
	ValidUntil     string   `json:"validUntil,omitempty"`
}

// APIInjiDelegationSetup prepares the inji AUTH-CODE delegation flow: it creates
// the holder's eSignet mock-identity, ensures the two auth-code credential_configs
// exist (subject + delegation, SD-JWT, with a flat `delegation` field), and
// provisions the holder's vc_subject with the linkage anchor + the capability.
// The holder then claims both via eSignet at /holder/wallet/inji and verifies at
// /holder/wallet/inji/verify-delegation.
//
// NB: creating a config restarts inji-certify + eSignet (one-time; idempotent —
// skipped when the config already exists).
//
// POST /api/v1/delegation/inji/setup
func (h *H) APIInjiDelegationSetup(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	var req apiInjiDelegationSetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(req.IndividualID) == "" || strings.TrimSpace(req.PIN) == "" {
		apiError(w, http.StatusBadRequest, "individualId and pin are required")
		return
	}
	ctx := apiCtx(r, keyName)
	subjType := orDefault(req.SubjectType, "BirthCertificate")
	delegType := orDefault(req.DelegationType, "DelegatedAccessCredential")
	subjectRef := orDefault(req.SubjectRef, req.IndividualID)
	given := orDefault(req.GivenName, "Maria")

	// 1. eSignet mock-identity (so the holder can PIN-login).
	if err := createMockIdentity(ctx, req.IndividualID, req.PIN, given+" Holder", given, "Holder",
		"Female", "2015/03/10", req.IndividualID+"@example.com", "+10000000000"); err != nil {
		// already-exists is fine; surface other errors
		if !strings.Contains(strings.ToLower(err.Error()), "exist") && !strings.Contains(err.Error(), "duplicate") {
			apiError(w, http.StatusBadGateway, "create mock identity: "+err.Error())
			return
		}
	}

	// 2. Ensure the two auth-code configs exist (idempotent; create restarts certify+eSignet).
	existing := map[string]bool{}
	if creds, err := h.Subjects.ListCredentials(ctx); err == nil {
		for _, c := range creds {
			existing[c["key"]] = true
		}
	}
	for _, spec := range []struct {
		typeName string
		fields   []string
	}{
		{subjType, []string{"subjectRef", "givenName"}},
		{delegType, []string{"onBehalfOf", "role", "allowedAction", "validUntil", "statusUri", "statusIdx"}},
	} {
		if existing[spec.typeName] {
			continue
		}
		if _, err := h.applyAuthcodeSchema(ctx, injiAuthcodeSchema(spec.typeName, spec.fields), "api:"+keyName); err != nil {
			apiError(w, http.StatusBadGateway, "create config "+spec.typeName+": "+err.Error())
			return
		}
	}

	// Allocate a per-holder IETF Token Status List slot so the delegation is
	// revocable (uniform revocation — the evaluator's 4th check).
	binding, err := h.allocateStatusListBinding(injiAuthcodeSchema(delegType, nil))
	if err != nil {
		apiError(w, http.StatusInternalServerError, "status list: "+err.Error())
		return
	}

	// 3. Provision the holder's vc_subject (one row; each config's view reads its
	//    fields). The capability is carried as FLAT claims — Certify's SD-JWT
	//    template cannot nest a JSON object, so onBehalfOf + allowedAction (+
	//    validUntil) are top-level claims the evaluator's flat path reads.
	actions := req.AllowedAction
	if len(actions) == 0 {
		actions = []string{"present"}
	}
	claims := map[string]string{
		"subjectRef":    subjectRef,
		"givenName":     given,
		"onBehalfOf":    subjectRef,
		"role":          orDefault(req.Role, "Mother"),
		"allowedAction": strings.Join(actions, ","),
	}
	if req.ValidUntil != "" {
		claims["validUntil"] = req.ValidUntil
	}
	if binding != nil {
		// flat status claims (Certify's SD-JWT template cannot nest status.status_list)
		claims["statusUri"] = binding.PublishURL
		claims["statusIdx"] = strconv.Itoa(binding.Index)
	}
	subjectID := esignetSubjectID(req.IndividualID, injiAuthcodeClientID())
	if err := h.Subjects.ProvisionSubject(ctx, subjectID, claims); err != nil {
		apiError(w, http.StatusBadGateway, "provision vc_subject: "+err.Error())
		return
	}

	out := map[string]any{
		"individualId":         req.IndividualID,
		"subjectCredential":    subjType,
		"delegationCredential": delegType,
		"claimURLs": map[string]string{
			"subject":    "/holder/wallet/inji/start?cred=" + subjType,
			"delegation": "/holder/wallet/inji/start?cred=" + delegType,
		},
	}
	if binding != nil {
		out["statusListIndex"] = binding.Index
		out["statusListCredential"] = binding.PublishURL
	}
	apiJSON(w, http.StatusCreated, out)
}

// APIInjiDelegationRevoke flips the revocation bit for a delegation issued via
// the inji auth-code flow (by its Token Status List index). The next
// verify-delegation then denies (uniform revocation).
//
// POST /api/v1/delegation/inji/revoke   {"index": <n>}
func (h *H) APIInjiDelegationRevoke(w http.ResponseWriter, r *http.Request) {
	_, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	var req struct {
		Index int `json:"index"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if h.TokenStore == nil {
		apiError(w, http.StatusServiceUnavailable, "no token status store")
		return
	}
	if err := h.TokenStore.Revoke(req.Index); err != nil {
		apiError(w, http.StatusBadGateway, "revoke: "+err.Error())
		return
	}
	apiJSON(w, http.StatusOK, map[string]any{"revoked": req.Index})
}

// injiAuthcodeSchema builds a vctypes.Schema for an inji auth-code SD-JWT config.
func injiAuthcodeSchema(typeName string, fields []string) vctypes.Schema {
	fs := make([]vctypes.FieldSpec, 0, len(fields))
	for _, f := range fields {
		fs = append(fs, vctypes.FieldSpec{Name: f, Datatype: "string"})
	}
	return vctypes.Schema{
		ID:              typeName,
		Name:            typeName,
		Desc:            "Delegated-access " + typeName,
		Std:             "sd_jwt_vc (IETF)",
		Custom:          true,
		AdditionalTypes: []string{typeName},
		FieldsSpec:      fs,
	}
}

// VerifyInjiDelegation runs the delegated-access evaluator over the holder's
// in-app Inji-claimed credentials (the eSignet auth-code flow). The in-app Inji
// holder CLAIMS credentials but does not OID4VP-present them, so delegation
// verification evaluates the held credential set directly — the same DPG-agnostic
// evaluator the OID4VP verifier path uses, just sourced from the session's
// claimed creds instead of a presented VP.
//
// GET /holder/wallet/inji/verify-delegation
func (h *H) VerifyInjiDelegation(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	creds := normalizeClaimedInjiCreds(sess.InjiClaimedVCs)
	res := backend.VerificationResult{
		Credentials: creds,
		// The in-app holder proved possession via the OID4VCI holder proof at
		// claim time; mark the binding confirmed (no identifier — the evaluator's
		// invocation check then relies on the capability binding the delegate).
		HolderBinding: &backend.HolderBinding{Confirmed: true},
		Valid:         len(creds) > 0,
	}
	h.attachDelegationVerdict(r, &res)
	out := map[string]any{
		"credentialCount": len(creds),
		"valid":           res.Valid,
	}
	if res.Delegation != nil {
		out["delegation"] = res.Delegation
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// normalizeClaimedInjiCreds parses the holder's claimed Inji credentials — stored
// as the raw credential JSON: an object for ldp_vc, or a quoted compact SD-JWT
// string for vc+sd-jwt — into the shared NormalizedCredential shape.
func normalizeClaimedInjiCreds(raws []string) []backend.NormalizedCredential {
	var out []backend.NormalizedCredential
	for _, raw := range raws {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var obj map[string]any
		if json.Unmarshal([]byte(raw), &obj) == nil && len(obj) > 0 {
			out = append(out, vp.FromVCObject(obj))
			continue
		}
		var s string
		if json.Unmarshal([]byte(raw), &s) == nil && strings.Contains(s, "~") {
			if nc, ok := vp.FromCompactSDJWT(s); ok {
				out = append(out, nc)
			}
		} else if strings.Contains(raw, "~") {
			if nc, ok := vp.FromCompactSDJWT(raw); ok {
				out = append(out, nc)
			}
		}
	}
	return out
}

type apiInjiPreAuthIssueRequest struct {
	SubjectType    string   `json:"subjectType,omitempty"`
	DelegationType string   `json:"delegationType,omitempty"`
	SubjectRef     string   `json:"subjectRef,omitempty"`
	GivenName      string   `json:"givenName,omitempty"`
	Role           string   `json:"role,omitempty"`
	AllowedAction  []string `json:"allowedAction,omitempty"`
	ValidUntil     string   `json:"validUntil,omitempty"`
}

// APIInjiPreAuthDelegationIssue issues a delegated-access pair via the inji
// PRE-AUTH flow: it registers the two SD-JWT configs in the pre-auth Certify
// instance and stages two pre-authorized credential offers (claims inline — no
// vc_subject, no eSignet, no restart). The holder claims both offers into the
// walt.id wallet, then verifies via /holder/wallet/verify-delegation.
// Capability + status are FLAT claims (Certify cannot nest), exactly as the
// auth-code flow.
//
// POST /api/v1/delegation/inji/preauth/issue
func (h *H) APIInjiPreAuthDelegationIssue(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	var req apiInjiPreAuthIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	ctx := apiCtx(r, keyName)
	const dpg = "Inji Certify · Pre-Auth"
	subjType := orDefault(req.SubjectType, "BirthCertificate")
	delegType := orDefault(req.DelegationType, "DelegationPre")
	subjectRef := orDefault(req.SubjectRef, "urn:person:preauth")
	given := orDefault(req.GivenName, "Maria")
	actions := req.AllowedAction
	if len(actions) == 0 {
		actions = []string{"present"}
	}

	subjSchema := injiPreAuthSchema(subjType, dpg, []string{"subjectRef", "givenName"})
	delegSchema := injiPreAuthSchema(delegType, dpg, []string{"onBehalfOf", "role", "allowedAction", "validUntil", "statusUri", "statusIdx"})
	if err := h.Adapter.SaveCustomSchema(ctx, subjSchema); err != nil {
		apiError(w, http.StatusBadGateway, "register subject schema: "+err.Error())
		return
	}
	if err := h.Adapter.SaveCustomSchema(ctx, delegSchema); err != nil {
		apiError(w, http.StatusBadGateway, "register delegation schema: "+err.Error())
		return
	}
	binding, err := h.allocateStatusListBinding(delegSchema)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "status list: "+err.Error())
		return
	}

	subjRes, err := h.Adapter.IssueToWallet(ctx, backend.IssueRequest{
		IssuerDpg: dpg, Schema: subjSchema, Flow: "pre_auth",
		SubjectData: map[string]string{"subjectRef": subjectRef, "givenName": given},
	})
	if err != nil {
		apiError(w, http.StatusBadGateway, "issue subject: "+err.Error())
		return
	}
	delegClaims := map[string]string{
		"onBehalfOf":    subjectRef,
		"role":          orDefault(req.Role, "Mother"),
		"allowedAction": strings.Join(actions, ","),
	}
	if req.ValidUntil != "" {
		delegClaims["validUntil"] = req.ValidUntil
	}
	if binding != nil {
		delegClaims["statusUri"] = binding.PublishURL
		delegClaims["statusIdx"] = strconv.Itoa(binding.Index)
	}
	delegRes, err := h.Adapter.IssueToWallet(ctx, backend.IssueRequest{
		IssuerDpg: dpg, Schema: delegSchema, Flow: "pre_auth", SubjectData: delegClaims,
	})
	if err != nil {
		apiError(w, http.StatusBadGateway, "issue delegation: "+err.Error())
		return
	}

	out := map[string]any{
		"subject":    map[string]any{"offerUri": subjRes.OfferURI, "type": subjType},
		"delegation": map[string]any{"offerUri": delegRes.OfferURI, "type": delegType},
	}
	if binding != nil {
		out["statusListIndex"] = binding.Index
		out["statusListCredential"] = binding.PublishURL
	}
	apiJSON(w, http.StatusCreated, out)
}

func injiPreAuthSchema(typeName, dpg string, fields []string) vctypes.Schema {
	fs := make([]vctypes.FieldSpec, 0, len(fields))
	for _, f := range fields {
		fs = append(fs, vctypes.FieldSpec{Name: f, Datatype: "string"})
	}
	return vctypes.Schema{
		ID:              "dapre-" + strings.ToLower(typeName),
		Name:            typeName,
		Desc:            "Delegated-access " + typeName,
		Std:             "sd_jwt_vc (IETF)",
		DPGs:            []string{dpg},
		Custom:          true,
		AdditionalTypes: []string{typeName},
		FieldsSpec:      fs,
	}
}

// VerifyWalletDelegation evaluates the delegated-access pair the holder is
// HOLDING in their walt.id wallet (read via ListWalletCredentials), rather than
// requiring an OID4VP presentation. This serves DPG/flow combinations whose
// wallet cannot build a multi-credential VP (walt.id v0.18.2 throws on a
// multi-cred SD-JWT / ldp_vc vp_token) — e.g. the inji PRE-AUTH pair claimed
// into the walt.id wallet. Same DPG-agnostic evaluator, sourced from held creds.
//
// GET /holder/wallet/verify-delegation
func (h *H) VerifyWalletDelegation(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	ctx := holderCtx(r, sess)
	held, err := h.Adapter.ListWalletCredentials(ctx)
	if err != nil {
		apiError(w, http.StatusBadGateway, "list wallet credentials: "+err.Error())
		return
	}
	creds := make([]backend.NormalizedCredential, 0, len(held))
	for _, c := range held {
		creds = append(creds, normalizeWalletCred(c))
	}
	res := backend.VerificationResult{
		Credentials:   creds,
		HolderBinding: &backend.HolderBinding{Confirmed: true},
		Valid:         len(creds) > 0,
	}
	h.attachDelegationVerdict(r, &res)
	out := map[string]any{"credentialCount": len(creds), "valid": res.Valid}
	if res.Delegation != nil {
		out["delegation"] = res.Delegation
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// normalizeWalletCred maps a held walt.id wallet credential into the evaluator's
// view. For SD-JWT the wallet flattens top-level claims into Fields, so the flat
// capability/status claims (onBehalfOf, allowedAction, validUntil, statusUri,
// statusIdx, subjectRef) are all present.
func normalizeWalletCred(c vctypes.Credential) backend.NormalizedCredential {
	raw := make(map[string]any, len(c.Fields))
	for k, v := range c.Fields {
		raw[k] = v
	}
	return backend.NormalizedCredential{
		Types:  []string{c.Type},
		Issuer: c.Issuer,
		Format: c.Format,
		Claims: c.Fields,
		Raw:    raw,
	}
}

// injiGetJSON GETs a URL and decodes JSON into out.
func injiGetJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

// injiPreAuthClaim is a headless OID4VCI pre-authorized-code holder: it resolves
// the credential offer, exchanges the pre-authorized_code for a token, signs a
// CONFORMANT proof JWT (typ=openid4vci-proof+jwt with a `jwk` header and no
// `kid` — the same shape verifiably's auth-code holder and the whitelabel
// wallet's manual SD-JWT path use, which Certify accepts; unlike walt.id's
// kid+jwk proof), and fetches the credential. Returns the compact SD-JWT. This
// is the holder verifiably's own software provides for the inji PRE-AUTH flow,
// so no external mobile wallet is required.
func (h *H) injiPreAuthClaim(ctx context.Context, offerURI string) (string, error) {
	ouri := strings.TrimSpace(offerURI)
	if u, err := url.Parse(ouri); err == nil {
		if c := u.Query().Get("credential_offer_uri"); c != "" {
			ouri = c
		}
	}
	var offer struct {
		CredentialIssuer string   `json:"credential_issuer"`
		ConfigIDs        []string `json:"credential_configuration_ids"`
		Grants           map[string]struct {
			PreAuthCode string `json:"pre-authorized_code"`
		} `json:"grants"`
	}
	if err := injiGetJSON(ctx, ouri, &offer); err != nil {
		return "", fmt.Errorf("resolve offer: %w", err)
	}
	if len(offer.ConfigIDs) == 0 {
		return "", fmt.Errorf("offer has no credential_configuration_ids")
	}
	issuer := strings.TrimRight(offer.CredentialIssuer, "/")
	configID := offer.ConfigIDs[0]
	preAuth := offer.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].PreAuthCode
	if preAuth == "" {
		return "", fmt.Errorf("offer has no pre-authorized_code")
	}

	var meta struct {
		CredentialEndpoint string `json:"credential_endpoint"`
		TokenEndpoint      string `json:"token_endpoint"`
		Configs            map[string]struct {
			Vct string `json:"vct"`
		} `json:"credential_configurations_supported"`
	}
	if err := injiGetJSON(ctx, issuer+"/.well-known/openid-credential-issuer", &meta); err != nil {
		return "", fmt.Errorf("issuer metadata: %w", err)
	}
	tokenEP := orDefault(meta.TokenEndpoint, issuer+"/v1/certify/oauth/token")
	credEP := orDefault(meta.CredentialEndpoint, issuer+"/v1/certify/issuance/credential")
	vct := meta.Configs[configID].Vct

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	form.Set("pre-authorized_code", preAuth)
	var tok struct {
		AccessToken string `json:"access_token"`
		CNonce      string `json:"c_nonce"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := postForm(ctx, tokenEP, form, &tok); err != nil {
		return "", fmt.Errorf("pre-auth token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("pre-auth token: %s %s", tok.Error, tok.ErrorDesc)
	}

	holderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	xb, yb := make([]byte, 32), make([]byte, 32)
	holderKey.X.FillBytes(xb)
	holderKey.Y.FillBytes(yb)
	jwk := map[string]any{"kty": "EC", "crv": "P-256", "x": b64u(xb), "y": b64u(yb), "alg": "ES256"}
	claim := func(nonce string) (int, []byte, error) {
		pc := map[string]any{"aud": issuer, "iat": time.Now().Unix()}
		if nonce != "" {
			pc["nonce"] = nonce
		}
		proof, e := signES256(holderKey, map[string]any{"alg": "ES256", "typ": "openid4vci-proof+jwt", "jwk": jwk}, pc)
		if e != nil {
			return 0, nil, e
		}
		reqMap := map[string]any{"format": "vc+sd-jwt", "proof": map[string]any{"proof_type": "jwt", "jwt": proof}}
		if vct != "" {
			reqMap["vct"] = vct
		}
		rb, _ := json.Marshal(reqMap)
		return postJSON(ctx, credEP, rb, "Bearer "+tok.AccessToken)
	}
	status, body, err := claim(tok.CNonce)
	if err != nil {
		return "", err
	}
	if status >= 400 {
		var e struct {
			CNonce string `json:"c_nonce"`
		}
		_ = json.Unmarshal(body, &e)
		if e.CNonce != "" {
			status, body, err = claim(e.CNonce)
			if err != nil {
				return "", err
			}
		}
		if status >= 400 {
			return "", fmt.Errorf("credential endpoint %d: %s", status, truncateForLog(string(body), 200))
		}
	}
	var wrap struct {
		Credential json.RawMessage `json:"credential"`
	}
	if json.Unmarshal(body, &wrap) == nil && len(wrap.Credential) > 0 {
		var s string
		if json.Unmarshal(wrap.Credential, &s) == nil && s != "" {
			return s, nil
		}
		return string(wrap.Credential), nil
	}
	return string(body), nil
}

// APIInjiPreAuthDelegationClaim claims one or more inji PRE-AUTH offers headlessly
// (verifiably's own conformant-proof holder) and returns the raw credentials.
//
// POST /api/v1/delegation/inji/preauth/claim   {"offers": ["<uri>", ...]}
func (h *H) APIInjiPreAuthDelegationClaim(w http.ResponseWriter, r *http.Request) {
	keyName, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	var req struct {
		Offers []string `json:"offers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	ctx := apiCtx(r, keyName)
	creds := make([]string, 0, len(req.Offers))
	for i, o := range req.Offers {
		vc, err := h.injiPreAuthClaim(ctx, o)
		if err != nil {
			apiError(w, http.StatusBadGateway, fmt.Sprintf("claim offer %d: %s", i, err.Error()))
			return
		}
		creds = append(creds, vc)
	}
	apiJSON(w, http.StatusOK, map[string]any{"credentials": creds})
}

// APIVerifyDelegationSDJWT evaluates the delegated-access relation over a set of
// raw credentials (compact SD-JWT or JSON-LD objects) supplied directly — the
// verify side for holders that hand back their held creds (e.g. the headless
// pre-auth claim). Same DPG-agnostic evaluator.
//
// POST /api/v1/delegation/verify/sdjwt   {"credentials": ["<sd-jwt>", ...]}
func (h *H) APIVerifyDelegationSDJWT(w http.ResponseWriter, r *http.Request) {
	_, ok := h.requireAPIAuth(w, r)
	if !ok {
		return
	}
	var req struct {
		Credentials []string `json:"credentials"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	creds := make([]backend.NormalizedCredential, 0, len(req.Credentials))
	for _, c := range req.Credentials {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.Contains(c, "~") {
			if nc, ok := vp.FromCompactSDJWT(c); ok {
				creds = append(creds, nc)
			}
			continue
		}
		var obj map[string]any
		if json.Unmarshal([]byte(c), &obj) == nil && len(obj) > 0 {
			creds = append(creds, vp.FromVCObject(obj))
		}
	}
	res := backend.VerificationResult{
		Credentials:   creds,
		HolderBinding: &backend.HolderBinding{Confirmed: true},
		Valid:         len(creds) > 0,
	}
	h.attachDelegationVerdict(r, &res)
	out := map[string]any{"credentialCount": len(creds), "valid": res.Valid}
	if res.Delegation != nil {
		out["delegation"] = res.Delegation
	}
	apiJSON(w, http.StatusOK, out)
}
