package waltid

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/httpx"
	"github.com/verifiably/verifiably-go/vctypes"
)

// base64urlDecode accepts base64url-encoded input with or without padding,
// as JWT spec specifies unpadded but some implementations add it.
func base64urlDecode(s string) ([]byte, error) {
	// RawURLEncoding handles both with-padding and without via the Strict
	// check being off; but to be safe, pad explicitly.
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(s)
}

// accountRequest is walt.id's AccountRequest body shape; the email variant is
// what this adapter uses. Walt.id distinguishes variants by the fields present.
type accountRequest struct {
	Type     string `json:"type,omitempty"` // "email" etc.; walt.id matches on fields so this is advisory
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

type walletListing struct {
	Account string      `json:"account"`
	Wallets []walletRef `json:"wallets"`
}

type walletRef struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	CreatedOn   string `json:"createdOn"`
	AddedOn     string `json:"addedOn"`
	Permission  string `json:"permission"`
}

// ensureWalletSession registers-or-logs-in a walt.id account for the
// calling user and caches a session token + wallet id. Each unique user
// identity (read from ctx via backend.HolderIdentityFromContext) gets
// its own walt.id account and its own wallet — so switching users
// switches credentials, not just OIDC sessions. Empty identity falls
// back to the configured demo account for pre-auth / single-user mode.
func (a *Adapter) ensureWalletSession(ctx context.Context) (*walletSession, error) {
	if a.wallet == nil {
		return nil, fmt.Errorf("waltid: wallet role not configured (walletBaseUrl missing)")
	}
	userKey := backend.HolderIdentityFromContext(ctx)
	acc := a.accountForUser(userKey)
	cacheKey := acc.Email
	log.Printf("waltid: sess userKey=%q acc=%q", userKey, cacheKey)

	a.mu.Lock()
	if s, ok := a.sessions[cacheKey]; ok {
		a.mu.Unlock()
		log.Printf("waltid: sess hit walletID=%s", s.WalletID)
		return s, nil
	}
	a.mu.Unlock()

	body := accountRequest{
		Type:     "email",
		Name:     acc.Name,
		Email:    acc.Email,
		Password: acc.Password,
	}

	// Register first. Ignore "already exists" — login below will succeed.
	_ = a.wallet.DoJSON(ctx, "POST", "/wallet-api/auth/register", body, nil, nil)

	var tok loginResponse
	if err := a.wallet.DoJSON(ctx, "POST", "/wallet-api/auth/login", body, &tok, nil); err != nil {
		return nil, fmt.Errorf("wallet login: %w", err)
	}
	if tok.Token == "" {
		return nil, fmt.Errorf("wallet login: empty token")
	}

	// Wallet listing requires the session token in the Authorization header.
	authCtx := httpx.WithToken(ctx, tok.Token)
	var wl walletListing
	if err := a.wallet.DoJSON(authCtx, "GET", "/wallet-api/wallet/accounts/wallets", nil, &wl, nil); err != nil {
		return nil, fmt.Errorf("list wallets: %w", err)
	}
	if len(wl.Wallets) == 0 {
		return nil, fmt.Errorf("wallet login: no wallets for account")
	}

	sess := &walletSession{Token: tok.Token, WalletID: wl.Wallets[0].ID}
	a.mu.Lock()
	a.sessions[cacheKey] = sess
	a.mu.Unlock()
	return sess, nil
}

// accountForUser derives the walt.id account credentials for a given
// verifiably-go identity. When userKey is empty we use the configured
// demo account (legacy single-user mode). Otherwise every distinct key
// maps to a unique email / deterministic password — deterministic so a
// user who logs in again after a restart recovers their same walt.id
// wallet (and its stored credentials) rather than landing in a fresh
// empty one.
func (a *Adapter) accountForUser(userKey string) Account {
	if userKey == "" {
		acc := a.cfg.DemoAccount
		if acc.Email == "" {
			acc.Email = "verifiably-demo@example.org"
		}
		if acc.Password == "" {
			acc.Password = generatePassword()
		}
		if acc.Name == "" {
			acc.Name = "Verifiably Demo"
		}
		return acc
	}
	// Deterministic slug for use in an email local-part. The
	// verifiably-demo.local hostname is a placeholder — walt.id's
	// accounts DB doesn't send anything to it.
	slug := emailSlug(userKey)
	return Account{
		Name:     userKey,
		Email:    slug + "@verifiably-demo.local",
		Password: deterministicPassword(userKey),
	}
}

// emailSlug normalises a user key (usually an email) into a short,
// deterministic, email-local-part-safe identifier. Callers only need
// uniqueness + consistency across logins; walt.id doesn't parse it.
func emailSlug(key string) string {
	sum := sha256Hex(key)
	if len(sum) > 16 {
		sum = sum[:16]
	}
	return "u-" + sum
}

// deterministicPassword produces a stable password from the user key so
// re-logging in after a walt.id restart finds the same account. Using
// the sha256 of key+a static salt so the password isn't literally the
// key echoed back.
func deterministicPassword(key string) string {
	return "pw-" + sha256Hex("verifiably|"+key)
}

// sha256Hex returns the hex-encoded sha256 of s — tiny helper for the
// email-slug / password derivation above.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// DeleteWalletCredential removes a held credential from the walt.id wallet.
// Walt.id's DELETE defaults to a SOFT delete (returns 202 but the credential
// still shows up in subsequent list calls, just flagged); passing
// ?permanent=true is what actually removes it. This adapter always does
// permanent deletes — from the operator's perspective "delete" means gone.
func (a *Adapter) DeleteWalletCredential(ctx context.Context, credentialID string) error {
	if credentialID == "" {
		return fmt.Errorf("empty credential id")
	}
	sess, err := a.ensureWalletSession(ctx)
	if err != nil {
		return err
	}
	authCtx := httpx.WithToken(ctx, sess.Token)
	_, err = a.wallet.DoRaw(authCtx, http.MethodDelete,
		fmt.Sprintf("/wallet-api/wallet/%s/credentials/%s?permanent=true", sess.WalletID, url.PathEscape(credentialID)),
		nil, "", nil)
	return err
}

// ListWalletCredentials returns held credentials for the demo wallet.
func (a *Adapter) ListWalletCredentials(ctx context.Context) ([]vctypes.Credential, error) {
	sess, err := a.ensureWalletSession(ctx)
	if err != nil {
		return nil, err
	}
	var raw []map[string]json.RawMessage
	if err := a.wallet.DoJSON(httpx.WithToken(ctx, sess.Token), "GET",
		fmt.Sprintf("/wallet-api/wallet/%s/credentials", sess.WalletID),
		nil, &raw, nil); err != nil {
		return nil, err
	}
	out := make([]vctypes.Credential, 0, len(raw))
	for _, c := range raw {
		cred := walletCredentialToVctype(c)
		if cred.ID == "" {
			continue
		}
		out = append(out, cred)
	}
	// IssuerDisplay enrichment lives at the handler layer, not here:
	// adapter.ListSchemas reconstructs schemas from walt.id's wellknown
	// (which has no IssuerDisplayName field), while handlers reach the
	// Registry's ListAllSchemas which merges in our local customSchemas
	// where the field is preserved. See handlers.attachIssuerDisplay.
	return out, nil
}

// ListExampleOffers is used by the "paste example" helper. The registry drives
// bootstrap offers; this method stays here for adapter symmetry but returns an
// empty slice — the registry's ListExampleOffers aggregates BootstrapOffers
// across all issuer adapters instead.
func (a *Adapter) ListExampleOffers(_ context.Context) ([]string, error) {
	return nil, nil
}

// ParseOffer resolves an offer URI via /exchange/resolveCredentialOffer.
// Walt.id accepts the raw offer string as the request body (plain text) and
// returns a parsed CredentialOffer JSON we surface as a "pending" credential
// the operator can accept or reject.
//
// Errors from walt.id are surfaced in the returned error message so the UI
// toast tells the operator what went wrong — previously this swallowed the
// body and made paste failures look like "nothing happened".
func (a *Adapter) ParseOffer(ctx context.Context, offerURI string) (vctypes.Credential, error) {
	sess, err := a.ensureWalletSession(ctx)
	if err != nil {
		return vctypes.Credential{}, err
	}
	body, err := a.wallet.DoRaw(httpx.WithToken(ctx, sess.Token), "POST",
		fmt.Sprintf("/wallet-api/wallet/%s/exchange/resolveCredentialOffer", sess.WalletID),
		strings.NewReader(offerURI), "text/plain", nil)
	if err != nil {
		// Surface walt.id's own error body so the UI can explain why the
		// paste failed (e.g. unknown issuer, unparseable offer, signature
		// mismatch). Still wraps ErrOfferUnresolvable so handlers can branch
		// on typed error if needed.
		return vctypes.Credential{}, fmt.Errorf("%w: %v", backend.ErrOfferUnresolvable, err)
	}

	// Parse what we can out of the returned offer JSON to surface meaningful
	// preview text — credential type(s), issuer id — instead of an opaque
	// "Incoming credential" label.
	var parsed struct {
		CredentialIssuer              string   `json:"credential_issuer"`
		CredentialConfigurationIds    []string `json:"credential_configuration_ids"`
		Credentials                   []any    `json:"credentials"` // older shape
		Grants                        map[string]any `json:"grants"`
	}
	_ = json.Unmarshal(body, &parsed)

	title := "Incoming credential"
	configID := firstOr(parsed.CredentialConfigurationIds, "")
	if configID != "" {
		title = humanise(strings.SplitN(configID, "_", 2)[0])
	}
	issuer := parsed.CredentialIssuer
	if issuer == "" {
		issuer = "(unknown issuer)"
	}

	fields := map[string]string{
		"offer_uri": offerURI,
		"config_id": configID,
	}
	// Best-effort: fetch the issuer's well-known openid-credential-issuer
	// metadata and copy in the display name + claim slots the holder will
	// receive if they accept. The pending card has no claim VALUES — the
	// wallet only learns those after claiming — but knowing WHICH fields
	// are coming + the issuer's display name is meaningful context.
	if issuer != "" && configID != "" {
		if slots, display := fetchCredentialSlots(ctx, issuer, configID); display != "" || len(slots) > 0 {
			if display != "" {
				title = display
			}
			if len(slots) > 0 {
				fields["offered_fields"] = strings.Join(slots, ", ")
			}
		}
	}

	return vctypes.Credential{
		ID:     "pending-" + randomHex(4),
		Title:  title,
		Issuer: issuer,
		Type:   "w3c_vcdm_2",
		Status: "pending",
		Fields: fields,
	}, nil
}

// fetchCredentialSlots reads the issuer's well-known
// openid-credential-issuer document, looks up the configID, and returns
// the display name + claim keys. Best-effort: any network error returns
// empty values so the caller falls back to the offer-only preview.
func fetchCredentialSlots(ctx context.Context, issuerBase, configID string) (slots []string, display string) {
	u := strings.TrimRight(issuerBase, "/") + "/.well-known/openid-credential-issuer"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, ""
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ""
	}
	var doc struct {
		CredentialConfigurationsSupported map[string]struct {
			Display []struct {
				Name string `json:"name"`
			} `json:"display"`
			CredentialDefinition struct {
				CredentialSubject map[string]any `json:"credentialSubject"`
			} `json:"credential_definition"`
			Claims map[string]any `json:"claims"`
		} `json:"credential_configurations_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, ""
	}
	cfg, ok := doc.CredentialConfigurationsSupported[configID]
	if !ok {
		return nil, ""
	}
	if len(cfg.Display) > 0 && cfg.Display[0].Name != "" {
		display = cfg.Display[0].Name
	}
	// Prefer credential_definition.credentialSubject (W3C VCDM shape);
	// fall back to the flat claims map (SD-JWT VC shape).
	pool := cfg.CredentialDefinition.CredentialSubject
	if len(pool) == 0 {
		pool = cfg.Claims
	}
	for k := range pool {
		slots = append(slots, k)
	}
	return slots, display
}

func firstOr(xs []string, fallback string) string {
	if len(xs) > 0 {
		return xs[0]
	}
	return fallback
}

// ClaimCredential consummates the offer via /exchange/useOfferRequest. Walt.id
// accepts the offer URI as plain text body; query params control the did used
// and whether user input is required.
//
// After the claim succeeds, we re-list the wallet and find the credential we
// just added so the returned vctypes.Credential carries its real
// credentialSubject fields. Without this, the card that replaces the pending
// one would still only show offer metadata — the claim values would only
// appear after a subsequent /holder/wallet fetch.
func (a *Adapter) ClaimCredential(ctx context.Context, cred vctypes.Credential) (vctypes.Credential, error) {
	sess, err := a.ensureWalletSession(ctx)
	if err != nil {
		return cred, err
	}
	offerURI := cred.Fields["offer_uri"]
	if offerURI == "" {
		return cred, fmt.Errorf("claim credential: missing offer_uri on pending cred")
	}
	q := url.Values{"requireUserInput": {"false"}}
	path := fmt.Sprintf("/wallet-api/wallet/%s/exchange/useOfferRequest?%s", sess.WalletID, q.Encode())
	_, err = a.wallet.DoRaw(httpx.WithToken(ctx, sess.Token), "POST", path,
		strings.NewReader(offerURI), "text/plain", nil)
	if err != nil {
		return cred, friendlyClaimError(err, cred.Fields["config_id"])
	}
	cred.Status = "accepted"

	// Best-effort: list the wallet and pick the newest credential whose
	// config id matches this offer — that's almost always the one we just
	// claimed. Walt.id's useOfferRequest response doesn't echo the stored
	// credential's id, so we can't look up by primary key.
	held, err := a.ListWalletCredentials(ctx)
	if err != nil || len(held) == 0 {
		return cred, nil
	}
	configID := cred.Fields["config_id"]
	var match *vctypes.Credential
	for i := range held {
		h := &held[i]
		if configID != "" && h.Fields["config_id"] == configID {
			match = h
			break
		}
	}
	if match == nil {
		// No config_id match — fall back to the last credential listed, which
		// walt.id emits in insertion order.
		match = &held[len(held)-1]
	}
	// Preserve the pending card's ID so the HTMX swap replaces the right card,
	// but copy over everything else from the just-claimed credential.
	pendingID := cred.ID
	cred = *match
	cred.ID = pendingID
	cred.Status = "accepted"
	return cred, nil
}

// PresentCredential responds to an OID4VP request via /exchange/usePresentationRequest.
//
// Two call shapes are tried in order to cover walt.id's wallet-api versions:
//
//   1. Match-then-present. Calls /exchange/matchCredentialsForPresentationDefinition
//      first so the wallet resolves the PD URL, fetches the definition, and
//      returns the credentials that match. If that succeeds we submit with
//      the wallet's own canonical credential-id (which can differ from the
//      id surfaced by ListWalletCredentials when walt.id re-emits ids
//      per-presentation). If the match call fails we continue to step 2 —
//      some older wallet-api builds don't expose the match endpoint.
//
//   2. Direct submit with the caller-provided CredentialID. This is the
//      original code path; kept as a fallback because it works on builds
//      where matchCredentialsForPresentationDefinition is missing.
//
// Either way, the raw 400 body is surfaced verbatim to the caller so the
// UI toast shows the walt.id error (previously the user saw
// "Bad Request" with no detail).
func (a *Adapter) PresentCredential(ctx context.Context, req backend.PresentCredentialRequest) (backend.PresentCredentialResult, error) {
	sess, err := a.ensureWalletSession(ctx)
	if err != nil {
		return backend.PresentCredentialResult{}, err
	}
	authCtx := httpx.WithToken(ctx, sess.Token)

	// Pre-flight: fetch the verifier's PD and ask the wallet which of its
	// credentials satisfy it. If none do, fail fast with an error message
	// that explains exactly which credential type + format the verifier
	// wanted — otherwise the submit would produce a raw walt.id 400 saying
	// only "presentationDefinitionMatch:false" which gives the user no
	// hint about what to fix.
	pd := a.fetchPresentationDefinition(authCtx, req.RequestURI)
	credID := req.CredentialID
	var selected []string
	if pd != nil {
		matched, ok := a.matchPD(authCtx, sess.WalletID, pd)
		if ok && len(matched) == 0 {
			wantType, wantFormat := describePD(pd)
			// Diagnose: report what the wallet actually holds vs the PD
			// filter so the operator can see whether this is a stale
			// credential (issued before a config alignment fix), a vct
			// mismatch (walt.id substituted the catalog vct for ir.Vct),
			// or genuinely a missing credential. Without this hint the
			// user is left guessing whether to re-issue, redeploy, or
			// inspect the catalog.
			held, _ := a.ListWalletCredentials(authCtx)
			diag := summariseHeldForDiagnostic(held, wantFormat)
			return backend.PresentCredentialResult{}, fmt.Errorf(
				"your wallet has no credential matching this request (verifier asked for %s in %s format)%s; accept a matching offer first, then try again",
				wantType, wantFormat, diag)
		}
		if ok {
			if pdDescriptorCount(pd) > 1 {
				// Multi-credential request (e.g. a delegated-access pair):
				// present EVERY matched credential so each input-descriptor is
				// satisfied, instead of a single best match.
				selected = allMatchedIDs(matched)
			} else {
				credID = pickBestMatch(matched, req.CredentialID)
			}
		}
	}
	if len(selected) == 0 {
		selected = []string{credID}
	}

	body := map[string]any{
		"presentationRequest": req.RequestURI,
		"selectedCredentials": selected,
	}
	// Selective-disclosure filtering per selected credential: walt.id's VP
	// builder otherwise returns ALL disclosures in the SD-JWT, which fails the
	// verifier's limit_disclosure=required constraint. No-op for jwt_vc_json /
	// ldp_vc (no disclosures).
	if pd != nil {
		disc := map[string][]string{}
		for _, id := range selected {
			if d := a.selectRequestedDisclosures(authCtx, sess.WalletID, id, pd); len(d) > 0 {
				disc[id] = d
			}
		}
		if len(disc) > 0 {
			body["disclosures"] = disc
		}
	} else if len(req.DisclosedClaim) > 0 {
		body["disclosures"] = map[string][]string{credID: req.DisclosedClaim}
	}
	respRaw, err := a.wallet.DoRaw(authCtx, "POST",
		fmt.Sprintf("/wallet-api/wallet/%s/exchange/usePresentationRequest", sess.WalletID),
		jsonReaderBytes(mustJSON(body)), "application/json", nil)
	if err != nil {
		return backend.PresentCredentialResult{}, friendlyPresentError(err)
	}
	redirectURI := ""
	if len(respRaw) > 0 {
		var parsed struct {
			RedirectURI string `json:"redirectUri"`
		}
		_ = json.Unmarshal(respRaw, &parsed)
		redirectURI = parsed.RedirectURI
	}
	return backend.PresentCredentialResult{
		Success:       true,
		Method:        "OID4VP · via wallet API",
		SharedClaims:  req.DisclosedClaim,
		VerifierState: redirectURI,
	}, nil
}

// vpFormatRank returns a score for a credential format based on whether
// walt.id's wallet-api has a tested VP submit path for it. Formats
// outside the canonical two (jwt_vc_json, vc+sd-jwt) crash the wallet's
// internal SD-JWT-suffix assertion when built into a vp_token.
func vpFormatRank(f string) int {
	switch f {
	case "jwt_vc_json":
		return 100
	case "vc+sd-jwt":
		return 90
	case "dc+sd-jwt":
		return 85
	case "mso_mdoc":
		return 70
	default:
		return 0
	}
}

// fetchPresentationDefinition extracts presentation_definition_uri from an
// openid4vp:// request URI, GETs the PD from walt.id's verifier, and
// returns the decoded JSON object. The GET goes through a.verifier
// (the httpx.Client bound to the docker-internal verifier URL) so the
// fetch works from inside the verifiably-go container — `localhost:7003`
// in the request URI doesn't resolve inside the container, but the
// path after it is the same on both host and container views of the
// verifier.
func (a *Adapter) fetchPresentationDefinition(ctx context.Context, requestURI string) map[string]any {
	idx := strings.Index(requestURI, "presentation_definition_uri=")
	if idx < 0 {
		return nil
	}
	encoded := requestURI[idx+len("presentation_definition_uri="):]
	if amp := strings.IndexByte(encoded, '&'); amp >= 0 {
		encoded = encoded[:amp]
	}
	pdURL, err := url.QueryUnescape(encoded)
	if err != nil {
		return nil
	}
	// Strip the scheme+host so the path lands on whatever URL a.verifier
	// was configured with (docker-internal name when containerized, host
	// URL otherwise). Path shape is the same on both forms.
	if u, err := url.Parse(pdURL); err == nil {
		pdURL = u.Path
		if u.RawQuery != "" {
			pdURL += "?" + u.RawQuery
		}
	}
	var out map[string]any
	if err := a.verifier.DoJSON(ctx, http.MethodGet, pdURL, nil, &out, nil); err != nil {
		return nil
	}
	return out
}

// PreviewPresentation fetches the verifier's PD and cross-references the
// requested fields against the holder's picked credential so the consent
// page can show "what's about to be shared" before the actual submit.
// Implements backend.PresentationPreviewer.
//
// Critically it also calls walt.id's match endpoint with the same PD the
// SUBMIT will use, so we catch format mismatches up-front. Previously the
// preview would happily render values from the held credential's cached
// Fields map — even when the credential was in a format walt.id wouldn't
// accept for this PD — and the submit then failed with "no credential
// matching" after the user had already clicked Disclose.
func (a *Adapter) PreviewPresentation(ctx context.Context, req backend.PresentCredentialRequest) (backend.PresentationPreview, error) {
	sess, err := a.ensureWalletSession(ctx)
	if err != nil {
		return backend.PresentationPreview{}, err
	}
	authCtx := httpx.WithToken(ctx, sess.Token)
	preview := backend.PresentationPreview{
		CredentialID:     req.CredentialID,
		VerifierClientID: extractClientID(req.RequestURI),
		Compatible:       true, // optimistic; downgraded below on match failure
	}
	// Locate the held credential so we can surface its field values.
	creds, _ := a.ListWalletCredentials(ctx)
	var held *vctypes.Credential
	for i := range creds {
		if creds[i].ID == req.CredentialID {
			held = &creds[i]
			break
		}
	}
	if held != nil {
		preview.CredentialTitle = held.Title
	}

	pd := a.fetchPresentationDefinition(authCtx, req.RequestURI)
	if pd == nil {
		// No PD we can parse — fall back to the whole credential's field
		// set so the operator still sees what would be shared. Can't make
		// a compatibility claim either way.
		if held != nil {
			for k, v := range held.Fields {
				if k == "offer_uri" || k == "config_id" {
					continue
				}
				preview.Fields = append(preview.Fields, backend.PresentationField{
					Name: k, Value: v, Required: false,
				})
			}
		}
		preview.Disclosure = "none"
		return preview, nil
	}
	preview.Disclosure, preview.Fields = describePDFields(pd, held)
	preview.RequestedFormat = extractPDFormat(pd)

	// Diagnostic: dump the raw stored document JWT payload so we can confirm
	// exactly where walt.id's matcher would resolve the PD's JSONPaths.
	// Match runs against SDJwt.parse(document).fullPayload — so if the
	// holder/subject fields don't live at $.vc.credentialSubject.* in that
	// payload, matchPD returns zero. Log both the PD and each credential's
	// decoded payload so the mismatch is visible in one place.
	if pdJSON, err := json.Marshal(pd); err == nil {
		log.Printf("waltid: PreviewPresentation PD=%s", string(pdJSON))
	}
	a.dumpWalletDocumentPayloads(authCtx, sess.WalletID)

	// Walt.id's wallet-api is the authority on whether a credential
	// satisfies a PD. Ask it directly so the consent page reflects what
	// the submit will actually do.
	matches, ok := a.matchPD(authCtx, sess.WalletID, pd)
	log.Printf("waltid: PreviewPresentation walletID=%s credReq=%s held=%d matched=%d ok=%v heldNotNil=%v",
		sess.WalletID, req.CredentialID, len(creds), len(matches), ok, held != nil)
	for i, c := range creds {
		log.Printf("waltid: PreviewPresentation held[%d] id=%s title=%q format=%s fields=%v",
			i, c.ID, c.Title, c.Format, c.Fields)
	}
	if !ok {
		return preview, nil
	}
	if len(matches) == 0 {
		preview.Compatible = false
		preview.IncompatibleReason = incompatibilityMessage(pd, creds, preview.RequestedFormat) +
			summariseHeldForDiagnostic(creds, preview.RequestedFormat)
		return preview, nil
	}
	for _, row := range matches {
		var id string
		_ = json.Unmarshal(row["id"], &id)
		if id == req.CredentialID {
			return preview, nil
		}
	}
	// The user picked something walt.id wouldn't accept, but walt.id DID
	// find a compatible credential in this same wallet. Auto-swap to it —
	// the user's wallet has multiple credentials of the same title and
	// they can't tell from the UI which one is the compatible one.
	// Refreshing the values from the match's parsedDocument keeps the
	// consent card honest about what's in the picked credential.
	var autoID string
	_ = json.Unmarshal(matches[0]["id"], &autoID)
	if autoID != "" {
		preview.CredentialID = autoID
		// Re-pair field values against the auto-selected credential.
		for i := range creds {
			if creds[i].ID == autoID {
				_, preview.Fields = describePDFields(pd, &creds[i])
				preview.CredentialTitle = creds[i].Title
				break
			}
		}
		return preview, nil
	}
	// No usable id in the match rows — fall back to incompatibility.
	preview.Compatible = false
	preview.IncompatibleReason = fmt.Sprintf(
		"walt.id found %d compatible credential(s) but couldn't surface an id to auto-select. Go back and pick a %s credential manually.",
		len(matches), preview.RequestedFormat)
	return preview, nil
}

// selectRequestedDisclosures returns the subset of SD-JWT disclosures for
// credID that the verifier's PD requests. Walt.id's wallet-api stores the
// raw disclosure strings separately from the JWS; we fetch the credential,
// decode each base64url(JSON([salt, claim, value])) disclosure, and keep
// only those whose claim name maps to a path in the PD's
// constraints.fields. An empty return means either no match (the PD's
// paths don't correspond to any disclosure) or the credential isn't an
// SD-JWT (disclosures field empty) — both cases are caller-safe; walt.id
// falls back to "include everything" which fails the verifier's
// limit_disclosure policy, so the caller should interpret "" as "can't
// selectively disclose for this combo".
func (a *Adapter) selectRequestedDisclosures(ctx context.Context, walletID, credID string, pd map[string]any) []string {
	// Pull the single credential to access its raw disclosures.
	var cred map[string]json.RawMessage
	if err := a.wallet.DoJSON(ctx, http.MethodGet,
		fmt.Sprintf("/wallet-api/wallet/%s/credentials/%s", walletID, url.PathEscape(credID)),
		nil, &cred, nil); err != nil {
		log.Printf("waltid: fetch credential for disclosures: %v", err)
		return nil
	}
	var discStr string
	if err := json.Unmarshal(cred["disclosures"], &discStr); err != nil || discStr == "" {
		return nil
	}
	// Disclosures come as `~`-separated base64url strings.
	items := []string{}
	for _, p := range strings.Split(discStr, "~") {
		if p = strings.TrimSpace(p); p != "" {
			items = append(items, p)
		}
	}
	// Requested claim names from the PD (strip the JSONPath prefixes).
	wanted := map[string]bool{}
	ds, _ := pd["input_descriptors"].([]any)
	for _, d := range ds {
		dm, _ := d.(map[string]any)
		if dm == nil {
			continue
		}
		cons, _ := dm["constraints"].(map[string]any)
		if cons == nil {
			continue
		}
		fields, _ := cons["fields"].([]any)
		for _, f := range fields {
			fm, _ := f.(map[string]any)
			if fm == nil {
				continue
			}
			paths, _ := fm["path"].([]any)
			for _, p := range paths {
				s, _ := p.(string)
				name := claimNameFromPath(s)
				if name != "" {
					wanted[name] = true
				}
			}
		}
	}
	// Filter disclosures: each is base64url([salt, claim, value]).
	out := []string{}
	for _, d := range items {
		claim := claimNameOfDisclosure(d)
		if claim != "" && wanted[claim] {
			out = append(out, d)
		}
	}
	return out
}

// claimNameOfDisclosure base64url-decodes an SD-JWT disclosure and returns
// its claim name. Returns "" on any decode / shape failure.
func claimNameOfDisclosure(d string) string {
	raw, err := base64.RawURLEncoding.DecodeString(d)
	if err != nil {
		// try standard + padding
		raw, err = base64.URLEncoding.DecodeString(d + strings.Repeat("=", (4-len(d)%4)%4))
		if err != nil {
			return ""
		}
	}
	var arr []any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return ""
	}
	if len(arr) >= 3 {
		if s, ok := arr[1].(string); ok {
			return s
		}
	}
	return ""
}

// extractPDFormat reads the first input_descriptor's format map and returns
// the single key (walt.id always emits exactly one per descriptor).
// Returns "" if the shape isn't what we expect.
func extractPDFormat(pd map[string]any) string {
	ds, _ := pd["input_descriptors"].([]any)
	if len(ds) == 0 {
		return ""
	}
	d, _ := ds[0].(map[string]any)
	if d == nil {
		return ""
	}
	fm, _ := d["format"].(map[string]any)
	for k := range fm {
		return k
	}
	return ""
}

// incompatibilityMessage produces the "why no match" sentence. When the
// wallet holds credentials of the same type but in different wire formats,
// name BOTH formats explicitly — the operator's usual fix is either
// (a) ask the verifier to request the format the holder has, or
// (b) re-issue in the format the verifier wants. Saying only "not in X
// format" without naming the format the holder DOES have leaves them
// guessing why walt.id (which sees both as "w3c_vcdm_2") insists on an
// exact wire-format match.
func incompatibilityMessage(pd map[string]any, held []vctypes.Credential, wantFormat string) string {
	wantType, _ := describePD(pd)
	// Collect the formats the wallet has this type in.
	haveFormats := map[string]bool{}
	var sameTitle string
	for _, c := range held {
		if strings.EqualFold(sanitizeIncompatibleName(c.Title), sanitizeIncompatibleName(wantType)) {
			sameTitle = c.Title
			if c.Format != "" {
				haveFormats[c.Format] = true
			}
		}
	}
	if sameTitle != "" {
		fmts := make([]string, 0, len(haveFormats))
		for f := range haveFormats {
			if f != wantFormat {
				fmts = append(fmts, f)
			}
		}
		if len(fmts) > 0 {
			return fmt.Sprintf(
				"your wallet has %q in %s but this verifier is asking for %s specifically. Walt.id's matcher treats each wire format as distinct even when they belong to the same taxonomy (w3c_vcdm_2 covers jwt_vc_json, jwt_vc_json-ld, ldp_vc, and jwt_vc separately). Ask the verifier to request %s, or re-issue the credential as %s.",
				sameTitle,
				strings.Join(fmts, ", "),
				wantFormat,
				fmts[0],
				wantFormat)
		}
		return fmt.Sprintf(
			"your wallet has %q but not in %s format. Walt.id rejects format mismatches even when the type matches. Re-issue the credential in %s or pick a different credential type.",
			sameTitle, wantFormat, wantFormat)
	}
	return fmt.Sprintf(
		"your wallet has no credential matching this request (verifier asked for %s in %s format). Accept a matching offer first, then try again.",
		wantType, wantFormat)
}

// summariseHeldForDiagnostic produces a short human-readable suffix listing
// the wallet's actual credential identifiers (vct for SD-JWT, type for JWT)
// so the "no match" toast tells the operator exactly why walt.id's wallet
// matcher rejected. Format: " [DIAG: wallet=2 vct=foo (vc+sd-jwt), vct=bar
// (vc+sd-jwt)]". Returns the explicit "wallet=0" suffix when the wallet is
// empty so the operator can rule that out — earlier "" returns made the
// fallback indistinguishable from "code didn't ship", reported on
// 2026-04-30.
//
// The DIAG: prefix is intentionally machine-greppable so we can quickly
// confirm whether the user is running the latest build by glancing at
// their error message.
func summariseHeldForDiagnostic(held []vctypes.Credential, wantFormat string) string {
	if len(held) == 0 {
		return " [DIAG: wallet=0 (empty — but if your picker showed a credential you may be hitting a per-user-wallet routing bug; share /tmp logs)]"
	}
	parts := make([]string, 0, len(held))
	for _, c := range held {
		// Prefer the most identifying claim per format.
		switch {
		case strings.HasPrefix(c.Format, "vc+sd-jwt") || strings.HasPrefix(c.Format, "dc+sd-jwt"):
			if vct := c.Fields["vct"]; vct != "" {
				parts = append(parts, fmt.Sprintf("vct=%q (%s)", vct, c.Format))
				continue
			}
		case c.Format == "mso_mdoc":
			if dt := c.Fields["doctype"]; dt != "" {
				parts = append(parts, fmt.Sprintf("doctype=%q (%s)", dt, c.Format))
				continue
			}
		}
		// Fallback: title + format.
		title := c.Title
		if title == "" {
			title = "(unnamed)"
		}
		parts = append(parts, fmt.Sprintf("%q (%s)", title, c.Format))
	}
	if len(parts) == 0 {
		return ""
	}
	suffix := fmt.Sprintf(" [DIAG: wallet=%d %s]", len(held), strings.Join(parts, ", "))
	// Hint the most common cause when the verifier asked for SD-JWT but
	// every held credential has a different vct: stale credential issued
	// before vct alignment landed.
	if strings.HasPrefix(wantFormat, "vc+sd-jwt") || strings.HasPrefix(wantFormat, "dc+sd-jwt") {
		suffix += " (if a held vct starts with 'custom-' the credential was issued before the type/vct alignment fix — re-issue to get the canonical type name baked in)"
	}
	return suffix
}

// sanitizeIncompatibleName strips spaces + punctuation so "Open Badge
// Credential" compares equal to "OpenBadgeCredential".
func sanitizeIncompatibleName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return strings.ToLower(b.String())
}

// describePDFields extracts the requested field list from a PD and pairs
// each with the held credential's value (when available). Returns the
// limit_disclosure hint so the UI can describe what the wallet will
// actually do — "required" truly restricts, "preferred" is advisory,
// "none" means the entire credential goes.
func describePDFields(pd map[string]any, held *vctypes.Credential) (string, []backend.PresentationField) {
	descriptors, _ := pd["input_descriptors"].([]any)
	if len(descriptors) == 0 {
		return "none", nil
	}
	d, _ := descriptors[0].(map[string]any)
	if d == nil {
		return "none", nil
	}
	constraints, _ := d["constraints"].(map[string]any)
	if constraints == nil {
		return "none", nil
	}
	disclosure, _ := constraints["limit_disclosure"].(string)
	if disclosure == "" {
		disclosure = "none"
	}
	fields, _ := constraints["fields"].([]any)
	out := make([]backend.PresentationField, 0, len(fields))
	for _, f := range fields {
		m, _ := f.(map[string]any)
		if m == nil {
			continue
		}
		paths, _ := m["path"].([]any)
		if len(paths) == 0 {
			continue
		}
		p, _ := paths[0].(string)
		name := claimNameFromPath(p)
		if name == "" {
			continue // filter-only paths like $.vct + $.vc.type don't name a claim
		}
		val := ""
		if held != nil {
			val = held.Fields[name]
		}
		out = append(out, backend.PresentationField{
			Name: name, Value: val, Required: true,
		})
	}
	return disclosure, out
}

// claimNameFromPath strips JSONPath prefixes to yield the plain claim name
// the UI should render. Drops the vct/type filter paths (those describe
// credential identity, not claims to share).
func claimNameFromPath(path string) string {
	// SD-JWT top-level: $.<field>
	if strings.HasPrefix(path, "$.") {
		p := strings.TrimPrefix(path, "$.")
		if p == "vct" || p == "vc.type" {
			return ""
		}
		if strings.HasPrefix(p, "vc.credentialSubject.") {
			return strings.TrimPrefix(p, "vc.credentialSubject.")
		}
		return p
	}
	// mdoc: $['namespace']['field']
	if strings.HasPrefix(path, "$[") {
		// Crude bracket-parse: last ['<name>'] is the field.
		end := strings.LastIndex(path, "']")
		if end < 0 {
			return path
		}
		start := strings.LastIndex(path[:end], "['")
		if start < 0 {
			return path
		}
		return path[start+2 : end]
	}
	return path
}

// extractClientID pulls the client_id query param from an openid4vp:// URI
// so the consent page can name the verifier.
func extractClientID(requestURI string) string {
	u, err := url.Parse(requestURI)
	if err != nil {
		return ""
	}
	return u.Query().Get("client_id")
}

// dumpWalletDocumentPayloads fetches the wallet's credential listing and
// logs the decoded JWT payload for each credential that has one. Purely
// diagnostic; used to confirm the shape of fullPayload that walt.id's
// PD matcher sees when evaluating JSONPath constraints.
func (a *Adapter) dumpWalletDocumentPayloads(ctx context.Context, walletID string) {
	var raw []map[string]json.RawMessage
	if err := a.wallet.DoJSON(ctx, http.MethodGet,
		fmt.Sprintf("/wallet-api/wallet/%s/credentials", walletID),
		nil, &raw, nil); err != nil {
		log.Printf("waltid: dump payloads: list failed: %v", err)
		return
	}
	for _, c := range raw {
		var id, format, doc string
		_ = json.Unmarshal(c["id"], &id)
		_ = json.Unmarshal(c["format"], &format)
		_ = json.Unmarshal(c["document"], &doc)
		if doc == "" {
			_ = json.Unmarshal(c["jwt"], &doc)
		}
		if doc == "" {
			log.Printf("waltid: dump payloads id=%s format=%s (no document)", id, format)
			continue
		}
		parts := strings.SplitN(doc, ".", 3)
		if len(parts) < 2 {
			log.Printf("waltid: dump payloads id=%s format=%s (non-JWT document)", id, format)
			continue
		}
		body, err := base64urlDecode(parts[1])
		if err != nil {
			log.Printf("waltid: dump payloads id=%s format=%s decode err=%v", id, format, err)
			continue
		}
		log.Printf("waltid: dump payloads id=%s format=%s payload=%s", id, format, string(body))
	}
}

// matchPD calls walt.id's match endpoint with an inline PD. Returns
// (matches, ok). ok=false means the endpoint itself errored (network
// fault, older wallet-api build without the endpoint); callers must
// NOT treat that as "no matches found" — fall back to submitting with
// the user-picked id and let walt.id return its own error.
func (a *Adapter) matchPD(ctx context.Context, walletID string, pd map[string]any) ([]map[string]json.RawMessage, bool) {
	var matched []map[string]json.RawMessage
	if err := a.wallet.DoJSON(ctx, "POST",
		fmt.Sprintf("/wallet-api/wallet/%s/exchange/matchCredentialsForPresentationDefinition", walletID),
		pd, &matched, nil); err != nil {
		log.Printf("waltid: matchPD failed: %v", err)
		return nil, false
	}
	return matched, true
}

// pickBestMatch picks the highest-ranked (walt.id-tested format) id from
// the match results. Falls back to the user-picked id if the ranking
// produced no winner (all 0-ranked).
func pickBestMatch(matched []map[string]json.RawMessage, fallback string) string {
	best := -1
	bestID := fallback
	for _, row := range matched {
		var id, fmtVal string
		_ = json.Unmarshal(row["id"], &id)
		_ = json.Unmarshal(row["format"], &fmtVal)
		if id == "" {
			continue
		}
		rank := vpFormatRank(fmtVal)
		log.Printf("waltid: match candidate id=%s format=%s rank=%d", id, fmtVal, rank)
		if rank > best {
			best = rank
			bestID = id
		}
	}
	log.Printf("waltid: picked id=%s rank=%d from %d matches", bestID, best, len(matched))
	return bestID
}

// pdDescriptorCount reports how many input-descriptors a presentation
// definition has (i.e. how many credentials the verifier is asking for).
func pdDescriptorCount(pd map[string]any) int {
	ds, _ := pd["input_descriptors"].([]any)
	return len(ds)
}

// allMatchedIDs returns the deduped ids of every credential the wallet matched
// against the PD — used to present a credential per input-descriptor for a
// multi-credential (e.g. delegated-access) request.
func allMatchedIDs(matched []map[string]json.RawMessage) []string {
	out := make([]string, 0, len(matched))
	seen := map[string]bool{}
	for _, row := range matched {
		var id string
		_ = json.Unmarshal(row["id"], &id)
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// describePD extracts a human-readable (type, format) pair from a PD's
// first input descriptor. Used to explain failures when the wallet has
// nothing matching — the UI can tell the user "you need a <type> in
// <format> format" instead of the opaque walt.id error.
func describePD(pd map[string]any) (typeName, format string) {
	typeName = "VerifiableCredential"
	format = "any"
	descriptors, _ := pd["input_descriptors"].([]any)
	if len(descriptors) == 0 {
		return
	}
	d, _ := descriptors[0].(map[string]any)
	if d == nil {
		return
	}
	// Format is a map keyed by the VP format name (e.g. "vc+sd-jwt").
	if fm, ok := d["format"].(map[string]any); ok {
		for k := range fm {
			format = k
			break
		}
	}
	// Type is declared via constraints.fields[*].filter.const|pattern or
	// via the input-descriptor's id on walt.id's generated PDs.
	if id, ok := d["id"].(string); ok && id != "" {
		typeName = id
	}
	return
}

// friendlyClaimError translates the most common cross-issuer interop
// failures walt.id's wallet surfaces on /exchange/useOfferRequest. Raw
// wallet errors read as opaque 400s; the operator needs to know whether
// the issue is their offer, the issuer's metadata, or a known quirk.
func friendlyClaimError(err error, _ string) error {
	msg := err.Error()
	// Inji Certify ↔ walt.id interop: Inji Certify's offer advertises
	// credential_issuer="http://inji-certify-preauth:8090" but only serves
	// /.well-known/openid-credential-issuer at /v1/certify/issuance/
	// .well-known/openid-credential-issuer. Walt.id fetches the standard
	// "{issuer}/.well-known/openid-credential-issuer" path, gets 404,
	// returns no offered credentials, and 400s on our claim call.
	if strings.Contains(msg, "Resolved an empty list of offered credentials") {
		return fmt.Errorf("walt.id's wallet couldn't resolve this offer: it fetched the issuer's .well-known metadata but got no matching credential configurations. This usually means the offer's `credential_issuer` URL doesn't point at the directory that serves the metadata (a known Inji Certify quirk — Inji Certify advertises http://…:8090 as the issuer but its well-known lives under /v1/certify/issuance/). Use Inji Web Wallet for Inji Certify offers, or ask the issuer admin to fix the credential_issuer URL.")
	}
	return fmt.Errorf("wallet claim failed: %s", truncateClaim(msg, 200))
}

// formatFromConfigID extracts the walt.id format key from a configuration
// id like "AlpsTourReservation_jwt_vc_json-ld" → "jwt_vc_json-ld". Returns
// "" when none of the known suffixes match (e.g. when configID is empty).
func formatFromConfigID(configID string) string {
	for _, suf := range []string{
		"jwt_vc_json-ld", "jwt_vc_json", "vc+sd-jwt", "dc+sd-jwt",
		"mso_mdoc", "ldp_vc", "jwt_vc",
	} {
		if strings.HasSuffix(configID, "_"+suf) {
			return suf
		}
	}
	return ""
}

func truncateClaim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// friendlyPresentError translates walt.id's wallet 400 body into a message
// a non-walt.id-literate operator can act on. Empirically (against
// walt.id Community Stack v0.18.2):
//
//   - "JsonArray is not a JsonPrimitive" fires when the wallet tries to
//     build a vp_token for a credential in a format whose VP payload is a
//     JSON object/array (ldp_vc, jwt_vc_json-ld) rather than a compact
//     JWT string. walt.id's VP submit path calls .jsonPrimitive on the
//     vpToken unconditionally (SSIKit2WalletService.kt) — fine for
//     jwt_vc_json / vc+sd-jwt, throws for the others.
//   - "VCFormat does not contain element with name 'jwt_vc_json-ld'" —
//     the verifier's Kotlin format enum is missing that literal, so
//     creating the verifier session for a jwt_vc_json-ld filter fails.
//   - "presentationDefinitionMatch" + "false" — no held credential
//     satisfies the PD; the pre-flight in PresentCredential usually
//     catches this first with a more specific message.
// RevocationError is the sentinel error friendlyPresentError returns when
// walt.id's wallet-api rejects the presentation because the credential's
// status-list policy failed. Carrying it as a typed value lets the
// handler swap to a revocation-specific fragment instead of toasting
// the raw 400 body — the operator's view of "this credential was
// revoked by the issuer" is much clearer than walt.id's stack trace.
//
// Detection is by substring on walt.id's error body. v0.18.2 surfaces
// the policy name "credential-status" alongside the verifier-side
// "Status validation failed: expected X, but got Y" message; either
// signal is sufficient.
type RevocationError struct {
	// Detail is the underlying walt.id message, kept for logs / debug
	// and shown in small print under the friendly headline so the
	// operator can paste it into a support ticket.
	Detail string
}

func (e *RevocationError) Error() string {
	return "credential has been revoked by the issuer"
}

// IsRevocation reports whether err originated from a status-list policy
// failure. Used by the present-credential handler to dispatch to the
// revocation fragment.
func IsRevocation(err error) bool {
	if err == nil {
		return false
	}
	var re *RevocationError
	return errors.As(err, &re)
}

func friendlyPresentError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "credential-status") && strings.Contains(msg, "Status validation failed"):
		return &RevocationError{Detail: msg}
	case strings.Contains(msg, "JsonArray") && strings.Contains(msg, "JsonPrimitive"):
		return fmt.Errorf(
			"walt.id's wallet-api v0.18.2 can't build a verifiable presentation for this credential format — its VP submit path only handles compact-JWT formats (jwt_vc_json, vc+sd-jwt). For jwt_vc_json-ld and ldp_vc the vpToken is a JSON object and the wallet throws internally. Re-issue the credential in JWT · W3C (jwt_vc_json) or SD-JWT · VC (vc+sd-jwt) and retry")
	case strings.Contains(msg, "VCFormat does not contain"):
		return fmt.Errorf(
			"walt.id's verifier doesn't recognise this format (e.g. jwt_vc_json-ld is not in its Kotlin format enum). Re-issue the credential in a format the verifier supports — jwt_vc_json, ldp_vc, jwt_vc, or vc+sd-jwt all round-trip end-to-end")
	case strings.Contains(msg, "presentationDefinitionMatch") && strings.Contains(msg, "false"):
		return fmt.Errorf("the wallet couldn't build a presentation the verifier would accept — typically the held credential's format doesn't match what was requested")
	case strings.Contains(msg, "signature") && strings.Contains(msg, "policy"):
		return fmt.Errorf("the credential's signature could not be verified by the verifier (the issuer's key may not be trusted by this verifier)")
	}
	return err
}

// jsonReaderBytes adapts a precomputed []byte for DoRaw's io.Reader argument.
func jsonReaderBytes(b []byte) *strings.Reader { return strings.NewReader(string(b)) }

// mustJSON marshals v or returns a JSON null on error. Used when we're
// building a small, known-safe map in code — failures are programmer bugs,
// not runtime errors.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("null")
	}
	return b
}

// walletCredentialToVctype maps a walt.id WalletCredential onto vctypes.Credential.
// The walt.id shape varies by credential format; we extract claims from
// whichever body field is populated:
//   - `parsedDocument` for JSON-LD VCs (already decoded)
//   - `document` / `jwt` for JWT-style VCs (a compact JWS whose payload holds `vc`)
//
// All scalar claim types (string, number, boolean) are rendered into a
// string for display; object/array values (address, dependents, etc.) are
// JSON-encoded so the card still surfaces them instead of silently
// dropping them, which was the symptom users saw for VCs that carry
// anything other than flat strings.
func walletCredentialToVctype(raw map[string]json.RawMessage) vctypes.Credential {
	var id string
	_ = json.Unmarshal(raw["id"], &id)
	var format string
	_ = json.Unmarshal(raw["format"], &format)

	cred := vctypes.Credential{
		ID:     id,
		Status: "accepted",
		Type:   stdFromFormat(format),
		Format: format,
		Fields: map[string]string{},
	}

	// Prefer parsedDocument (JSON-LD, already-decoded). Fall back to
	// decoding the `document` or `jwt` compact JWS and reading the `vc`
	// payload claim.
	parsed := pickParsedDocument(raw)
	if parsed != nil {
		if issuer := parsed["issuer"]; issuer != nil {
			cred.Issuer = issuerString(issuer)
		}
		// SD-JWT VCs carry the issuer DID/URL on the JWT body's `iss`
		// claim, NOT in `issuer`. Without this branch the wallet card
		// would render "Unknown issuer" for every SD-JWT credential.
		if cred.Issuer == "" {
			if issRaw := parsed["iss"]; issRaw != nil {
				var iss string
				if err := json.Unmarshal(issRaw, &iss); err == nil && iss != "" {
					cred.Issuer = iss
				}
			}
		}
		var types []string
		if err := json.Unmarshal(parsed["type"], &types); err == nil && len(types) > 1 {
			cred.Title = humanise(types[len(types)-1])
		}
		// SD-JWT VC's `vct` sits at the root of the payload (not in
		// credentialSubject). Surface it for verifier-side debugging +
		// for the Title fallback on SD-JWT creds that don't carry a
		// `type` array.
		if vctRaw := parsed["vct"]; vctRaw != nil {
			var vct string
			if err := json.Unmarshal(vctRaw, &vct); err == nil && vct != "" {
				cred.Fields["vct"] = vct
				if cred.Title == "" {
					if i := strings.LastIndex(vct, "/"); i >= 0 {
						cred.Title = humanise(vct[i+1:])
					} else {
						cred.Title = humanise(vct)
					}
				}
			}
		}
		var subject map[string]any
		if err := json.Unmarshal(parsed["credentialSubject"], &subject); err == nil {
			for k, v := range subject {
				if k == "id" {
					continue
				}
				cred.Fields[k] = stringifyClaim(v)
			}
		}
		// For SD-JWT, top-level claims ARE the credential subject.
		// Walk root-level primitive keys (excluding SD control fields).
		for k, raw := range parsed {
			if k == "_sd" || k == "_sd_alg" || k == "cnf" || k == "iss" ||
				k == "iat" || k == "exp" || k == "nbf" || k == "sub" ||
				k == "vct" || k == "status" || k == "type" || k == "@context" ||
				k == "credentialSubject" || k == "issuer" || k == "id" {
				continue
			}
			var v any
			if err := json.Unmarshal(raw, &v); err == nil {
				cred.Fields[k] = stringifyClaim(v)
			}
		}
	}
	// When walt.id issued this SD-JWT with selectiveDisclosure set, every
	// subject claim lives in the separate `disclosures` blob, NOT in
	// parsedDocument — the payload only carries _sd/cnf/vct. Decode each
	// disclosure (base64url-encoded [salt, claim, value]) so the wallet
	// card still shows real field values. Without this the UI renders an
	// empty card even though the holder has a perfectly valid SD-JWT in
	// their wallet.
	if format == "vc+sd-jwt" || format == "dc+sd-jwt" {
		var discStr string
		if err := json.Unmarshal(raw["disclosures"], &discStr); err == nil && discStr != "" {
			for _, seg := range strings.Split(discStr, "~") {
				seg = strings.TrimSpace(seg)
				if seg == "" {
					continue
				}
				decoded, err := base64.RawURLEncoding.DecodeString(seg)
				if err != nil {
					decoded, err = base64.URLEncoding.DecodeString(seg + strings.Repeat("=", (4-len(seg)%4)%4))
					if err != nil {
						continue
					}
				}
				var arr []any
				if err := json.Unmarshal(decoded, &arr); err != nil {
					continue
				}
				if len(arr) >= 3 {
					if claimName, ok := arr[1].(string); ok {
						cred.Fields[claimName] = stringifyClaim(arr[2])
					}
				}
			}
		}
	}
	if cred.Title == "" {
		cred.Title = "Credential"
	}
	if cred.Issuer == "" {
		cred.Issuer = "Unknown issuer"
	}
	return cred
}

// pickParsedDocument returns the decoded VC body from whichever walt.id
// field carries it. JSON-LD VCs use parsedDocument directly; JWT-encoded
// VCs store a compact three-dot JWS in `document` or `jwt`, whose payload
// holds the VC claim either at the top level or nested under `vc`.
func pickParsedDocument(raw map[string]json.RawMessage) map[string]json.RawMessage {
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(raw["parsedDocument"], &parsed); err == nil && len(parsed) > 0 {
		return parsed
	}
	for _, field := range []string{"document", "jwt"} {
		var jws string
		if err := json.Unmarshal(raw[field], &jws); err != nil || jws == "" {
			continue
		}
		if payload := decodeJWSPayload(jws); payload != nil {
			if vcRaw, ok := payload["vc"]; ok {
				var vc map[string]json.RawMessage
				if err := json.Unmarshal(vcRaw, &vc); err == nil {
					return vc
				}
			}
			return payload
		}
	}
	return nil
}

// decodeJWSPayload base64url-decodes the middle segment of a compact JWS
// and unmarshals it as a JSON object. Returns nil on any error.
func decodeJWSPayload(jws string) map[string]json.RawMessage {
	parts := strings.SplitN(jws, ".", 3)
	if len(parts) < 2 {
		return nil
	}
	body, err := base64urlDecode(parts[1])
	if err != nil {
		return nil
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(body, &out); err != nil {
		return nil
	}
	return out
}

// stringifyClaim coerces any JSON claim value into a human-readable string.
// Scalars render as themselves; containers (objects, arrays) are
// JSON-encoded so the card still surfaces them rather than silently
// dropping non-string claim values.
func stringifyClaim(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		// json.Unmarshal into any gives float64 for numbers; trim the
		// trailing .0 for integers so "25" doesn't render as "25.0".
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func issuerString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err == nil {
		if id, ok := obj["id"].(string); ok {
			return id
		}
	}
	return ""
}

func stdFromFormat(format string) string {
	switch format {
	case "jwt_vc_json", "jwt_vc_json-ld", "ldp_vc":
		return "w3c_vcdm_2"
	case "vc+sd-jwt", "dc+sd-jwt":
		return "sd_jwt_vc (IETF)"
	case "mso_mdoc":
		return "mso_mdoc"
	default:
		return "w3c_vcdm_2"
	}
}

// humanise converts CamelCase to "Camel Case".
func humanise(s string) string {
	var out []rune
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			out = append(out, ' ')
		}
		out = append(out, r)
	}
	return string(out)
}

func generatePassword() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// referenced to keep the import used
var _ http.Request
