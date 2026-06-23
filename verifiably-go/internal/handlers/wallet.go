package handlers

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// holderCtx wraps r.Context() with the selected holder DPG so the Registry
// can route holder-scoped adapter calls when multiple holders are registered.
// Used by every wallet.go handler that touches the Adapter; safe to call even
// when sess.HolderDpg is "" (WithHolderDpg is a no-op).
func holderCtx(r *http.Request, sess *Session) context.Context {
	ctx := backend.WithHolderDpg(r.Context(), sess.HolderDpg)
	// Partition upstream wallet state per authenticated identity. Prefer
	// AuthProvider+Subject (the OIDC `sub` claim is guaranteed non-empty
	// for a valid session, email isn't — admins, machine accounts, and
	// any IdP that doesn't surface email would otherwise collide on the
	// fallback). Then try email, then the session-scoped fallback for
	// unauthenticated demo mode. Each distinct key maps to its own
	// wallet account upstream.
	// Freeze the wallet key on first use so credentials claimed early in
	// the session (before OIDC `sub` was populated) stay reachable after
	// a later auth flow fills it in — otherwise holderCtx would flip
	// userKey mid-session and a subsequent /holder/present would reach
	// into a different walt.id wallet than the one the credential landed
	// in. AuthCallback clears WalletUserKey so the next login derives fresh.
	if sess.WalletUserKey == "" {
		switch {
		case sess.AuthProvider != "" && sess.UserSubject != "":
			sess.WalletUserKey = sess.AuthProvider + "|" + sess.UserSubject
		case sess.UserEmail != "":
			sess.WalletUserKey = sess.UserEmail
		default:
			sess.WalletUserKey = "session-" + sess.ID
		}
	}
	log.Printf("holderCtx sess.ID=%s authProv=%q sub=%q email=%q → userKey=%q (frozen)",
		sess.ID, sess.AuthProvider, sess.UserSubject, sess.UserEmail, sess.WalletUserKey)
	return backend.WithHolderIdentity(ctx, sess.WalletUserKey)
}

// issuerCtx is the issuer-side mirror of holderCtx: it attaches the
// per-operator identity key to ctx so the Registry can scope its
// in-memory custom-schema slice (and subsequent owner-checked actions)
// to the calling issuer's view. Same fallback chain as holderCtx —
// AuthProvider+Subject when authenticated, then email, then a session-
// scoped key for unauthenticated demo flows. Empty key never reaches
// the Registry; the helpers there bypass scoping when the key is
// unset (admin/CLI semantics).
//
// Callers: every handler that touches Adapter.ListSchemas /
// ListAllSchemas / SaveCustomSchema / DeleteCustomSchema should pass
// issuerCtx(r, sess) instead of r.Context() so the schema browser is
// per-operator, not global.
func issuerCtx(r *http.Request, sess *Session) context.Context {
	return backend.WithIssuerIdentity(r.Context(), sessionOwnerKey(sess))
}

// ShowWallet renders the wallet home (receive + inbox + held credentials).
// First visit lazy-loads held credentials from the adapter.
func (h *H) ShowWallet(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.HolderDpg == "" {
		h.redirect(w, r, "/holder/dpg")
		return
	}
	if sess.WalletCreds == nil {
		creds, err := h.Adapter.ListWalletCredentials(holderCtx(r, sess))
		if err != nil {
			h.errorToast(w, r, err.Error())
			return
		}
		h.attachIssuerDisplayToCreds(r.Context(), creds)
		sess.WalletCreds = creds
	}
	h.render(w, r, "holder_wallet", h.pageData(sess, nil))
}

// attachIssuerDisplayToCreds populates Credential.IssuerDisplay by looking
// up each credential's Title against Schema.Name in the Registry's merged
// schema list — the only place that knows IssuerDisplayName, since walt.id
// 0.18.2 has no wellknown field that would let it round-trip back through
// adapter.ListSchemas. Best-effort: silent on lookup failure so the wallet
// still renders (with the bare DID as fallback).
func (h *H) attachIssuerDisplayToCreds(ctx context.Context, creds []vctypes.Credential) {
	if len(creds) == 0 {
		return
	}
	schemas, err := h.Adapter.ListAllSchemas(ctx)
	if err != nil {
		return
	}
	byTitle := make(map[string]string, len(schemas))
	for _, s := range schemas {
		if iss := strings.TrimSpace(s.IssuerDisplayName); iss != "" {
			byTitle[strings.ToLower(strings.TrimSpace(s.Name))] = iss
		}
	}
	for i := range creds {
		if iss, ok := byTitle[strings.ToLower(strings.TrimSpace(creds[i].Title))]; ok {
			creds[i].IssuerDisplay = iss
		}
	}
}

// ScanOffer simulates scanning a QR — cycles through example offers from the adapter.
func (h *H) ScanOffer(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	examples, err := h.Adapter.ListExampleOffers(r.Context())
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	if len(examples) == 0 {
		h.errorToast(w, r, "no example offers available")
		return
	}
	uri := examples[sess.NextExampleIdx%len(examples)]
	sess.NextExampleIdx++
	cred, err := h.Adapter.ParseOffer(holderCtx(r, sess), uri)
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	cred.Source = "scan"
	cred.ID = "pending-" + time.Now().Format("150405.000000")
	sess.WalletPending = append([]vctypes.Credential{cred}, sess.WalletPending...)
	h.renderFragment(w, r, "fragment_wallet_body", sess)
}

// explainPasteError rewrites the raw adapter error into an actionable
// message for the wallet paste flow. ErrNotLinked is the common case — the
// holder DPG is a redirect-style wallet (e.g. Inji Web) that requires an
// eSignet login before it can claim anything. Point the user at
// /holder/dpg so they can switch to a DPG that accepts raw offer URIs.
func explainPasteError(err error, currentDpg string) string {
	if errors.Is(err, backend.ErrNotLinked) {
		return fmt.Sprintf(
			"%q requires an eSignet login before it can receive offers — redirect-style wallets (like Inji Web) need an account link first. Two ways forward: (1) switch your holder DPG to Walt Community Stack on the DPG picker (it accepts raw openid-credential-offer:// URIs without linking), or (2) link the wallet's operator account first. Click “← Back” on the subtitle (or go to /holder/dpg) to switch.",
			currentDpg)
	}
	return err.Error()
}

// PasteOffer processes a pasted offer URI. Renders the wallet body on both
// success and failure so the user gets a visible result either way — toasts
// can be missed (browser focus, quick fade) but an inline error banner
// stays until the next action.
func (h *H) PasteOffer(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	raw := strings.TrimSpace(r.FormValue("offer_uri"))
	if raw == "" {
		sess.LastWalletError = "Paste an openid-credential-offer:// URI first"
		h.renderFragment(w, r, "fragment_wallet_body", sess)
		return
	}
	if !strings.HasPrefix(raw, "openid-credential-offer://") && !strings.HasPrefix(raw, "https://") {
		sess.LastWalletError = "That doesn't look like a credential offer URI — it should start with openid-credential-offer:// or https://"
		h.renderFragment(w, r, "fragment_wallet_body", sess)
		return
	}
	cred, err := h.Adapter.ParseOffer(holderCtx(r, sess), raw)
	if err != nil {
		sess.LastWalletError = explainPasteError(err, sess.HolderDpg)
		h.renderFragment(w, r, "fragment_wallet_body", sess)
		return
	}
	sess.LastWalletError = ""
	cred.Source = "paste"
	cred.ID = "pending-" + time.Now().Format("150405.000000")
	sess.WalletPending = append([]vctypes.Credential{cred}, sess.WalletPending...)
	h.renderFragment(w, r, "fragment_wallet_body", sess)
}

// PrefillExample returns a textarea pre-populated with an example offer URI.
// HTMX swaps the existing #offer-paste textarea with this one.
func (h *H) PrefillExample(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	examples, err := h.Adapter.ListExampleOffers(r.Context())
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	if len(examples) == 0 {
		h.errorToast(w, r, "no example offers available")
		return
	}
	uri := examples[sess.NextExampleIdx%len(examples)]
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("HX-Trigger", `{"toast":"Example offer URI pasted — click Process offer"}`)
	// URI may come from an untrusted adapter in the future, so escape.
	_, _ = w.Write([]byte(`<textarea id="offer-paste" name="offer_uri" rows="3" class="mono" style="font-size:0.78rem">` + template.HTMLEscapeString(uri) + `</textarea>`))
}

// AcceptCred moves a pending offer into held credentials.
func (h *H) AcceptCred(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	id := r.FormValue("id")
	idx := -1
	for i, c := range sess.WalletPending {
		if c.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		h.errorToast(w, r, "offer not found")
		return
	}
	pending := sess.WalletPending[idx]
	sess.WalletPending = append(sess.WalletPending[:idx], sess.WalletPending[idx+1:]...)
	claimed, err := h.Adapter.ClaimCredential(holderCtx(r, sess), pending)
	if err != nil {
		h.errorToast(w, r, err.Error())
		return
	}
	sess.WalletCreds = append([]vctypes.Credential{claimed}, sess.WalletCreds...)
	h.renderFragment(w, r, "fragment_wallet_body", sess)
}

// RejectCred discards a pending offer.
func (h *H) RejectCred(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	id := r.FormValue("id")
	found := false
	kept := make([]vctypes.Credential, 0, len(sess.WalletPending))
	for _, c := range sess.WalletPending {
		if c.ID == id {
			found = true
			continue
		}
		kept = append(kept, c)
	}
	if !found {
		h.errorToast(w, r, "offer not found")
		return
	}
	sess.WalletPending = kept
	h.renderFragment(w, r, "fragment_wallet_body", sess)
}

// ShowPresent renders the OID4VP presentation entry screen for the holder.
// An optional ?credential=<id> query pre-selects the credential in the
// picker; used when the holder clicks "Present this →" directly on a
// wallet card so they land on the form with their choice already made.
func (h *H) ShowPresent(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.HolderDpg == "" {
		h.redirect(w, r, "/holder/dpg")
		return
	}
	dpgs, _ := h.Adapter.ListHolderDpgs(r.Context())
	// Pull the holder's accepted credentials so the UI can render a picker.
	// Use the session's cached list if present; otherwise do a fresh adapter
	// call. Non-linked DPGs surface as an empty list (the template renders
	// an "accept an offer first" hint in that case).
	creds := sess.WalletCreds
	if len(creds) == 0 {
		if c, err := h.Adapter.ListWalletCredentials(holderCtx(r, sess)); err == nil {
			h.attachIssuerDisplayToCreds(r.Context(), c)
			creds = c
		}
	}
	preselect := r.URL.Query().Get("credential")
	h.render(w, r, "holder_present", h.pageData(sess, map[string]any{
		"HolderDpgObj":          dpgs[sess.HolderDpg],
		"Credentials":           creds,
		"PreselectCredentialID": preselect,
	}))
}

// ConfirmPresent renders the consent interstitial before an OID4VP submit.
// Fetches the verifier's PD, extracts the requested fields + the values
// the wallet would disclose, and presents them for the operator to review.
// Adapters that don't implement PresentationPreviewer get a minimal
// fallback preview (credential title only, no per-field breakdown).
func (h *H) ConfirmPresent(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.HolderDpg == "" {
		h.redirect(w, r, "/holder/dpg")
		return
	}
	credID := r.FormValue("credential_id")
	reqURI := r.FormValue("request_uri")
	if credID == "" || reqURI == "" {
		h.errorToast(w, r, "Pick a credential and paste the verifier's request URI")
		return
	}
	prev := backend.PresentationPreview{CredentialID: credID}
	if p, ok := h.Adapter.(backend.PresentationPreviewer); ok {
		resolved, err := p.PreviewPresentation(holderCtx(r, sess), backend.PresentCredentialRequest{
			HolderDpg:    sess.HolderDpg,
			CredentialID: credID,
			RequestURI:   reqURI,
		})
		if err != nil {
			h.errorToast(w, r, err.Error())
			return
		}
		prev = resolved
	}
	// Fill in the title from the session's cached wallet list if the
	// adapter didn't (minimum viable consent card still needs SOMETHING
	// recognisable to review).
	if prev.CredentialTitle == "" {
		for _, c := range sess.WalletCreds {
			if c.ID == credID {
				prev.CredentialTitle = c.Title
				break
			}
		}
	}
	h.renderFragment(w, r, "fragment_present_consent", map[string]any{
		"Preview":    prev,
		"RequestURI": reqURI,
	})
}

// SubmitPresent actually submits the OID4VP presentation after the holder
// clicks Disclose on the consent card. Same adapter call as before — the
// new layer is purely an interstitial that can be declined.
func (h *H) SubmitPresent(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.HolderDpg == "" {
		h.redirect(w, r, "/holder/dpg")
		return
	}
	credID := r.FormValue("credential_id")
	reqURI := r.FormValue("request_uri")
	if credID == "" || reqURI == "" {
		h.errorToast(w, r, "Pick a credential and paste the verifier's request URI")
		return
	}
	res, err := h.Adapter.PresentCredential(holderCtx(r, sess), backend.PresentCredentialRequest{
		HolderDpg:    sess.HolderDpg,
		CredentialID: credID,
		RequestURI:   reqURI,
	})
	if err != nil {
		// A revocation rejection is the operator-visible failure mode we
		// most need to humanize: walt.id returns 400 with a stack trace,
		// but what the holder needs to know is "your credential was
		// revoked, contact the issuer". Swap the consent card for a
		// revocation card in the same DOM target instead of toasting the
		// raw error.
		if isRevocationError(err) {
			title := credentialTitleFromSession(sess, credID)
			h.renderFragment(w, r, "fragment_present_revoked", map[string]any{
				"CredentialTitle": title,
				"Detail":          err.Error(),
			})
			return
		}
		h.errorToast(w, r, err.Error())
		return
	}
	h.renderFragment(w, r, "fragment_present_result", res)
}

// isRevocationError reports whether err originated from a status-list
// policy failure raised by the verifier. We probe via type assertion on
// the walt.id-specific sentinel rather than string-match here so the
// handler stays adapter-neutral; any future adapter that wraps the same
// failure pattern just has to expose a similar typed error.
func isRevocationError(err error) bool {
	type isRev interface{ Error() string }
	// Use string-match on the typed adapter error's stable headline.
	// We deliberately don't import the waltid package from handlers
	// (handler is adapter-neutral), so the contract is the surface text.
	if err == nil {
		return false
	}
	if e, ok := err.(isRev); ok {
		return strings.Contains(e.Error(), "credential has been revoked")
	}
	return false
}

// credentialTitleFromSession looks the credential up by id in the
// session's cached wallet list — the same fallback ConfirmPresent uses
// when the adapter doesn't surface a title — so the revocation card
// can show the holder which credential just failed.
func credentialTitleFromSession(sess *Session, credID string) string {
	for _, c := range sess.WalletCreds {
		if c.ID == credID {
			return c.Title
		}
	}
	return ""
}

// DeclinePresent renders a "declined" fragment when the holder refuses to
// disclose. No network call — just acknowledges the refusal and lets the
// user try again with a different credential or different disclosure.
func (h *H) DeclinePresent(w http.ResponseWriter, r *http.Request) {
	h.renderFragment(w, r, "fragment_present_declined", nil)
}

// DeleteCredential removes a held credential from the holder's wallet.
// Returns a toast on success/failure and triggers a wallet-list refresh
// via HX-Trigger so the card grid re-renders without a full page reload.
func (h *H) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	sess := h.Sessions.MustGet(w, r)
	if sess.HolderDpg == "" {
		h.redirect(w, r, "/holder/dpg")
		return
	}
	credID := r.FormValue("credential_id")
	if credID == "" {
		h.errorToast(w, r, "Missing credential id")
		return
	}
	if err := h.Adapter.DeleteWalletCredential(holderCtx(r, sess), credID); err != nil {
		h.errorToast(w, r, "Delete failed: "+err.Error())
		return
	}
	// Drop it from the session cache too so the next ShowWallet render
	// doesn't resurrect the card.
	filtered := sess.WalletCreds[:0]
	for _, c := range sess.WalletCreds {
		if c.ID != credID {
			filtered = append(filtered, c)
		}
	}
	sess.WalletCreds = filtered
	// Re-list to get the fresh picture + swap the whole body fragment.
	creds, _ := h.Adapter.ListWalletCredentials(holderCtx(r, sess))
	h.attachIssuerDisplayToCreds(r.Context(), creds)
	sess.WalletCreds = creds
	h.renderFragment(w, r, "fragment_wallet_body", sess)
}
