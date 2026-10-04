// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// The binding of the browser key (ADR-020 decision 4, ADR-073). After
// the browser makes its signing key, wallet.js binds it to the wallet
// once. The portal hands the page the signing input of a proof over the
// session id, the browser signs it, and the portal sends the public key
// and the proof to the wallet-auth service of its pair. That service
// answers a session token that names the key, and the portal sets it as
// the session cookie.
//
//	POST /holder-key/proof   the signing input of the proof
//	POST /holder-key         the public key and the signature

// keyProofHeader is the protected header of the proof.
var keyProofHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))

// keyProofInput is the signing input of the proof over a session id.
func keyProofInput(sid string) string {
	raw, err := json.Marshal(struct {
		SID string `json:"sid"`
	}{sid})
	if err != nil {
		return ""
	}
	return keyProofHeader + "." + base64.RawURLEncoding.EncodeToString(raw)
}

// bindsKey reports whether the portal binds the browser key: the
// browser store keeps the credentials, and wallet-auth takes the key.
func (p *Portal) bindsKey() bool {
	return p.opts.Service.BrowserStorage() && p.opts.Topology.RegisterKey != nil && p.shell.AuthURL() != ""
}

// holderKeyProof answers the signing input of the proof.
func (p *Portal) holderKeyProof(w http.ResponseWriter, r *http.Request) error {
	if !p.bindsKey() {
		http.NotFound(w, r)
		return nil
	}
	who, ok := p.writer(w, r)
	if !ok {
		return nil
	}
	return writeJSON(w, http.StatusOK, map[string]string{"signing_input": keyProofInput(who.SessionID)})
}

// holderKeyBind sends the key and the proof to wallet-auth, and sets the
// session cookie that names the key.
func (p *Portal) holderKeyBind(w http.ResponseWriter, r *http.Request) error {
	if !p.bindsKey() {
		http.NotFound(w, r)
		return nil
	}
	who, ok := p.writer(w, r)
	if !ok {
		return nil
	}
	cookie, err := r.Cookie(session.CookieName)
	if err != nil || cookie.Value == "" {
		return writeJSON(w, http.StatusUnauthorized, map[string]string{"error": msg.T("holder.keys.bind.session")})
	}
	jwk, signature := strings.TrimSpace(r.PostFormValue("jwk")), strings.TrimSpace(r.PostFormValue("signature"))
	if jwk == "" || signature == "" {
		return writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg.T("holder.keys.bind.missing")})
	}
	got, err := p.opts.Topology.RegisterKey(r.Context(), p.shell.AuthURL(), cookie.Value, jwk, keyProofInput(who.SessionID)+"."+signature)
	if err != nil {
		return writeJSONError(w, err)
	}
	oidcflow.Cookie{Name: session.CookieName, Secure: p.opts.Topology.SecureCookie}.Set(w, got.SessionToken, who.ExpiresAt)
	return writeJSON(w, http.StatusOK, map[string]string{"thumbprint": got.Thumbprint, "holder_did": got.HolderDID})
}

// keyMark marks the status line of a page whose browser still has to
// bind its key, so wallet.js binds it after it makes the key.
func (p *Portal) keyMark(b *pen) string {
	if !p.bindsKey() || b.who.HasHolderKey {
		return ""
	}
	return ` data-holder-key="register"`
}

// browserThumbprint returns the thumbprint of the browser key that the
// did:jwk of the session names, or "".
func browserThumbprint(did string) string {
	encoded, ok := strings.CutPrefix(did, "did:jwk:")
	if !ok {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	jwk, err := jose.ParseJWK(raw)
	if err != nil {
		return ""
	}
	thumbprint, err := jose.Thumbprint(jwk)
	if err != nil {
		return ""
	}
	return thumbprint
}
