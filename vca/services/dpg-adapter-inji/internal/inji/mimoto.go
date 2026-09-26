// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// Mimoto 0.21.0 is the backend of Inji Web 0.16.0. It keeps a servlet
// session per user. The token login opens one from the ID token of an
// identity provider it trusts, so a server drives the wallet with the
// session cookie (P6-I7a decision, docs/dpg-adapter-inji.md).
//
//   - POST /v1/mimoto/auth/{provider}/token-login opens the session.
//   - GET /v1/mimoto/wallets lists the wallets of the user and sets the
//     CSRF cookie that every call that changes state repeats.
//   - POST /v1/mimoto/wallets makes a wallet with a PIN of six digits.
//   - POST /v1/mimoto/wallets/{id}/unlock puts the wallet key in the session.
//   - GET, DELETE /v1/mimoto/wallets/{id}/credentials[/{credentialId}]
//     list, render, and remove the held credentials.
//   - POST, PATCH /v1/mimoto/wallets/{id}/presentations answer an
//     OID4VP request.
const mimotoPath = "/v1/mimoto"

// ErrMimotoSession reports a session that Mimoto no longer knows, or a
// token it refused. The holder signs in again.
var ErrMimotoSession = errors.New("inji: Mimoto refused the session")

// The errors of the wallet PIN, by the errorCode of the answer of
// Mimoto 0.21.0 (WalletsController).
var (
	// ErrMimotoPIN is a wrong PIN (invalid_pin).
	ErrMimotoPIN = errors.New("inji: the PIN does not open the wallet")
	// ErrMimotoLastAttempt is a wrong PIN with one attempt left before
	// the lock (last_attempt_before_lockout).
	ErrMimotoLastAttempt = errors.New("inji: the PIN does not open the wallet, and one attempt is left")
	// ErrMimotoLockedOut is a wallet that too many wrong PINs locked
	// (423 temporarily_locked or permanently_locked).
	ErrMimotoLockedOut = errors.New("inji: too many wrong PINs locked the wallet")
	// ErrMimotoWalletLocked is a session without the key of the wallet
	// (wallet_locked).
	ErrMimotoWalletLocked = errors.New("inji: the wallet is locked in this session")
)

// xsrfCookie is the CSRF cookie of Mimoto. A call that changes state
// repeats its value in xsrfHeader (CookieCsrfTokenRepository).
const (
	xsrfCookie = "XSRF-TOKEN"
	xsrfHeader = "X-XSRF-TOKEN"
)

// Wallet is one wallet of the user.
type Wallet struct {
	// ID is the wallet id.
	ID string `json:"walletId"`
	// Name is the name the holder gave it.
	Name string `json:"walletName"`
	// Status is empty, temporarily_locked, or permanently_locked.
	Status string `json:"walletStatus"`
}

// Locked reports a wallet that too many wrong PINs locked.
func (w Wallet) Locked() bool { return strings.HasSuffix(w.Status, "_locked") }

// Mimoto calls the Mimoto service of the stack.
type Mimoto struct {
	client *dpgclient.Client
}

// NewMimoto returns the client, or nil for a nil HTTP client.
func NewMimoto(client *dpgclient.Client) *Mimoto {
	if client == nil {
		return nil
	}
	return &Mimoto{client: client}
}

// HeldCredential is one credential of a Mimoto wallet. Mimoto returns
// the names and the logos only, never the credential bytes.
type HeldCredential struct {
	// ID is the id of the credential in the wallet.
	ID string `json:"credentialId"`
	// Issuer is the display name of the issuer.
	Issuer string `json:"issuerDisplayName"`
	// IssuerLogo is the logo of the issuer.
	IssuerLogo string `json:"issuerLogo"`
	// Type is the display name of the credential type.
	Type string `json:"credentialTypeDisplayName"`
	// TypeLogo is the logo of the credential type.
	TypeLogo string `json:"credentialTypeLogo"`
}

// Presented is the outcome of a presentation.
type Presented struct {
	// PresentationID is the id Mimoto gave the request.
	PresentationID string
	// RedirectURI is the address of the verifier, when it gave one.
	RedirectURI string
}

// call sends one request with the session cookie. A 401 or a 403 gives
// ErrMimotoSession.
func (m *Mimoto) call(ctx context.Context, r dpgclient.Request, cookie string) (*dpgclient.Response, error) {
	if m == nil {
		return nil, errors.New("inji: no Mimoto URL")
	}
	r.Path = mimotoPath + r.Path
	if cookie != "" {
		if r.Header == nil {
			r.Header = http.Header{}
		}
		r.Header.Set("Cookie", cookie)
		if token := cookieValue(cookie, xsrfCookie); token != "" && r.Method != http.MethodGet {
			r.Header.Set(xsrfHeader, token)
		}
	}
	resp, err := m.client.Do(ctx, r)
	if dpgclient.IsStatus(err, http.StatusUnauthorized) || dpgclient.IsStatus(err, http.StatusForbidden) {
		return nil, fmt.Errorf("%w: %w", ErrMimotoSession, err)
	}
	if code := errorCode(err); code != nil {
		return nil, fmt.Errorf("%w: %w", code, err)
	}
	return resp, err
}

// errorCode maps the errorCode of a Mimoto error answer onto an error of
// the PIN, or nil.
func errorCode(err error) error {
	var status *dpgclient.StatusError
	if !errors.As(err, &status) {
		return nil
	}
	if status.Status == http.StatusLocked {
		return ErrMimotoLockedOut
	}
	var body struct {
		Code string `json:"errorCode"`
	}
	if json.Unmarshal([]byte(status.Body), &body) == nil {
		switch body.Code {
		case "invalid_pin":
			return ErrMimotoPIN
		case "last_attempt_before_lockout":
			return ErrMimotoLastAttempt
		case "temporarily_locked", "permanently_locked":
			return ErrMimotoLockedOut
		case "wallet_locked":
			return ErrMimotoWalletLocked
		}
	}
	return nil
}

// cookieValue returns the value of one cookie of a Cookie header.
func cookieValue(cookie, name string) string {
	for _, part := range strings.Split(cookie, ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && k == name {
			return v
		}
	}
	return ""
}

// mergeCookies adds the cookies of the Set-Cookie headers to a Cookie
// header, and replaces a cookie of the same name.
func mergeCookies(cookie string, h http.Header) string {
	names := []string{}
	values := map[string]string{}
	add := func(pair string) {
		k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || k == "" {
			return
		}
		if _, seen := values[k]; !seen {
			names = append(names, k)
		}
		values[k] = v
	}
	for _, part := range strings.Split(cookie, ";") {
		add(part)
	}
	for _, line := range h.Values("Set-Cookie") {
		pair, _, _ := strings.Cut(line, ";")
		add(pair)
	}
	parts := make([]string, 0, len(names))
	for _, k := range names {
		parts = append(parts, k+"="+values[k])
	}
	return strings.Join(parts, "; ")
}

// Wallets lists the wallets of the user of the session. The answer of a
// GET carries the CSRF cookie, so it returns the cookie with it.
func (m *Mimoto) Wallets(ctx context.Context, cookie string) ([]Wallet, string, error) {
	resp, err := m.call(ctx, dpgclient.Request{Method: http.MethodGet, Path: "/wallets", Accept: "application/json"}, cookie)
	if err != nil {
		return nil, cookie, err
	}
	var out []Wallet
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, cookie, fmt.Errorf("inji: read the Mimoto wallets: %w", err)
	}
	return out, mergeCookies(cookie, resp.Header), nil
}

// TokenLogin opens a session with the ID token for the provider bean of
// Mimoto, such as google. It returns the cookie that carries the session.
func (m *Mimoto) TokenLogin(ctx context.Context, provider, idToken string) (string, error) {
	resp, err := m.call(ctx, dpgclient.Request{
		Method: http.MethodPost, Path: "/auth/" + url.PathEscape(provider) + "/token-login",
		Accept: "application/json", Header: http.Header{"Authorization": {"Bearer " + idToken}},
	}, "")
	if err != nil {
		return "", err
	}
	cookie := cookieOf(resp.Header)
	if cookie == "" {
		return "", errors.New("inji: the Mimoto token login set no session cookie")
	}
	return cookie, nil
}

// cookieOf joins the name=value parts of every Set-Cookie header.
func cookieOf(h http.Header) string {
	var parts []string
	for _, line := range h.Values("Set-Cookie") {
		pair, _, _ := strings.Cut(line, ";")
		if pair = strings.TrimSpace(pair); strings.Contains(pair, "=") {
			parts = append(parts, pair)
		}
	}
	return strings.Join(parts, "; ")
}

// CreateWallet makes a wallet with the PIN and returns its id.
func (m *Mimoto) CreateWallet(ctx context.Context, cookie, name, pin string) (string, error) {
	raw, err := json.Marshal(map[string]string{"walletName": name, "walletPin": pin, "confirmWalletPin": pin})
	if err != nil {
		return "", fmt.Errorf("inji: encode the wallet: %w", err)
	}
	resp, err := m.call(ctx, dpgclient.Request{
		Method: http.MethodPost, Path: "/wallets", Body: raw, ContentType: "application/json", Accept: "application/json",
	}, cookie)
	if err != nil {
		return "", err
	}
	var out struct {
		WalletID string `json:"walletId"`
	}
	if err := json.Unmarshal(resp.Body, &out); err != nil || out.WalletID == "" {
		return "", errors.New("inji: the Mimoto wallet answer has no walletId")
	}
	return out.WalletID, nil
}

// Unlock puts the key of the wallet in the session.
func (m *Mimoto) Unlock(ctx context.Context, cookie, walletID, pin string) error {
	raw, err := json.Marshal(map[string]string{"walletPin": pin})
	if err != nil {
		return fmt.Errorf("inji: encode the PIN: %w", err)
	}
	_, err = m.call(ctx, dpgclient.Request{
		Method: http.MethodPost, Path: "/wallets/" + url.PathEscape(walletID) + "/unlock", Body: raw,
		ContentType: "application/json", Accept: "application/json",
	}, cookie)
	return err
}

// Credentials lists the credentials of the wallet.
func (m *Mimoto) Credentials(ctx context.Context, cookie, walletID string) ([]HeldCredential, error) {
	resp, err := m.call(ctx, dpgclient.Request{
		Method: http.MethodGet, Path: "/wallets/" + url.PathEscape(walletID) + "/credentials", Accept: "application/json",
		Header: http.Header{"Accept-Language": {"en"}},
	}, cookie)
	if err != nil {
		return nil, err
	}
	var out []HeldCredential
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("inji: read the Mimoto credentials: %w", err)
	}
	return out, nil
}

// Document returns the PDF of one credential.
func (m *Mimoto) Document(ctx context.Context, cookie, walletID, credentialID string) ([]byte, string, error) {
	resp, err := m.call(ctx, dpgclient.Request{
		Method: http.MethodGet, Accept: "application/pdf",
		Path:   "/wallets/" + url.PathEscape(walletID) + "/credentials/" + url.PathEscape(credentialID) + "?action=download",
		Header: http.Header{"Accept-Language": {"en"}},
	}, cookie)
	if err != nil {
		return nil, "", err
	}
	media := resp.Header.Get("Content-Type")
	if media == "" {
		media = "application/pdf"
	}
	return resp.Body, media, nil
}

// Delete removes one credential.
func (m *Mimoto) Delete(ctx context.Context, cookie, walletID, credentialID string) error {
	_, err := m.call(ctx, dpgclient.Request{
		Method: http.MethodDelete, Path: "/wallets/" + url.PathEscape(walletID) + "/credentials/" + url.PathEscape(credentialID),
	}, cookie)
	return err
}

// Present answers an OID4VP request with the credentials: Mimoto reads
// the request, then sends the presentation the holder chose.
func (m *Mimoto) Present(ctx context.Context, cookie, walletID, requestURL string, credentialIDs []string) (Presented, error) {
	raw, err := json.Marshal(map[string]string{"authorizationRequestUrl": requestURL})
	if err != nil {
		return Presented{}, fmt.Errorf("inji: encode the request: %w", err)
	}
	base := "/wallets/" + url.PathEscape(walletID) + "/presentations"
	resp, err := m.call(ctx, dpgclient.Request{
		Method: http.MethodPost, Path: base, Body: raw, ContentType: "application/json", Accept: "application/json",
	}, cookie)
	if err != nil {
		return Presented{}, err
	}
	var started struct {
		PresentationID string `json:"presentationId"`
	}
	if jerr := json.Unmarshal(resp.Body, &started); jerr != nil || started.PresentationID == "" {
		return Presented{}, errors.New("inji: the Mimoto presentation answer has no presentationId")
	}
	body, err := json.Marshal(map[string][]string{"selectedCredentials": credentialIDs})
	if err != nil {
		return Presented{}, fmt.Errorf("inji: encode the selection: %w", err)
	}
	sent, err := m.call(ctx, dpgclient.Request{
		Method: http.MethodPatch, Path: base + "/" + url.PathEscape(started.PresentationID), Body: body,
		ContentType: "application/json", Accept: "application/json",
	}, cookie)
	if err != nil {
		return Presented{}, err
	}
	out := Presented{PresentationID: started.PresentationID}
	var answer struct {
		RedirectURI string `json:"redirectUri"`
	}
	if json.Unmarshal(sent.Body, &answer) == nil {
		out.RedirectURI = answer.RedirectURI
	}
	return out, nil
}

// AuthorizationRequestURL returns an OID4VP authorization request URL
// for Mimoto: the URL as it is, or an openid4vp URL that names a bare
// request object address in request_uri.
func AuthorizationRequestURL(request string) string {
	request = strings.TrimSpace(request)
	if strings.Contains(request, "?") || !strings.HasPrefix(request, "http") {
		return request
	}
	return "openid4vp://authorize?request_uri=" + url.QueryEscape(request)
}
