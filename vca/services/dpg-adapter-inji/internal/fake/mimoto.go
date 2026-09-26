// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// The Mimoto 0.21.0 answers of the holder role (testdata/doc/SOURCE.md).
// The fake keeps a servlet session per token login, checks the double
// submit CSRF token of every call that changes state, keeps one wallet
// of the one user with its PIN, and follows the passcode rule of the
// release: the fourth wrong PIN warns, and the fifth locks the wallet.
const (
	// MimotoCookie is the session cookie of the first token login.
	MimotoCookie = "SESSION=mimoto-session-1"
	// RefusedToken is an ID token the token login refuses, as Mimoto
	// refuses a token of an identity provider it does not trust.
	//nolint:gosec // G101: a test value, not a credential
	RefusedToken = "refused.id.token"
	// mimotoPrefix is the context path of Mimoto.
	mimotoPrefix = "/v1/mimoto"
	// maxFailedPins is wallet.passcode.maxFailedAttemptsAllowedPerCycle.
	maxFailedPins = 5
)

// mimotoSession is one servlet session.
type mimotoSession struct {
	// unlocked is the wallet whose key sits in the session.
	unlocked string
}

// mimoto is the wallet state of the fake Mimoto.
type mimoto struct {
	// sessions holds the sessions by the value of the SESSION cookie.
	sessions map[string]*mimotoSession
	// wallet is the id of the wallet of the user, or empty.
	wallet string
	// pin is the PIN of the wallet.
	pin string
	// made counts the wallets the API made.
	made int
	// failed counts the wrong PINs since the last right one.
	failed int
	// deleted lists the removed credential ids.
	deleted []string
	// downloaded lists the credentials a claim added.
	downloaded []json.RawMessage
	// presented records the selections of the presentations.
	presented [][]string
	// logins counts the token logins.
	logins int
}

// MimotoLogins returns the number of token logins.
func (f *Server) MimotoLogins() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mimoto.logins
}

// MimotoWalletPIN returns the PIN of the wallet, or empty when the user
// has no wallet.
func (f *Server) MimotoWalletPIN() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mimoto.pin
}

// MimotoWalletsMade returns the number of wallets the API made.
func (f *Server) MimotoWalletsMade() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mimoto.made
}

// SeedMimotoWallet gives the user a wallet with the PIN, as a holder
// who made it in Inji Web has.
func (f *Server) SeedMimotoWallet(pin string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mimoto.wallet, f.mimoto.pin = f.walletID(), pin
}

// MimotoPresented returns the credential ids of the last presentation.
func (f *Server) MimotoPresented() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.mimoto.presented) == 0 {
		return nil
	}
	return f.mimoto.presented[len(f.mimoto.presented)-1]
}

// ForgetMimotoSession ends every session, as Mimoto does after 30 idle
// minutes.
func (f *Server) ForgetMimotoSession() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mimoto.sessions = nil
}

// LockMimotoSessions drops the wallet key of every session, as a restart
// of Mimoto with the sessions kept in Redis does.
func (f *Server) LockMimotoSessions() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.mimoto.sessions {
		s.unlocked = ""
	}
}

// ClaimInInjiWeb runs the calls of Inji Web 0.16.0 for a claim in the
// browser of the holder: a login, the wallet list, the unlock with the
// PIN the holder types, and the download after the authorization at the
// issuer. It returns an error when a call fails.
func (f *Server) ClaimInInjiWeb(idToken, pin string) error {
	call := func(method, path, cookie string, body any, header ...string) (http.Header, []byte, error) {
		var raw []byte
		if body != nil {
			var err error
			if raw, err = json.Marshal(body); err != nil {
				return nil, nil, err
			}
		}
		req, err := http.NewRequestWithContext(context.Background(), method, f.URL()+mimotoPrefix+path, bytes.NewReader(raw))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Cookie", cookie)
		for i := 0; i+1 < len(header); i += 2 {
			req.Header.Set(header[i], header[i+1])
		}
		resp, err := f.Client().Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer func() { anyval.Discard(resp.Body.Close()) }()
		out, err := io.ReadAll(resp.Body)
		if err == nil && resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("%s %s answered %d: %s", method, path, resp.StatusCode, out)
		}
		return resp.Header, out, err
	}
	login, _, err := call(http.MethodPost, "/auth/google/token-login", "", nil, "Authorization", "Bearer "+idToken)
	if err != nil {
		return err
	}
	session, _, _ := strings.Cut(login.Get("Set-Cookie"), ";")
	list, raw, err := call(http.MethodGet, "/wallets", session, nil)
	if err != nil {
		return err
	}
	xsrf, _, _ := strings.Cut(strings.TrimPrefix(list.Get("Set-Cookie"), "XSRF-TOKEN="), ";")
	cookie := session + "; XSRF-TOKEN=" + xsrf
	var wallets []struct {
		ID string `json:"walletId"`
	}
	if jerr := json.Unmarshal(raw, &wallets); jerr != nil || len(wallets) != 1 {
		return fmt.Errorf("the user has %d wallets", len(wallets))
	}
	base := "/wallets/" + wallets[0].ID
	if _, _, err = call(http.MethodPost, base+"/unlock", cookie, map[string]string{"walletPin": pin}, "X-XSRF-TOKEN", xsrf); err != nil {
		return err
	}
	_, _, err = call(http.MethodPost, base+"/credentials", cookie, map[string]string{
		"issuer": "InjiCertify", "credentialConfigurationId": "FarmerCredential", "code": "esignet-code",
		"grantType": "authorization_code", "redirectUri": "http://localhost:17085/redirect", "codeVerifier": "v",
	}, "X-XSRF-TOKEN", xsrf)
	return err
}

// walletID returns the recorded wallet id.
func (f *Server) walletID() string {
	raw, err := os.ReadFile(filepath.Join(f.dir, "doc/mimoto-wallet.json")) //nolint:gosec // G304: a fixed answer
	if err != nil {
		return ""
	}
	var wallet struct {
		ID string `json:"walletId"`
	}
	if json.Unmarshal(raw, &wallet) != nil {
		return ""
	}
	return wallet.ID
}

// cookies reads the name=value pairs of the Cookie header.
func cookies(r *http.Request) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(r.Header.Get("Cookie"), ";") {
		if name, value, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
			out[name] = value
		}
	}
	return out
}

// mimotoError writes an error of the release from its recorded answer.
func (f *Server) mimotoError(w http.ResponseWriter, status int, name string) {
	raw := f.read(w, "doc/"+name)
	if raw == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(raw); err != nil {
		return
	}
}

// serveMimoto answers the Mimoto API. It reports false for another path.
func (f *Server) serveMimoto(w http.ResponseWriter, r *http.Request, body []byte) bool {
	path, ok := strings.CutPrefix(r.URL.Path, mimotoPrefix)
	if !ok {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasPrefix(path, "/auth/") && strings.HasSuffix(path, "/token-login") && r.Method == http.MethodPost {
		token, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !bearer || token == "" || token == RefusedToken {
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}
		if f.mimoto.sessions == nil {
			f.mimoto.sessions = map[string]*mimotoSession{}
		}
		f.mimoto.logins++
		id := "mimoto-session-" + strconv.Itoa(len(f.mimoto.sessions)+1)
		f.mimoto.sessions[id] = &mimotoSession{}
		w.Header().Add("Set-Cookie", "SESSION="+id+"; Path=/; HttpOnly")
		f.sendJSON(w, map[string]string{})
		return true
	}
	jar := cookies(r)
	session := f.mimoto.sessions[jar["SESSION"]]
	if session == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}
	if r.Method == http.MethodGet {
		// CsrfTokenCookieFilter of the release sets the token on a GET.
		w.Header().Add("Set-Cookie", "XSRF-TOKEN=xsrf-"+jar["SESSION"]+"; Path=/")
	} else if token := r.Header.Get("X-XSRF-TOKEN"); token == "" || token != jar["XSRF-TOKEN"] {
		w.WriteHeader(http.StatusForbidden)
		return true
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "wallets" && r.Method == http.MethodGet:
		f.wallets(w)
	case len(parts) == 1 && parts[0] == "wallets" && r.Method == http.MethodPost:
		f.createWallet(w, body)
	case len(parts) == 3 && parts[2] == "unlock" && r.Method == http.MethodPost:
		f.unlock(w, session, parts[1], body)
	case len(parts) >= 3 && (parts[1] != f.mimoto.wallet || session.unlocked != parts[1]):
		f.mimotoError(w, http.StatusBadRequest, "mimoto-error-wallet-locked.json")
	case len(parts) == 3 && parts[2] == "credentials" && r.Method == http.MethodGet:
		f.heldCredentials(w)
	case len(parts) == 3 && parts[2] == "credentials" && r.Method == http.MethodPost:
		f.download(w, body)
	case len(parts) == 4 && parts[2] == "credentials" && r.Method == http.MethodGet:
		f.credentialDocument(w, r)
	case len(parts) == 4 && parts[2] == "credentials" && r.Method == http.MethodDelete:
		f.mimoto.deleted = append(f.mimoto.deleted, parts[3])
		w.WriteHeader(http.StatusOK)
	case len(parts) == 3 && parts[2] == "presentations" && r.Method == http.MethodPost:
		var req struct {
			URL string `json:"authorizationRequestUrl"`
		}
		if json.Unmarshal(body, &req) != nil || !strings.HasPrefix(req.URL, "openid4vp://") {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		if raw := f.read(w, "doc/mimoto-presentation.json"); raw != nil {
			f.sendJSON(w, json.RawMessage(raw))
		}
	case len(parts) == 4 && parts[2] == "presentations" && r.Method == http.MethodPatch:
		var req struct {
			Selected []string `json:"selectedCredentials"`
		}
		if json.Unmarshal(body, &req) != nil || len(req.Selected) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		f.mimoto.presented = append(f.mimoto.presented, req.Selected)
		f.sendJSON(w, map[string]string{"redirectUri": "https://verify.inji.example/redirect"})
	default:
		http.NotFound(w, r)
	}
	return true
}

// wallets lists the wallet of the user with its lock status.
func (f *Server) wallets(w http.ResponseWriter) {
	if f.mimoto.wallet == "" {
		f.sendJSON(w, []any{})
		return
	}
	var list []map[string]any
	if json.Unmarshal(f.read(w, "doc/mimoto-wallets.json"), &list) != nil || len(list) == 0 {
		return
	}
	if f.mimoto.failed >= maxFailedPins {
		list[0]["walletStatus"] = "temporarily_locked"
	}
	f.sendJSON(w, list[:1])
}

// createWallet makes the wallet of the user with a PIN of six digits.
func (f *Server) createWallet(w http.ResponseWriter, body []byte) {
	var req struct {
		Name    string `json:"walletName"`
		Pin     string `json:"walletPin"`
		Confirm string `json:"confirmWalletPin"`
	}
	if json.Unmarshal(body, &req) != nil || !sixDigits(req.Pin) || req.Pin != req.Confirm || f.mimoto.wallet != "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	raw := f.read(w, "doc/mimoto-wallet.json")
	if raw == nil {
		return
	}
	f.mimoto.wallet, f.mimoto.pin = f.walletID(), req.Pin
	f.mimoto.made++
	f.sendJSON(w, json.RawMessage(raw))
}

// unlock puts the wallet key in the session when the PIN matches.
func (f *Server) unlock(w http.ResponseWriter, session *mimotoSession, wallet string, body []byte) {
	var req struct {
		Pin string `json:"walletPin"`
	}
	switch {
	case json.Unmarshal(body, &req) != nil || !sixDigits(req.Pin) || wallet != f.mimoto.wallet:
		w.WriteHeader(http.StatusBadRequest)
	case f.mimoto.failed >= maxFailedPins:
		f.mimotoError(w, http.StatusLocked, "mimoto-error-temporarily-locked.json")
	case req.Pin != f.mimoto.pin:
		f.mimoto.failed++
		switch {
		case f.mimoto.failed >= maxFailedPins:
			f.mimotoError(w, http.StatusLocked, "mimoto-error-temporarily-locked.json")
		case f.mimoto.failed == maxFailedPins-1:
			f.mimotoError(w, http.StatusBadRequest, "mimoto-error-last-attempt.json")
		default:
			f.mimotoError(w, http.StatusBadRequest, "mimoto-error-invalid-pin.json")
		}
	default:
		f.mimoto.failed = 0
		session.unlocked = wallet
		f.sendJSON(w, map[string]string{"walletId": wallet})
	}
}

// download adds the recorded credential of a claim, as Mimoto does
// after the token call at the issuer.
func (f *Server) download(w http.ResponseWriter, body []byte) {
	var req struct {
		Issuer string `json:"issuer"`
		Config string `json:"credentialConfigurationId"`
		Code   string `json:"code"`
	}
	if json.Unmarshal(body, &req) != nil || req.Issuer == "" || req.Config == "" || req.Code == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	raw := f.read(w, "doc/mimoto-download.json")
	if raw == nil {
		return
	}
	f.mimoto.downloaded = append(f.mimoto.downloaded, raw)
	f.sendJSON(w, json.RawMessage(raw))
}

// sixDigits reports a PIN of six digits, the rule of the release.
func sixDigits(pin string) bool {
	if len(pin) != 6 {
		return false
	}
	for _, c := range pin {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// heldCredentials lists the recorded credentials that no call removed,
// then the ones a claim added.
func (f *Server) heldCredentials(w http.ResponseWriter) {
	var list []map[string]any
	if json.Unmarshal(f.read(w, "doc/mimoto-credentials.json"), &list) != nil {
		return
	}
	for _, raw := range f.mimoto.downloaded {
		var c map[string]any
		if json.Unmarshal(raw, &c) == nil {
			list = append(list, c)
		}
	}
	kept := list[:0]
	for _, c := range list {
		if !slices.Contains(f.mimoto.deleted, anyval.As[string](c["credentialId"])) {
			kept = append(kept, c)
		}
	}
	f.sendJSON(w, kept)
}

// credentialDocument serves the PDF of a credential, which Mimoto
// renders only for Accept: application/pdf.
func (f *Server) credentialDocument(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Accept") != "application/pdf" {
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}
	raw := f.read(w, "doc/mimoto-credential.pdf")
	if raw == nil {
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	if _, err := w.Write(raw); err != nil {
		return
	}
}

// read returns one recorded file, or nil after it wrote an error.
func (f *Server) read(w http.ResponseWriter, name string) []byte {
	raw, err := os.ReadFile(filepath.Join(f.dir, name)) //nolint:gosec // G304: the name is one of the fixed answers
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}
	return raw
}
