// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// The Mimoto 0.21.0 answers of the holder role (testdata/doc/SOURCE.md).
const (
	// MimotoCookie is the session cookie the token login sets.
	MimotoCookie = "SESSION=mimoto-session-1"
	// RefusedToken is an ID token the token login refuses, as Mimoto
	// refuses a token of an identity provider it does not trust.
	//nolint:gosec // G101: a test value, not a credential
	RefusedToken = "refused.id.token"
	// mimotoPrefix is the context path of Mimoto.
	mimotoPrefix = "/v1/mimoto"
)

// mimoto is the wallet state of the fake Mimoto.
type mimoto struct {
	// pins holds the PIN of each wallet by id.
	pins map[string]string
	// unlocked lists the wallets whose key sits in the session.
	unlocked []string
	// deleted lists the removed credential ids.
	deleted []string
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
	f.mimoto.unlocked = nil
	f.mimoto.logins = -1
}

// serveMimoto answers the Mimoto API. It reports false for another path.
func (f *Server) serveMimoto(w http.ResponseWriter, r *http.Request, body []byte) bool {
	path, ok := strings.CutPrefix(r.URL.Path, mimotoPrefix)
	if !ok {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mimoto.pins == nil {
		f.mimoto.pins = map[string]string{}
	}
	if strings.HasPrefix(path, "/auth/") && strings.HasSuffix(path, "/token-login") && r.Method == http.MethodPost {
		token, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !bearer || token == "" || token == RefusedToken {
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}
		if f.mimoto.logins < 0 {
			f.mimoto.logins = 0
		}
		f.mimoto.logins++
		w.Header().Add("Set-Cookie", MimotoCookie+"; Path=/; HttpOnly")
		f.sendJSON(w, map[string]string{})
		return true
	}
	if r.Header.Get("Cookie") != MimotoCookie || f.mimoto.logins < 0 {
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "wallets" && r.Method == http.MethodPost:
		var req struct {
			Pin     string `json:"walletPin"`
			Confirm string `json:"confirmWalletPin"`
		}
		if json.Unmarshal(body, &req) != nil || len(req.Pin) != 6 || req.Pin != req.Confirm {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		raw := f.read(w, "doc/mimoto-wallet.json")
		if raw == nil {
			return true
		}
		var wallet struct {
			ID string `json:"walletId"`
		}
		if json.Unmarshal(raw, &wallet) == nil {
			f.mimoto.pins[wallet.ID] = req.Pin
		}
		f.sendJSON(w, json.RawMessage(raw))
	case len(parts) == 3 && parts[2] == "unlock" && r.Method == http.MethodPost:
		var req struct {
			Pin string `json:"walletPin"`
		}
		if json.Unmarshal(body, &req) != nil || f.mimoto.pins[parts[1]] == "" || f.mimoto.pins[parts[1]] != req.Pin {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		f.mimoto.unlocked = append(f.mimoto.unlocked, parts[1])
		f.sendJSON(w, map[string]string{"walletId": parts[1]})
	case len(parts) >= 3 && !slices.Contains(f.mimoto.unlocked, parts[1]):
		w.WriteHeader(http.StatusBadRequest)
	case len(parts) == 3 && parts[2] == "credentials" && r.Method == http.MethodGet:
		f.heldCredentials(w)
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

// heldCredentials lists the recorded credentials that no call removed.
func (f *Server) heldCredentials(w http.ResponseWriter) {
	var list []map[string]any
	if json.Unmarshal(f.read(w, "doc/mimoto-credentials.json"), &list) != nil {
		return
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
