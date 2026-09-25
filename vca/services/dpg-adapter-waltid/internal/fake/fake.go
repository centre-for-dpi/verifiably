// SPDX-License-Identifier: Apache-2.0

// Package fake replays recorded walt.id answers over httptest. The
// contract tests of the adapter run against it, so a change in the
// adapter that breaks the walt.id contract fails the build
// (ADR-004 decision 4).
//
// The recorded answers live in the testdata directory of the service.
// They follow the shapes of walt.id 0.18.2.
package fake

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// SessionState names which recorded verifier session the fake serves.
type SessionState string

// The recorded verifier sessions.
const (
	// SessionPending is a session that no wallet answered.
	SessionPending SessionState = "session-pending.json"
	// SessionAccepted is a session that walt.id accepted.
	SessionAccepted SessionState = "session-accepted.json"
	// SessionRejected is a session that walt.id rejected.
	SessionRejected SessionState = "session-rejected.json"
)

// Session2State names which verifier 2 session the fake serves. The
// answers follow the verifier 2 documentation (testdata/doc/SOURCE.md).
type Session2State string

// The verifier 2 sessions.
const (
	// Session2Active is a session that no wallet answered.
	Session2Active Session2State = "doc/verifier2-session-active.json"
	// Session2Successful is a session whose checks all passed.
	Session2Successful Session2State = "doc/verifier2-session-successful.json"
	// Session2Failed is a session with a failed check.
	Session2Failed Session2State = "doc/verifier2-session-failed.json"
	// Session2Expired is a session that expired unused.
	Session2Expired Session2State = "doc/verifier2-session-expired.json"
)

// Server is a running fake walt.id stack.
type Server struct {
	// Server is the HTTP test server.
	Server *httptest.Server

	mu sync.Mutex
	// dir holds the recorded answers.
	dir string
	// session selects the verifier session answer.
	session SessionState
	// session2 selects the verifier 2 session answer.
	session2 Session2State
	// last is the path of the last call.
	last string
	// lastQuery is the query of the last call.
	lastQuery url.Values
	// claimQuery is the query of the last claim of an offer.
	claimQuery url.Values
	// resolved is the answer of resolveCredentialOffer.
	resolved string
	// claimed reports whether a wallet claimed an offer.
	claimed bool
	// requests records the body of every write call by path.
	requests map[string][]byte
	// history records every body by path, oldest first.
	history map[string][][]byte
	// status forces a status code for one path.
	status map[string]int
}

// New starts a fake walt.id stack. The testdata directory holds the
// recorded answers.
func New(dir string) *Server {
	f := &Server{
		dir:      dir,
		session:  SessionPending,
		session2: Session2Active,
		resolved: "resolve-offer.json",
		requests: map[string][]byte{},
		history:  map[string][][]byte{},
		status:   map[string]int{},
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

// Close stops the fake.
func (f *Server) Close() { f.Server.Close() }

// Dir is the directory of the recorded answers.
func (f *Server) Dir() string { return f.dir }

// URL is the base URL of the fake.
func (f *Server) URL() string { return f.Server.URL }

// Client is an HTTP client that reaches the fake.
func (f *Server) Client() *http.Client { return f.Server.Client() }

// SetSession selects the verifier session answer.
func (f *Server) SetSession(state SessionState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.session = state
}

// SetSession2 selects the verifier 2 session answer.
func (f *Server) SetSession2(state Session2State) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.session2 = state
}

// LastQuery returns the query of the last call.
func (f *Server) LastQuery() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastQuery
}

// LastClaimQuery returns the query of the last claim of an offer.
func (f *Server) LastClaimQuery() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.claimQuery
}

// SetResolved selects the answer of resolveCredentialOffer.
func (f *Server) SetResolved(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = name
}

// LastPath returns the path of the last call.
func (f *Server) LastPath() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

// SetStatus makes the fake answer one path with a status code. An empty
// body follows. A status of zero removes the setting.
func (f *Server) SetStatus(path string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if status == 0 {
		delete(f.status, path)
		return
	}
	f.status[path] = status
}

// Request returns the recorded body of the last write to the path.
func (f *Server) Request(path string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[path]
}

// Bodies returns every body sent to the path, oldest first.
func (f *Server) Bodies(path string) [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.history[path]...)
}

// RequestJSON reads the recorded body of the path into out.
func (f *Server) RequestJSON(path string, out any) error {
	return json.Unmarshal(f.Request(path), out)
}

// file returns one recorded answer.
func (f *Server) file(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(f.dir, name)) //nolint:gosec // G304: the name is one of the fixed answers
}

func (f *Server) serve(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	f.mu.Lock()
	f.requests[r.URL.Path] = body
	f.history[r.URL.Path] = append(f.history[r.URL.Path], body)
	f.last = r.URL.Path
	f.lastQuery = r.URL.Query()
	resolved := f.resolved
	forced := f.status[r.URL.Path]
	session := f.session
	session2 := f.session2
	claimed := f.claimed
	f.mu.Unlock()
	if forced != 0 {
		w.WriteHeader(forced)
		return
	}
	path := r.URL.Path
	switch {
	case strings.HasSuffix(path, "/.well-known/openid-credential-issuer"):
		f.send(w, "issuer-metadata.json", "application/json")
	case path == "/onboard/issuer":
		f.onboard(w, body)
	case strings.HasPrefix(path, "/openid4vc/") && strings.HasSuffix(path, "/issue"):
		f.send(w, "offer.txt", "text/plain")
	case path == "/openid4vc/verify":
		f.send(w, "verify-authorize.txt", "text/plain")
	case strings.HasPrefix(path, "/openid4vc/session/"):
		f.send(w, string(session), "application/json")
	case path == "/verification-session/create" && r.Method == http.MethodPost:
		name := "doc/verifier2-create.json"
		if strings.Contains(string(body), `"flow_type":"dc_api`) {
			name = "doc/verifier2-create-dcapi.json"
		}
		f.send(w, name, "application/json")
	case strings.HasPrefix(path, "/verification-session/") && strings.HasSuffix(path, "/response"):
		f.send(w, "doc/verifier2-response.json", "application/json")
	case strings.HasPrefix(path, "/verification-session/") && strings.HasSuffix(path, "/info"):
		f.send(w, string(session2), "application/json")
	case path == "/wallet-api/auth/register":
		w.WriteHeader(http.StatusCreated)
	case path == "/wallet-api/auth/login":
		f.send(w, "wallet-login.json", "application/json")
	case path == "/wallet-api/wallet/accounts/wallets":
		f.send(w, "wallet-wallets.json", "application/json")
	case strings.HasSuffix(path, "/exchange/resolveCredentialOffer"):
		f.send(w, resolved, "application/json")
	case strings.HasSuffix(path, "/exchange/useOfferRequest"):
		f.mu.Lock()
		f.claimQuery = r.URL.Query()
		pending := r.URL.Query().Get("requireUserInput") == "true"
		f.claimed = f.claimed || !pending
		f.mu.Unlock()
		if pending {
			f.send(w, "doc/wallet-pending.json", "application/json")
			return
		}
		w.WriteHeader(http.StatusOK)
	case strings.HasSuffix(path, "/keys/generate"):
		w.WriteHeader(http.StatusCreated)
		f.sendBody(w, "doc/wallet-key-generate.txt")
	case strings.HasSuffix(path, "/keys"):
		f.send(w, "doc/wallet-keys.json", "application/json")
	case strings.Contains(path, "/dids/create/"):
		f.send(w, "doc/wallet-did-create.txt", "text/plain")
	case strings.HasSuffix(path, "/dids/default"):
		w.WriteHeader(http.StatusAccepted)
	case strings.HasSuffix(path, "/dids"):
		f.send(w, "doc/wallet-dids.json", "application/json")
	case strings.HasSuffix(path, "/eventlog"):
		f.send(w, "doc/wallet-events.json", "application/json")
	case strings.HasSuffix(path, "/reject"):
		w.WriteHeader(http.StatusAccepted)
	case strings.HasSuffix(path, "/exchange/usePresentationRequest"):
		f.send(w, "present-result.json", "application/json")
	case strings.Contains(path, "/credentials/"):
		w.WriteHeader(http.StatusOK)
	case strings.HasSuffix(path, "/credentials"):
		name := "wallet-credentials.json"
		if claimed {
			name = "wallet-credentials-after.json"
		}
		f.send(w, name, "application/json")
	default:
		http.NotFound(w, r)
	}
}

// onboard answers POST /onboard/issuer like walt.id: the recorded key of
// the asked key type, and the DID of the asked method. A did:web answer
// names the domain and the path of the request, as walt.id builds it.
func (f *Server) onboard(w http.ResponseWriter, body []byte) {
	var req struct {
		Key struct {
			Backend string `json:"backend"`
			KeyType string `json:"keyType"`
		} `json:"key"`
		Did struct {
			Method string `json:"method"`
			Config struct {
				Domain  string `json:"domain"`
				Path    string `json:"path"`
				Network string `json:"network"`
			} `json:"config"`
		} `json:"did"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "the onboarding request is not JSON", http.StatusBadRequest)
			return
		}
	}
	name := "onboard-issuer.json"
	switch {
	case req.Key.Backend == "tse":
		name = "doc/onboard-issuer-tse.json"
	case req.Key.KeyType == "Ed25519":
		name = "doc/onboard-issuer-ed25519.json"
	}
	if req.Did.Method == "key" || req.Did.Method == "" {
		f.send(w, name, "application/json")
		return
	}
	raw, err := f.file(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var answer map[string]json.RawMessage
	if err := json.Unmarshal(raw, &answer); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var did string
	switch req.Did.Method {
	case "web":
		// did:web encodes the port colon of the host as %3A.
		did = "did:web:" + strings.ReplaceAll(req.Did.Config.Domain, ":", "%3A") +
			strings.ReplaceAll(strings.TrimRight(req.Did.Config.Path, "/"), "/", ":")
	case "jwk":
		did = "did:jwk:" + base64.RawURLEncoding.EncodeToString(publicJWK(answer["issuerKey"]))
	default:
		// A cheqd DID names its network and a UUID.
		did = "did:" + req.Did.Method + ":" + req.Did.Config.Network + ":5e5d0e2c-5ea0-4b39-a2b6-3c1f1ab44c8e"
	}
	answer["issuerDid"] = anyval.Must(json.Marshal(did))
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(answer); err != nil {
		return
	}
}

// publicJWK returns the public members of the JWK of a key object, as
// JSON with sorted keys.
func publicJWK(key json.RawMessage) []byte {
	var obj struct {
		JWK map[string]any `json:"jwk"`
	}
	if err := json.Unmarshal(key, &obj); err != nil {
		return nil
	}
	delete(obj.JWK, "d")
	return anyval.Must(json.Marshal(obj.JWK))
}

// sendBody writes one recorded answer after the status line.
func (f *Server) sendBody(w http.ResponseWriter, name string) {
	raw, err := f.file(name)
	if err != nil {
		return
	}
	if _, err := w.Write(raw); err != nil {
		return
	}
}

// send writes one recorded answer.
func (f *Server) send(w http.ResponseWriter, name, contentType string) {
	raw, err := f.file(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	if _, err := w.Write(raw); err != nil {
		return
	}
}

// readBody reads the request body without failing on an empty one.
func readBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	buf := make([]byte, 0, 512)
	chunk := make([]byte, 512)
	for {
		n, err := r.Body.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil {
			return buf
		}
	}
}
