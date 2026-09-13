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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// Server is a running fake walt.id stack.
type Server struct {
	// Server is the HTTP test server.
	Server *httptest.Server

	mu sync.Mutex
	// dir holds the recorded answers.
	dir string
	// session selects the verifier session answer.
	session SessionState
	// claimed reports whether a wallet claimed an offer.
	claimed bool
	// requests records the body of every write call by path.
	requests map[string][]byte
	// status forces a status code for one path.
	status map[string]int
}

// New starts a fake walt.id stack. The testdata directory holds the
// recorded answers.
func New(dir string) *Server {
	f := &Server{
		dir:      dir,
		session:  SessionPending,
		requests: map[string][]byte{},
		status:   map[string]int{},
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

// Close stops the fake.
func (f *Server) Close() { f.Server.Close() }

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

// RequestJSON reads the recorded body of the path into out.
func (f *Server) RequestJSON(path string, out any) error {
	return json.Unmarshal(f.Request(path), out)
}

// file returns one recorded answer.
func (f *Server) file(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(f.dir, name))
}

func (f *Server) serve(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	f.mu.Lock()
	f.requests[r.URL.Path] = body
	forced := f.status[r.URL.Path]
	session := f.session
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
		f.send(w, "onboard-issuer.json", "application/json")
	case strings.HasPrefix(path, "/openid4vc/") && strings.HasSuffix(path, "/issue"):
		f.send(w, "offer.txt", "text/plain")
	case path == "/openid4vc/verify":
		f.send(w, "verify-authorize.txt", "text/plain")
	case strings.HasPrefix(path, "/openid4vc/session/"):
		f.send(w, string(session), "application/json")
	case path == "/wallet-api/auth/register":
		w.WriteHeader(http.StatusCreated)
	case path == "/wallet-api/auth/login":
		f.send(w, "wallet-login.json", "application/json")
	case path == "/wallet-api/wallet/accounts/wallets":
		f.send(w, "wallet-wallets.json", "application/json")
	case strings.HasSuffix(path, "/exchange/resolveCredentialOffer"):
		f.send(w, "resolve-offer.json", "application/json")
	case strings.HasSuffix(path, "/exchange/useOfferRequest"):
		f.mu.Lock()
		f.claimed = true
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
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

// send writes one recorded answer.
func (f *Server) send(w http.ResponseWriter, name, contentType string) {
	raw, err := f.file(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(raw)
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
