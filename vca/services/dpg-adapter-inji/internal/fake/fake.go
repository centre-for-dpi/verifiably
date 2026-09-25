// SPDX-License-Identifier: Apache-2.0

// Package fake replays recorded Inji answers over httptest. The contract
// tests of the adapter run against it, so a change that breaks the Inji
// contract fails the build (ADR-004 decision 4).
//
// The recorded answers live in the testdata directory of the service.
// They follow the shapes of Inji Certify 0.14.0 and Inji Verify 0.16.0.
package fake

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Answer names one recorded file the fake can serve.
type Answer string

// The recorded answers the tests switch between.
const (
	// StagedOffer is a staged offer of Inji Certify.
	StagedOffer Answer = "staged-offer.json"
	// StagedOfferError is a staging call that Inji rejected.
	StagedOfferError Answer = "staged-offer-error.json"
	// CredentialLdp is a JSON-LD credential.
	//nolint:gosec // G101: the value is a file name, not a credential
	CredentialLdp Answer = "credential-ldp.json"
	// CredentialSdJwt is an SD-JWT VC credential.
	//nolint:gosec // G101: the value is a file name, not a credential
	CredentialSdJwt Answer = "credential-sdjwt.json"
	// ResultPending is a transaction that no wallet answered.
	ResultPending Answer = "vp-result-pending.json"
	// ResultSuccess is a transaction that Inji Verify accepted.
	ResultSuccess Answer = "vp-result-success.json"
	// ResultWrongCredential is a success answer with a credential that
	// does not carry a requested claim.
	//nolint:gosec // G101: the value is a file name, not a credential
	ResultWrongCredential Answer = "vp-result-wrong-credential.json"
	// ResultInvalid is a transaction that Inji Verify rejected.
	ResultInvalid Answer = "vp-result-invalid.json"
)

// Server is a running fake Inji deployment.
type Server struct {
	// Server is the HTTP test server.
	Server *httptest.Server

	mu sync.Mutex
	// dir holds the recorded answers.
	dir string
	// staged selects the staging answer.
	staged Answer
	// credential selects the credential answer.
	credential Answer
	// result selects the presentation result.
	result Answer
	// requests records the body of every write call by path.
	requests map[string][]byte
	// status forces a status code for one path.
	status map[string]int
	// configs is the credential configuration store.
	configs configs
}

// New starts a fake Inji deployment.
func New(dir string) *Server {
	f := &Server{
		dir:        dir,
		staged:     StagedOffer,
		credential: CredentialLdp,
		result:     ResultPending,
		requests:   map[string][]byte{},
		status:     map[string]int{},
	}
	f.configs.seed(dir)
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

// Close stops the fake.
func (f *Server) Close() { f.Server.Close() }

// URL is the base URL of the fake.
func (f *Server) URL() string { return f.Server.URL }

// Client is an HTTP client that reaches the fake.
func (f *Server) Client() *http.Client { return f.Server.Client() }

// SetStaged selects the staging answer.
func (f *Server) SetStaged(a Answer) { f.set(&f.staged, a) }

// SetCredential selects the credential answer.
func (f *Server) SetCredential(a Answer) { f.set(&f.credential, a) }

// SetResult selects the presentation result.
func (f *Server) SetResult(a Answer) { f.set(&f.result, a) }

func (f *Server) set(field *Answer, a Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	*field = a
}

// SetStatus makes the fake answer one path with a status code. A status
// of zero removes the setting.
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

func (f *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, ignored := io.ReadAll(r.Body)
	_ = ignored
	f.mu.Lock()
	f.requests[r.URL.Path] = body
	forced := f.status[r.URL.Path]
	staged, credential, result := f.staged, f.credential, f.result
	f.mu.Unlock()
	if forced != 0 {
		w.WriteHeader(forced)
		return
	}
	if f.serveConfigs(w, r, body) {
		return
	}
	path := r.URL.Path
	switch {
	case strings.HasSuffix(path, "/.well-known/openid-credential-issuer"):
		raw, err := f.metadata()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		f.sendJSON(w, json.RawMessage(raw))
	case path == "/v1/certify/pre-authorized-data":
		f.send(w, string(staged))
	case strings.Contains(path, "/credential-offer/"):
		f.send(w, "offer-document.json")
	case path == "/v1/certify/oauth/token":
		f.send(w, "token.json")
	case path == "/v1/certify/issuance/credential":
		f.send(w, string(credential))
	case path == "/v1/verify/vp-request":
		f.send(w, "vp-request.json")
	case strings.HasPrefix(path, "/v1/verify/vp-result/"):
		f.send(w, string(result))
	default:
		http.NotFound(w, r)
	}
}

// send writes one recorded answer.
func (f *Server) send(w http.ResponseWriter, name string) {
	raw, err := os.ReadFile(filepath.Join(f.dir, name)) //nolint:gosec // G304: the name is one of the fixed answers
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(raw); err != nil {
		return
	}
}
