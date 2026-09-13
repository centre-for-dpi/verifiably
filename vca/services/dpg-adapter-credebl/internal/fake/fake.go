// SPDX-License-Identifier: Apache-2.0

// Package fake replays recorded CREDEBL answers over httptest. The
// contract tests of the adapter run against it, so a change that breaks
// the CREDEBL contract fails the build (ADR-004 decision 4).
//
// The recorded answers live in the testdata directory of the service.
// They follow the shapes of the CREDEBL 2.x api gateway.
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
	// SessionPending is a session that no wallet answered.
	SessionPending Answer = "session-pending.json"
	// SessionVerified is a session the platform accepted.
	SessionVerified Answer = "session-verified.json"
	// SessionError is a session the platform rejected.
	SessionError Answer = "session-error.json"
	// Templates is the list of credential templates.
	Templates Answer = "templates.json"
)

// Server is a running fake CREDEBL platform.
type Server struct {
	// Server is the HTTP test server.
	Server *httptest.Server

	mu sync.Mutex
	// dir holds the recorded answers.
	dir string
	// session selects the verification session answer.
	session Answer
	// templates selects the template listing.
	templates Answer
	// signins counts the sign in calls.
	signins int
	// requests records the body of every write call by path.
	requests map[string][]byte
	// status forces a status code for one path. A path can carry more
	// than one status, which the fake serves in order.
	status map[string][]int
}

// New starts a fake CREDEBL platform.
func New(dir string) *Server {
	f := &Server{
		dir:       dir,
		session:   SessionPending,
		templates: Templates,
		requests:  map[string][]byte{},
		status:    map[string][]int{},
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

// SetSession selects the verification session answer.
func (f *Server) SetSession(a Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.session = a
}

// SetTemplates selects the template listing.
func (f *Server) SetTemplates(a Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.templates = a
}

// SetStatus makes the fake answer the path with the statuses in order.
// An empty list removes the setting.
func (f *Server) SetStatus(path string, statuses ...int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(statuses) == 0 {
		delete(f.status, path)
		return
	}
	f.status[path] = statuses
}

// Signins returns the number of sign in calls.
func (f *Server) Signins() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.signins
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

// take returns the next forced status of the path, or zero.
func (f *Server) take(path string) int {
	statuses, ok := f.status[path]
	if !ok || len(statuses) == 0 {
		return 0
	}
	next := statuses[0]
	f.status[path] = statuses[1:]
	return next
}

func (f *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests[r.URL.Path] = body
	forced := f.take(r.URL.Path)
	session, templates := f.session, f.templates
	if r.URL.Path == "/v1/auth/signin" {
		f.signins++
	}
	f.mu.Unlock()
	if forced != 0 {
		w.WriteHeader(forced)
		return
	}
	path := r.URL.Path
	switch {
	case path == "/v1/auth/signin":
		f.send(w, "signin.json")
	case strings.HasSuffix(path, "/template") && r.Method == http.MethodGet:
		f.send(w, string(templates))
	case strings.HasSuffix(path, "/template"):
		f.send(w, "template-created.json")
	case strings.HasSuffix(path, "/schemas"):
		f.send(w, "schema-created.json")
	case strings.HasSuffix(path, "/create-offer"):
		f.send(w, "create-offer.json")
	case strings.HasSuffix(path, "/oid4vp/verifier") && r.Method == http.MethodGet:
		f.send(w, "verifier-list.json")
	case strings.HasSuffix(path, "/oid4vp/verifier"):
		f.send(w, "verifier-created.json")
	case strings.HasSuffix(path, "/oid4vp/presentation"):
		f.send(w, "presentation-created.json")
	case strings.HasSuffix(path, "/oid4vp/verifier-presentation"):
		f.send(w, string(session))
	default:
		http.NotFound(w, r)
	}
}

// send writes one recorded answer.
func (f *Server) send(w http.ResponseWriter, name string) {
	raw, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}
