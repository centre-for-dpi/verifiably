// SPDX-License-Identifier: Apache-2.0

// Package fake replays recorded CREDEBL answers over httptest. The
// contract tests of the adapter run against it, so a change that breaks
// the CREDEBL contract fails the build (ADR-004 decision 4).
//
// The recorded answers live in the testdata directory of the service.
// They follow the shapes of the CREDEBL 2.x api gateway.
package fake

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
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
	// OrgList is the list of organisations with a tenant and the
	// platform admin organisation.
	OrgList Answer = "doc/org-list.json"
	// NoOrgs makes the list of organisations answer the status not
	// found, as the platform does for an empty list.
	NoOrgs Answer = ""
	// OfferPending is an issuance session no wallet finished.
	OfferPending Answer = "doc/offer-session-pending.json"
	// OfferCompleted is an issuance session that issued.
	OfferCompleted Answer = "doc/offer-session-completed.json"
	// OfferError is an issuance session the agent ended in error.
	OfferError Answer = "doc/offer-session-error.json"
	// Connections is the list of the DIDComm connections.
	Connections Answer = "doc/connections.json"
	// NoConnections makes the list of connections answer the status not
	// found, as the platform does for an empty list.
	NoConnections Answer = ""
	// RecordOfferSent is a DIDComm exchange no wallet answered.
	RecordOfferSent Answer = "doc/credential-record-offer-sent.json"
	// RecordDone is a DIDComm exchange that issued.
	RecordDone Answer = "doc/credential-record-done.json"
	// RecordAbandoned is a DIDComm exchange the holder declined.
	RecordAbandoned Answer = "doc/credential-record-abandoned.json"
	// BulkFiles is the list of the files of the bulk import.
	BulkFiles Answer = "doc/bulk-files.json"
	// NoBulkFiles makes the list of files answer the status not found,
	// as the platform does for an empty list.
	NoBulkFiles Answer = ""
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
	// orgs selects the organisation listing.
	orgs Answer
	// offer selects the answer of one issuance session.
	offer Answer
	// connections selects the listing of the DIDComm connections.
	connections Answer
	// record selects the answer of one DIDComm credential exchange.
	record Answer
	// files selects the listing of the files of the bulk import.
	files Answer
	// types records the content type of every write call by path.
	types map[string]string
	// queries records the query of every call by path.
	queries map[string]string
	// deleted holds the organisations the fake deleted.
	deleted map[string]bool
	// calls records the method and path of every call, in order.
	calls []string
	// requests records the body of every write call by path.
	requests map[string][]byte
	// status forces a status code for one path. A path can carry more
	// than one status, which the fake serves in order.
	status map[string][]int
}

// New starts a fake CREDEBL platform.
func New(dir string) *Server {
	f := &Server{
		dir:         dir,
		session:     SessionPending,
		templates:   Templates,
		orgs:        OrgList,
		offer:       OfferPending,
		connections: Connections,
		record:      RecordOfferSent,
		files:       BulkFiles,
		types:       map[string]string{},
		queries:     map[string]string{},
		deleted:     map[string]bool{},
		requests:    map[string][]byte{},
		status:      map[string][]int{},
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

// SetOrgs selects the organisation listing.
func (f *Server) SetOrgs(a Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.orgs = a
}

// SetOfferSession selects the answer of one issuance session.
func (f *Server) SetOfferSession(a Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.offer = a
}

// SetConnections selects the listing of the DIDComm connections.
func (f *Server) SetConnections(a Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connections = a
}

// SetCredentialRecord selects the answer of one DIDComm exchange.
func (f *Server) SetCredentialRecord(a Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record = a
}

// SetBulkFiles selects the listing of the files of the bulk import.
func (f *Server) SetBulkFiles(a Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files = a
}

// Upload reads the CSV file of the last multipart write to the path:
// the name and the content of the part file.
func (f *Server) Upload(path string) (string, []byte, error) {
	f.mu.Lock()
	body, contentType := f.requests[path], f.types[path]
	f.mu.Unlock()
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", nil, err
	}
	r := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		part, err := r.NextPart()
		if err != nil {
			return "", nil, err
		}
		if part.FormName() == "file" {
			raw, err := io.ReadAll(part)
			return part.FileName(), raw, err
		}
	}
}

// Query returns the query of the last call to the path.
func (f *Server) Query(path string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queries[path]
}

// Calls returns the method and path of every call, in order.
func (f *Server) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
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
	body, ignored := io.ReadAll(r.Body)
	_ = ignored
	f.mu.Lock()
	f.requests[r.URL.Path] = body
	f.queries[r.URL.Path] = r.URL.RawQuery
	f.types[r.URL.Path] = r.Header.Get("Content-Type")
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	forced := f.take(r.URL.Path)
	session, templates, orgs, offer := f.session, f.templates, f.orgs, f.offer
	connections, record, files := f.connections, f.record, f.files
	if r.URL.Path == "/v1/auth/signin" {
		f.signins++
	}
	f.mu.Unlock()
	if forced != 0 {
		w.WriteHeader(forced)
		return
	}
	path := r.URL.Path
	if f.serveDidcomm(w, r, connections, record) {
		return
	}
	if f.serveBulk(w, r, files) {
		return
	}
	if f.serveOrgs(w, r, orgs) {
		return
	}
	switch {
	case path == "/v1/auth/signin":
		f.send(w, "signin.json")
	case strings.HasSuffix(path, "/template") && r.Method == http.MethodGet:
		f.send(w, string(templates))
	case strings.HasSuffix(path, "/template"):
		f.send(w, "template-created.json")
	case strings.HasSuffix(path, "/schemas"):
		f.send(w, schemaAnswer(body))
	case strings.HasSuffix(path, "/cred-defs") && r.Method == http.MethodPost:
		f.sendStatus(w, http.StatusCreated, "doc/cred-def-created.json")
	case strings.HasSuffix(path, "/oid4vc/credential-offer") && r.Method == http.MethodGet:
		f.send(w, "doc/offer-sessions.json")
	case strings.Contains(path, "/oid4vc/credential-offer/") && r.Method == http.MethodGet:
		f.send(w, string(offer))
	case path == "/v1/platform/ledgers":
		f.send(w, "doc/platform-ledgers.json")
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

// serveOrgs answers the organisation and agent calls of P6-C1 from the
// answers written from the platform sources (testdata/doc). It reports
// whether it answered.
func (f *Server) serveOrgs(w http.ResponseWriter, r *http.Request, orgs Answer) bool {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "v1" || parts[1] != "orgs" {
		return false
	}
	switch {
	case len(parts) == 2 && r.Method == http.MethodGet:
		if orgs == NoOrgs {
			http.NotFound(w, r)
			return true
		}
		f.send(w, string(orgs))
	case len(parts) == 2 && r.Method == http.MethodPost:
		f.sendStatus(w, http.StatusCreated, "doc/org-created.json")
	case len(parts) == 3 && r.Method == http.MethodGet:
		if f.isDeleted(parts[2]) {
			http.NotFound(w, r)
			return true
		}
		f.send(w, "doc/org.json")
	case len(parts) == 3 && r.Method == http.MethodDelete:
		if f.isDeleted(parts[2]) {
			http.NotFound(w, r)
			return true
		}
		f.mu.Lock()
		f.deleted[parts[2]] = true
		f.mu.Unlock()
		f.sendStatus(w, http.StatusAccepted, "doc/org-deleted.json")
	case len(parts) == 4 && parts[3] == "dids" && r.Method == http.MethodGet:
		f.send(w, "doc/org-dids.json")
	case len(parts) == 4 && parts[3] == "users" && r.Method == http.MethodGet:
		f.send(w, "doc/org-users.json")
	case len(parts) == 4 && parts[3] == "primary-did" && r.Method == http.MethodPut:
		f.sendStatus(w, http.StatusCreated, "doc/primary-did.json")
	case len(parts) == 5 && parts[3] == "agents" && parts[4] == "wallet" && r.Method == http.MethodPost:
		f.sendStatus(w, http.StatusCreated, "doc/wallet-created.json")
	case len(parts) == 5 && parts[3] == "agents" && parts[4] == "did" && r.Method == http.MethodPost:
		f.sendStatus(w, http.StatusCreated, "doc/did-created.json")
	default:
		return false
	}
	return true
}

// serveDidcomm answers the DIDComm issuance calls of P6-C3 from the
// answers written from the platform sources (testdata/doc). It reports
// whether it answered.
func (f *Server) serveDidcomm(w http.ResponseWriter, r *http.Request, connections, record Answer) bool {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "v1" || parts[1] != "orgs" {
		return false
	}
	tail := strings.Join(parts[3:], "/")
	switch {
	case tail == "credentials/oob/offer" && r.Method == http.MethodPost:
		f.sendStatus(w, http.StatusCreated, "doc/oob-offer-created.json")
	case tail == "credentials/offer" && r.Method == http.MethodPost:
		f.sendStatus(w, http.StatusCreated, "doc/connection-offer-created.json")
	case tail == "credentials/oob/email" && r.Method == http.MethodPost:
		f.sendStatus(w, http.StatusCreated, "doc/oob-email-sent.json")
	case tail == "connections" && r.Method == http.MethodGet:
		if connections == NoConnections {
			http.NotFound(w, r)
			return true
		}
		f.send(w, string(connections))
	case len(parts) == 5 && parts[3] == "credentials" && r.Method == http.MethodGet:
		f.send(w, string(record))
	default:
		return false
	}
	return true
}

// serveBulk answers the bulk import calls of P6-C4 from the answers
// written from the platform sources (testdata/doc). It reports whether
// it answered.
func (f *Server) serveBulk(w http.ResponseWriter, r *http.Request, files Answer) bool {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[0] != "v1" || parts[1] != "orgs" {
		return false
	}
	tail := strings.Join(parts[3:], "/")
	switch {
	case tail == "bulk/upload" && r.Method == http.MethodPost:
		f.sendStatus(w, http.StatusCreated, "doc/bulk-upload-created.json")
	case tail == "bulk/files" && r.Method == http.MethodGet:
		if files == NoBulkFiles {
			http.NotFound(w, r)
			return true
		}
		f.send(w, string(files))
	case len(parts) == 5 && parts[4] == "preview" && r.Method == http.MethodGet:
		f.send(w, "doc/bulk-preview.json")
	case len(parts) == 5 && parts[4] == "bulk" && r.Method == http.MethodPost:
		f.sendStatus(w, http.StatusCreated, "doc/bulk-issue-started.json")
	case len(parts) == 6 && parts[4] == "bulk" && parts[5] == "file-data" && r.Method == http.MethodGet:
		f.send(w, "doc/bulk-file-rows.json")
	case len(parts) == 6 && parts[4] == "retry" && parts[5] == "bulk" && r.Method == http.MethodPost:
		f.sendStatus(w, http.StatusCreated, "doc/bulk-retry-started.json")
	default:
		return false
	}
	return true
}

// schemaAnswer picks the answer of a schema write by the type of the
// body: an AnonCreds schema on a ledger, a W3C schema with no ledger, or
// the schema of an SD-JWT template (P6-C2).
func schemaAnswer(body []byte) string {
	var req struct {
		Type    string `json:"type"`
		Payload struct {
			SchemaType string `json:"schemaType"`
		} `json:"schemaPayload"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "schema-created.json"
	}
	switch {
	case req.Type == "indy":
		return "doc/indy-schema-created.json"
	case req.Payload.SchemaType == "no_ledger":
		return "doc/w3c-schema-created.json"
	}
	return "schema-created.json"
}

// isDeleted reports whether the fake deleted the organisation.
func (f *Server) isDeleted(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deleted[id]
}

// sendStatus writes one recorded answer with a status code.
func (f *Server) sendStatus(w http.ResponseWriter, status int, name string) {
	raw, err := os.ReadFile(filepath.Join(f.dir, name)) //nolint:gosec // G304: the name is one of the fixed answers
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(raw); err != nil {
		return
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
