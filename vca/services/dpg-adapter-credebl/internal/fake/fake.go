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
	"errors"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
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
	// OfferRevocable is the session of a revocable offer that no wallet
	// claimed yet. Its credential carries the status entry of the stack.
	OfferRevocable Answer = "doc/offer-session-revocable.json"
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
	// ProofRequestSent is a DIDComm proof exchange no wallet answered.
	ProofRequestSent Answer = "doc/proof-record-request-sent.json"
	// ProofPresentationReceived is a proof exchange whose presentation
	// waits for the verify call.
	ProofPresentationReceived Answer = "doc/proof-record-presentation-received.json"
	// ProofDone is a proof exchange the agent verified.
	ProofDone Answer = "doc/proof-record-done.json"
	// ProofDoneUnverified is a proof exchange whose proof did not verify.
	ProofDoneUnverified Answer = "doc/proof-record-done-unverified.json"
	// ProofAbandoned is a proof exchange the holder declined.
	ProofAbandoned Answer = "doc/proof-record-abandoned.json"
	// VerifiedIndy is the revealed data of an AnonCreds proof.
	VerifiedIndy Answer = "doc/verified-proof-indy.json"
	// VerifiedIndyTwoNames is the revealed data of an AnonCreds proof
	// with two revealed attributes, one referent each.
	VerifiedIndyTwoNames Answer = "doc/verified-proof-indy-two-names.json"
	// VerifiedPE is the revealed data of a DIF PE proof.
	VerifiedPE Answer = "doc/verified-proof-pe.json"
	// Proofs is the list of the proof requests of the organisation.
	Proofs Answer = "doc/proofs.json"
	// NoProofs makes the list of proof requests answer the status not
	// found, as the platform does for an empty list.
	NoProofs Answer = ""
	// PlatformSchemas is the list of the AnonCreds schemas of the
	// platform.
	PlatformSchemas Answer = "doc/platform-schemas.json"
	// NoPlatformSchemas makes the list of schemas answer the status not
	// found, as the platform does for an empty list.
	NoPlatformSchemas Answer = ""
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
	// proof selects the answer of one DIDComm proof exchange.
	proof Answer
	// verified selects the revealed data of a proof.
	verified Answer
	// proofs selects the listing of the proof requests.
	proofs Answer
	// schemas selects the listing of the AnonCreds schemas.
	schemas Answer
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
	// hooked and credentialed hold the organisations with a webhook and
	// with a client credential. notified holds the organisations with an
	// address of the notification service.
	hooked, credentialed, notified map[string]bool
	// eco holds the ecosystems of P6-C9.
	eco ecosystems
	// certs holds the certificate rows of P6-C9 by id, loaded from the
	// recorded list at the first call.
	certs map[string]map[string]any
}

// The certificate rows of the recorded list: the imported certificate,
// which waits for activation, and the older certificate, which is active.
const (
	ImportedCertificateID = "6f1d2c3b-4a5e-4f60-8b7a-9c0d1e2f3a4b"
	OlderCertificateID    = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
)

// EcosystemID is the id the fake gives the ecosystem it creates, as the
// recorded answer names it.
const EcosystemID = "3c9d7a41-6e2b-4f8a-b1d5-7e0c2f4a9b63"

// ecosystems is what the fake keeps of the ecosystems of the platform:
// the switch, the unused invitations of the platform admin, and the one
// ecosystem with its lead and its members in order.
type ecosystems struct {
	on                bool
	invitations       int
	name, description string
	lead              string
	members           []string
}

// New starts a fake CREDEBL platform.
func New(dir string) *Server {
	f := &Server{
		dir:          dir,
		session:      SessionPending,
		templates:    Templates,
		orgs:         OrgList,
		offer:        OfferPending,
		connections:  Connections,
		record:       RecordOfferSent,
		files:        BulkFiles,
		proof:        ProofRequestSent,
		verified:     VerifiedIndy,
		proofs:       Proofs,
		schemas:      PlatformSchemas,
		types:        map[string]string{},
		queries:      map[string]string{},
		deleted:      map[string]bool{},
		requests:     map[string][]byte{},
		status:       map[string][]int{},
		hooked:       map[string]bool{},
		credentialed: map[string]bool{},
		notified:     map[string]bool{},
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

// SetProof selects the answer of one DIDComm proof exchange.
func (f *Server) SetProof(a Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proof = a
}

// SetVerified selects the revealed data of a proof.
func (f *Server) SetVerified(a Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verified = a
}

// SetProofs selects the listing of the proof requests.
func (f *Server) SetProofs(a Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proofs = a
}

// SetPlatformSchemas selects the listing of the AnonCreds schemas.
func (f *Server) SetPlatformSchemas(a Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.schemas = a
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
	proofs := proofAnswers{record: f.proof, verified: f.verified, list: f.proofs, schemas: f.schemas}
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
	if f.serveProofs(w, r, proofs) {
		return
	}
	if f.serveBulk(w, r, files) {
		return
	}
	if f.serveNotify(w, r) {
		return
	}
	if f.serveEcosystem(w, r) {
		return
	}
	if f.serveX509(w, r) {
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
	case strings.Contains(path, "/openid4vc/issuance-sessions/") && strings.HasSuffix(path, "/revoke") && r.Method == http.MethodPost:
		f.send(w, "doc/session-revoked.json")
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

// serveNotify answers the webhook, notification and client credential
// calls of P6-C8 from the answers written from the platform sources
// (testdata/doc). It keeps which organisation holds each, as the
// platform does. It reports whether it answered.
func (f *Server) serveNotify(w http.ResponseWriter, r *http.Request) bool {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	org := r.URL.Query().Get("orgId")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/v1/webhooks/orgs/webhookurl" && r.Method == http.MethodGet:
		if f.hooked[org] {
			f.send(w, "doc/webhook-url.json")
		} else {
			f.send(w, "doc/webhook-url-none.json")
		}
	case len(parts) == 5 && parts[1] == "webhooks" && parts[4] == "register" && r.Method == http.MethodPost:
		f.hooked[parts[3]] = true
		f.sendStatus(w, http.StatusCreated, "doc/webhook-registered.json")
	case r.URL.Path == "/v1/notification/register/webhook-endpoint" && r.Method == http.MethodPost:
		var body struct {
			OrgID string `json:"orgId"`
		}
		if json.Unmarshal(f.requests[r.URL.Path], &body) != nil || f.notified[body.OrgID] {
			// The organisation column is unique, so a second row fails.
			w.WriteHeader(http.StatusInternalServerError)
			return true
		}
		f.notified[body.OrgID] = true
		f.sendStatus(w, http.StatusCreated, "doc/notification-endpoint-registered.json")
	case len(parts) == 4 && parts[1] == "orgs" && parts[3] == "client_credentials":
		f.serveCredential(w, r, parts[2])
	default:
		return false
	}
	return true
}

// serveEcosystem answers the ecosystem calls of P6-C9 from the answers
// written from the platform sources (testdata/doc). Like the platform,
// it refuses every ecosystem call while the switch is off, refuses a
// create without an unused invitation of the platform admin and with a
// name that exists, refuses the lead as a member, and answers not found
// for an ecosystem without members. It reports whether it answered.
func (f *Server) serveEcosystem(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	if path != "/v1/config/ecosystem" && path != "/v1/invitations" && path != "/v1/ecosystem/status" &&
		path != "/v1/ecosystem" && !strings.HasPrefix(path, "/v1/ecosystem/") {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	body := f.requests[path]
	e := &f.eco
	switch {
	case path == "/v1/ecosystem/status" && r.Method == http.MethodGet:
		if e.on {
			f.send(w, "doc/ecosystem-status.json")
		} else {
			f.send(w, "doc/ecosystem-status-off.json")
		}
	case path == "/v1/config/ecosystem" && r.Method == http.MethodPut:
		var in struct {
			On bool `json:"isEcosystemEnabled"`
		}
		if json.Unmarshal(body, &in) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		e.on = in.On
		f.send(w, "doc/ecosystem-config-updated.json")
	case !e.on:
		// The feature guard of the platform.
		w.WriteHeader(http.StatusForbidden)
	case path == "/v1/invitations" && r.Method == http.MethodPost:
		e.invitations++
		f.sendStatus(w, http.StatusCreated, "doc/ecosystem-invitation-created.json")
	case path == "/v1/ecosystem" && r.Method == http.MethodPost:
		f.createEcosystem(w, r.URL.Query().Get("orgId"), body)
	case path == "/v1/ecosystem" && r.Method == http.MethodGet:
		f.listEcosystems(w, r.URL.Query().Get("orgId"))
	case path == "/v1/ecosystem/members" && r.Method == http.MethodGet:
		f.listMembers(w, r)
	case path == "/v1/ecosystem/invitation" && r.Method == http.MethodPost:
		var in struct {
			OrgID string `json:"orgId"`
		}
		if json.Unmarshal(body, &in) != nil || in.OrgID == e.lead {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		e.members = append(e.members, in.OrgID)
		f.sendStatus(w, http.StatusCreated, "doc/ecosystem-member-invited.json")
	case path == "/v1/ecosystem/member" && r.Method == http.MethodDelete:
		var in struct {
			OrgIDs []string `json:"orgIds"`
		}
		n := len(e.members)
		if json.Unmarshal(body, &in) == nil {
			e.members = slices.DeleteFunc(e.members, func(m string) bool { return slices.Contains(in.OrgIDs, m) })
		}
		if len(e.members) == n {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		f.sendStatus(w, http.StatusCreated, "doc/ecosystem-member-deleted.json")
	default:
		http.NotFound(w, r)
	}
	return true
}

// serveX509 answers the certificate calls of P6-C9 from the recorded
// list (testdata/doc). It keeps the status of each row. It refuses a
// second active row of one key type, as the platform does for rows whose
// dates meet. It reports whether it answered.
func (f *Server) serveX509(w http.ResponseWriter, r *http.Request) bool {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[1] != "x509" {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.certs == nil {
		f.certs = map[string]map[string]any{}
		doc, err := f.loadJSON("doc/x509-certificates.json")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		for _, row := range asList(asMap(doc["data"])["data"]) {
			f.certs[anyval.As[string](asMap(row)["id"])] = asMap(row)
		}
	}
	switch {
	case len(parts) == 3 && r.Method == http.MethodGet:
		q := r.URL.Query()
		f.sendJSON(w, http.StatusOK, "doc/x509-certificates.json", func(doc map[string]any) {
			list := []any{}
			for _, id := range slices.Sorted(maps.Keys(f.certs)) {
				row := f.certs[id]
				if row["status"] == q.Get("status") && row["keyType"] == q.Get("keyType") {
					list = append(list, row)
				}
			}
			doc["data"] = map[string]any{"data": list, "total": len(list)}
		})
	case len(parts) == 4 && r.Method == http.MethodGet && f.certs[parts[3]] != nil:
		f.sendJSON(w, http.StatusOK, "doc/x509-certificate.json", func(doc map[string]any) { doc["data"] = f.certs[parts[3]] })
	case len(parts) == 5 && r.Method == http.MethodPut && f.certs[parts[4]] != nil:
		f.setCertificate(w, parts[3], f.certs[parts[4]])
	default:
		http.NotFound(w, r)
	}
	return true
}

// setCertificate activates or deactivates one row. The caller holds the
// lock.
func (f *Server) setCertificate(w http.ResponseWriter, action string, row map[string]any) {
	switch action {
	case "activate":
		for _, other := range f.certs {
			if other["id"] != row["id"] && other["status"] == "Active" && other["keyType"] == row["keyType"] {
				w.WriteHeader(http.StatusConflict)
				return
			}
		}
		row["status"] = "Active"
		f.sendJSON(w, http.StatusOK, "doc/x509-activated.json", func(doc map[string]any) { doc["data"] = row })
	case "deactivate":
		row["status"] = "In Active"
		f.sendJSON(w, http.StatusOK, "doc/x509-deactivated.json", func(doc map[string]any) { doc["data"] = row })
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// createEcosystem makes the one ecosystem of the fake. The caller holds
// the lock.
func (f *Server) createEcosystem(w http.ResponseWriter, lead string, body []byte) {
	e := &f.eco
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	switch {
	case e.invitations == 0:
		w.WriteHeader(http.StatusForbidden)
		return
	case json.Unmarshal(body, &in) != nil:
		w.WriteHeader(http.StatusBadRequest)
		return
	case e.lead != "":
		w.WriteHeader(http.StatusConflict)
		return
	}
	e.invitations--
	e.name, e.description, e.lead = in.Name, in.Description, lead
	f.sendJSON(w, http.StatusCreated, "doc/ecosystem-created.json", func(doc map[string]any) {
		data := asMap(doc["data"])
		data["name"], data["description"] = e.name, e.description
	})
}

// listEcosystems lists the ecosystem for its lead and its members. The
// caller holds the lock.
func (f *Server) listEcosystems(w http.ResponseWriter, org string) {
	e := &f.eco
	if e.lead == "" || (org != e.lead && !slices.Contains(e.members, org)) {
		f.send(w, "doc/ecosystems-none.json")
		return
	}
	f.sendJSON(w, http.StatusOK, "doc/ecosystems.json", func(doc map[string]any) {
		entry := asMap(asList(asMap(doc["data"])["data"])[0])
		entry["name"], entry["description"], entry["memberCount"] = e.name, e.description, len(e.members)
		asMap(entry["leadOrg"])["id"] = e.lead
		if org != e.lead {
			entry["role"] = "Ecosystem Member"
		}
	})
}

// listMembers lists the members of the ecosystem. The caller holds the
// lock.
func (f *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	e := &f.eco
	if r.URL.Query().Get("ecosystemId") != EcosystemID || len(e.members) == 0 {
		http.NotFound(w, r)
		return
	}
	f.sendJSON(w, http.StatusOK, "doc/ecosystem-members.json", func(doc map[string]any) {
		data := asMap(doc["data"])
		recorded := asList(data["data"])[0]
		list := make([]any, 0, len(e.members))
		for _, m := range e.members {
			raw, err := json.Marshal(recorded)
			var entry map[string]any
			if err != nil || json.Unmarshal(raw, &entry) != nil {
				continue
			}
			asMap(entry["organisation"])["id"] = m
			list = append(list, entry)
		}
		data["data"] = list
	})
}

// asMap reads an object of a recorded answer.
func asMap(v any) map[string]any { return anyval.As[map[string]any](v) }

// asList reads a list of a recorded answer.
func asList(v any) []any { return anyval.As[[]any](v) }

// loadJSON reads one recorded answer as JSON.
func (f *Server) loadJSON(name string) (map[string]any, error) {
	raw, err := os.ReadFile(filepath.Join(f.dir, name)) //nolint:gosec // G304: the name is one of the fixed answers
	var doc map[string]any
	if err == nil {
		err = json.Unmarshal(raw, &doc)
	}
	if err != nil {
		return nil, errors.New("the recorded answer " + name + " is damaged")
	}
	return doc, nil
}

// sendJSON writes one recorded answer after a change of its parts.
func (f *Server) sendJSON(w http.ResponseWriter, status int, name string, change func(map[string]any)) {
	doc, err := f.loadJSON(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	change(doc)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(out); err != nil {
		return
	}
}

// serveCredential answers the client credential calls of one
// organisation. The caller holds the lock.
func (f *Server) serveCredential(w http.ResponseWriter, r *http.Request, org string) {
	switch r.Method {
	case http.MethodGet:
		if !f.credentialed[org] {
			http.NotFound(w, r)
			return
		}
		f.send(w, "doc/client-credentials.json")
	case http.MethodPost:
		f.credentialed[org] = true
		f.sendStatus(w, http.StatusCreated, "doc/client-credentials-created.json")
	case http.MethodDelete:
		delete(f.credentialed, org)
		f.sendStatus(w, http.StatusAccepted, "doc/client-credentials-deleted.json")
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
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

// proofAnswers are the answers the proof calls of P6-C6 switch between.
type proofAnswers struct {
	record, verified, list, schemas Answer
}

// serveProofs answers the DIDComm proof calls of P6-C6 from the answers
// written from the platform sources (testdata/doc). It reports whether
// it answered.
func (f *Server) serveProofs(w http.ResponseWriter, r *http.Request, a proofAnswers) bool {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.URL.Path == "/v1/platform/schemas" && r.Method == http.MethodGet:
		f.sendOrNotFound(w, r, a.schemas)
		return true
	case r.URL.Path == "/v1/platform/cred-defs" && r.Method == http.MethodGet:
		f.send(w, "doc/platform-cred-defs.json")
		return true
	case len(parts) < 4 || parts[0] != "v1" || parts[1] != "orgs":
		return false
	}
	tail := strings.Join(parts[3:], "/")
	switch {
	case tail == "proofs/oob" && r.Method == http.MethodPost:
		f.sendStatus(w, http.StatusCreated, "doc/proof-oob-created.json")
	case tail == "proofs" && r.Method == http.MethodPost:
		f.sendStatus(w, http.StatusCreated, "doc/proof-connection-created.json")
	case tail == "proofs" && r.Method == http.MethodGet:
		f.sendOrNotFound(w, r, a.list)
	case len(parts) == 5 && parts[3] == "proofs" && r.Method == http.MethodGet:
		f.send(w, string(a.record))
	case len(parts) == 6 && parts[3] == "proofs" && parts[5] == "verify" && r.Method == http.MethodPost:
		f.sendStatus(w, http.StatusCreated, "doc/proof-verified.json")
	case len(parts) == 5 && parts[3] == "verified-proofs" && r.Method == http.MethodGet:
		f.send(w, string(a.verified))
	default:
		return false
	}
	return true
}

// sendOrNotFound writes one recorded answer, or the status not found
// for the empty answer, as the platform does for an empty list.
func (f *Server) sendOrNotFound(w http.ResponseWriter, r *http.Request, a Answer) {
	if a == "" {
		http.NotFound(w, r)
		return
	}
	f.send(w, string(a))
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
