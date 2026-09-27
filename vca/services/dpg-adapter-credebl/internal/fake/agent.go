// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// AgentAPIKey is the API key the fake agent takes.
const AgentAPIKey = "agent-api-key" //nolint:gosec // G101: the key of the fake agent in tests, not a credential.

// FirstTenant is the id of the first tenant the fake agent makes.
const FirstTenant = "5f3c6a1e-8b2d-4c7a-9e1f-2a3b4c5d6e7f"

// The ids of the records in the agent answers of testdata/doc.
const (
	// OfferRecord is the credential exchange of the offer.
	OfferRecord = "7b6a5c4d-3e2f-4a1b-8c9d-0e1f2a3b4c5d"
	// OfferThread is the thread of the offer.
	OfferThread = "9c8d7e6f-5a4b-4c3d-9e2f-1a0b9c8d7e6f"
	// ProofRecord is the proof exchange of the proof request.
	ProofRecord = "4f5a6b7c-8d9e-4f0a-9b1c-2d3e4f5a6b7c"
	// ProofThread is the thread of the proof request.
	ProofThread = "3d4e5f6a-7b8c-4d9e-8f0a-1b2c3d4e5f6a"
	// W3cRecord is the stored W3C credential.
	W3cRecord = "d2e3f4a5-b6c7-4d8e-9f0a-1b2c3d4e5f6a"
	// HolderDid is the did:key the fake agent makes.
	HolderDid = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
)

// The agent answers the tests switch between.
const (
	// OfferDone is an offer the issuer answered with a credential.
	OfferDone Answer = "doc/agent-credential-done.json"
	// OfferAbandoned is an offer the issuer withdrew.
	OfferAbandoned Answer = "doc/agent-credential-abandoned.json"
	// OfferDoneJSONLD is an offer the issuer answered with a W3C
	// JSON-LD credential.
	OfferDoneJSONLD Answer = "doc/agent-credential-done-jsonld.json"
	// OfferDoneUnbound is a finished exchange that names no stored
	// credential.
	OfferDoneUnbound Answer = "doc/agent-credential-done-unbound.json"
	// OfferRequestSent is an offer the issuer did not answer yet.
	OfferRequestSent Answer = "doc/agent-credential-request-sent.json"
	// HolderProofDone is a proof the verifier took.
	HolderProofDone Answer = "doc/agent-proof-done.json"
	// HolderProofAbandoned is a proof the verifier refused.
	HolderProofAbandoned Answer = "doc/agent-proof-abandoned.json"
	// HolderProofSent is a proof the verifier did not answer yet.
	HolderProofSent Answer = "doc/agent-proof-presentation-sent.json"
	// OfferPreAuthorized is an OID4VCI offer with a pre-authorized code
	// that needs a transaction code.
	OfferPreAuthorized Answer = "doc/agent-oid4vci-offer-resolved.json"
	// OfferAuthorizationCode is an OID4VCI offer with an authorization
	// code grant only.
	OfferAuthorizationCode Answer = "doc/agent-oid4vci-offer-authorization-code.json"
	// Oid4vpAccepted is an OID4VP answer the verifier took.
	Oid4vpAccepted Answer = "doc/agent-oid4vp-request-accepted.json"
	// Oid4vpRefused is an OID4VP answer the verifier refused.
	Oid4vpRefused Answer = "doc/agent-oid4vp-request-refused.json"
	// Oid4vpResolved is an OID4VP request with one claim.
	Oid4vpResolved Answer = "doc/agent-oid4vp-request-resolved.json"
	// Oid4vpResolvedClaimSets is an OID4VP request whose claim sets make
	// one claim optional. The agent discloses both claims.
	Oid4vpResolvedClaimSets Answer = "doc/agent-oid4vp-request-resolved-claim-sets.json"
)

// SdJwtRecord is the stored SD-JWT VC of the agent answers.
const SdJwtRecord = "e1f2a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b"

// MdocRecord is the stored mdoc of the agent answers.
const MdocRecord = "f2a3b4c5-d6e7-4f8a-9b0c-1d2e3f4a5b6c"

// Invitation returns one recorded invitation URL of the agent answers:
// offer, request, or connection.
func Invitation(dir, kind string) string {
	raw, err := os.ReadFile(filepath.Join(dir, "doc", "agent-invitations.txt")) //nolint:gosec // G304: a fixed fixture name
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if name, uri, ok := strings.Cut(line, " "); ok && name == kind {
			return uri
		}
	}
	return ""
}

// Agent is a running fake of the shared agent of the stack. It keeps
// the state of one offer and one proof request of each tenant.
type Agent struct {
	// Server is the HTTP test server.
	Server *httptest.Server

	mu  sync.Mutex
	dir string
	// tenants holds the ids of the tenants the fake made.
	tenants []string
	// offered and requested report that an invitation reached the
	// tenant.
	offered, requested bool
	// accepted and answered report the accept calls.
	accepted, answered bool
	// credentialEnd and proofEnd are the answers after an accept.
	credentialEnd, proofEnd Answer
	// offer and vpEnd are the OID4VCI offer and the OID4VP answer.
	offer, vpEnd Answer
	// resolved is the OID4VP request the agent reads.
	resolved Answer
	// inbox reports that an offer and a request wait over a connection.
	inbox bool
	// calls records the method and path of every call, in order.
	calls []string
	// bodies records the body of every write call by path.
	bodies map[string][]byte
	// status forces a status code for one path.
	status map[string][]int
}

// NewAgent starts a fake agent.
func NewAgent(dir string) *Agent {
	a := &Agent{dir: dir, credentialEnd: OfferDone, proofEnd: HolderProofDone, offer: OfferPreAuthorized, vpEnd: Oid4vpAccepted, resolved: Oid4vpResolved,
		bodies: map[string][]byte{}, status: map[string][]int{}}
	a.Server = httptest.NewServer(http.HandlerFunc(a.serve))
	return a
}

// Close stops the fake.
func (a *Agent) Close() { a.Server.Close() }

// URL is the base URL of the fake.
func (a *Agent) URL() string { return a.Server.URL }

// Client is an HTTP client that reaches the fake.
func (a *Agent) Client() *http.Client { return a.Server.Client() }

// SetCredentialEnd selects the answer of the offer after the accept.
func (a *Agent) SetCredentialEnd(end Answer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.credentialEnd = end
}

// SetProofEnd selects the answer of the proof after the accept.
func (a *Agent) SetProofEnd(end Answer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.proofEnd = end
}

// SetOid4vc selects the OID4VCI offer and the answer of the OID4VP
// verifier.
func (a *Agent) SetOid4vc(offer, vpEnd Answer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.offer, a.vpEnd = offer, vpEnd
}

// SetResolved selects the OID4VP request the agent reads.
func (a *Agent) SetResolved(resolved Answer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.resolved = resolved
}

// SetInbox makes an offer and a proof request wait over a connection.
func (a *Agent) SetInbox(on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.inbox = on
}

// SetStatus makes the fake answer the method and path with the statuses
// in order.
func (a *Agent) SetStatus(key string, statuses ...int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status[key] = statuses
}

// Calls returns the method and path of every call, in order.
func (a *Agent) Calls() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.calls...)
}

// Body returns the last body of a write call to the method and path.
func (a *Agent) Body(key string) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.bodies[key]
}

// attachedKind reads the kind of an invitation URL: offer, request, or
// connection.
func attachedKind(invitationURL string) string {
	u, err := url.Parse(invitationURL)
	if err != nil {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(u.Query().Get("oob"), "="))
	if err != nil {
		return ""
	}
	switch text := string(raw); {
	case strings.Contains(text, `"requests~attach"`) && strings.Contains(text, `"label":"[issuer organisation]"`):
		return "offer"
	case strings.Contains(text, `"requests~attach"`):
		return "request"
	case strings.Contains(text, "out-of-band"):
		return "connection"
	}
	return ""
}

func (a *Agent) serve(w http.ResponseWriter, r *http.Request) {
	body, ignored := io.ReadAll(r.Body)
	_ = ignored
	key := r.Method + " " + r.URL.Path
	a.mu.Lock()
	a.calls = append(a.calls, key)
	a.bodies[key] = body
	var forced int
	if list := a.status[key]; len(list) > 0 {
		forced, a.status[key] = list[0], list[1:]
	}
	a.mu.Unlock()
	switch {
	case forced != 0:
		w.WriteHeader(forced)
	case key == "POST /agent/token":
		if r.Header.Get("Authorization") != AgentAPIKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		a.send(w, "doc/agent-token.json")
	case !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer "):
		w.WriteHeader(http.StatusUnauthorized)
	case key == "POST /multi-tenancy/create-tenant":
		a.createTenant(w)
	case strings.HasPrefix(key, "POST /multi-tenancy/get-token/"):
		a.send(w, "doc/agent-tenant-token.json")
	case key == "POST /dids/write":
		a.send(w, "doc/agent-did-created.json")
	case key == "GET /dids":
		a.send(w, "doc/agent-dids.json")
	case key == "GET /didcomm/connections":
		a.send(w, "doc/agent-connections.json")
	case strings.HasPrefix(key, "GET /didcomm/connections/"):
		a.send(w, "doc/agent-connection-completed.json")
	case key == "POST /didcomm/oob/receive-invitation-url":
		a.receive(w, body)
	default:
		if !a.serveCredentials(w, r, key) && !a.serveProofs(w, r, key) && !a.serveOid4vc(w, key) {
			http.NotFound(w, r)
		}
	}
}

// createTenant answers a new tenant. The first one has the id of the
// recorded answer, and each later one a new id.
func (a *Agent) createTenant(w http.ResponseWriter) {
	raw, err := os.ReadFile(filepath.Join(a.dir, "doc", "agent-tenant-created.json"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	id := FirstTenant
	if n := len(a.tenants); n > 0 {
		id = "tenant-" + strconv.Itoa(n+1)
	}
	a.tenants = append(a.tenants, id)
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(strings.Replace(string(raw), FirstTenant, id, 1))); err != nil {
		return
	}
}

// receive answers an invitation by the message it carries.
func (a *Agent) receive(w http.ResponseWriter, body []byte) {
	var req struct {
		URL string `json:"invitationUrl"`
	}
	if json.Unmarshal(body, &req) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch attachedKind(req.URL) {
	case "offer":
		a.offered = true
		a.send(w, "doc/agent-oob-received-offer.json")
	case "request":
		a.requested = true
		a.send(w, "doc/agent-oob-received-request.json")
	case "connection":
		a.send(w, "doc/agent-oob-received-connection.json")
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

// serveCredentials answers the credential calls. It reports whether it
// answered.
func (a *Agent) serveCredentials(w http.ResponseWriter, r *http.Request, key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	q := r.URL.Query()
	switch {
	case key == "GET /didcomm/credentials" && q.Get("state") == "done":
		a.send(w, "doc/agent-credentials-done.json")
	case key == "GET /didcomm/credentials" && q.Get("threadId") != "":
		a.sendList(w, a.offered && !a.accepted && q.Get("threadId") == OfferThread, "doc/agent-credentials-offer-received.json")
	case key == "GET /didcomm/credentials":
		a.sendList(w, a.inbox && !a.accepted, "doc/agent-credentials-offer-received.json")
	case key == "POST /didcomm/credentials/accept-offer":
		a.accepted = true
		a.send(w, string(OfferRequestSent))
	case key == "GET /didcomm/credentials/w3c":
		a.send(w, "doc/agent-w3c-credentials.json")
	case key == "GET /didcomm/credentials/"+OfferRecord+"/form-data":
		a.send(w, "doc/agent-credential-form-data.json")
	case key == "GET /didcomm/credentials/"+OfferRecord && a.accepted:
		a.send(w, string(a.credentialEnd))
	case key == "GET /didcomm/credentials/"+OfferRecord:
		a.send(w, "doc/agent-credential-offer-received.json")
	case key == "DELETE /openid4vc/holder/credential":
		a.sendText(w, "{}")
	default:
		return false
	}
	return true
}

// serveProofs answers the proof calls. It reports whether it answered.
func (a *Agent) serveProofs(w http.ResponseWriter, r *http.Request, key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	thread := r.URL.Query().Get("threadId")
	switch {
	case key == "GET /didcomm/proofs" && thread != "":
		a.sendList(w, a.requested && !a.answered && thread == ProofThread, "doc/agent-proofs-request-received.json")
	case key == "GET /didcomm/proofs":
		a.sendList(w, a.inbox && !a.answered, "doc/agent-proofs-request-received.json")
	case key == "POST /didcomm/proofs/"+ProofRecord+"/accept-request":
		a.answered = true
		a.send(w, string(HolderProofSent))
	case key == "GET /didcomm/proofs/"+ProofRecord+"/form-data":
		a.send(w, "doc/agent-proof-form-data.json")
	case key == "GET /didcomm/proofs/"+ProofRecord && a.answered:
		a.send(w, string(a.proofEnd))
	case key == "GET /didcomm/proofs/"+ProofRecord:
		a.send(w, "doc/agent-proof-request-received.json")
	default:
		return false
	}
	return true
}

// serveOid4vc answers the OID4VC holder calls. It reports whether it
// answered.
func (a *Agent) serveOid4vc(w http.ResponseWriter, key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch key {
	case "POST /openid4vc/holder/resolve-credential-offer":
		a.send(w, string(a.offer))
	case "POST /openid4vc/holder/request-credential":
		a.send(w, "doc/agent-oid4vci-credential-stored.json")
	case "GET /openid4vc/holder/sd-jwt-vcs":
		a.send(w, "doc/agent-sd-jwt-vcs.json")
	case "GET /openid4vc/holder/mdoc-vcs":
		a.send(w, "doc/agent-mdoc-vcs.json")
	case "POST /openid4vc/holder/resolve-proof-request":
		a.send(w, string(a.resolved))
	case "POST /openid4vc/holder/accept-proof-request":
		a.send(w, string(a.vpEnd))
	default:
		return false
	}
	return true
}

// sendList writes a recorded list when on is true, and an empty list
// when it is false.
func (a *Agent) sendList(w http.ResponseWriter, on bool, name string) {
	if !on {
		a.sendText(w, "[]")
		return
	}
	a.send(w, name)
}

// send writes one recorded answer.
func (a *Agent) send(w http.ResponseWriter, name string) {
	raw, err := os.ReadFile(filepath.Join(a.dir, name)) //nolint:gosec // G304: the name is one of the fixed answers
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.sendText(w, string(raw))
}

// sendText writes a JSON body.
func (a *Agent) sendText(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(text)); err != nil {
		return
	}
}
