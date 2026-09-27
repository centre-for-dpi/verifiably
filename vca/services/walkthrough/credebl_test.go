// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package walkthrough_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/core/statuslist/token"
)

// The CREDEBL stack as a test double: the api gateway of platform
// v2.2.1-alpha.4, the OID4VCI issuer of the agent, and the status list
// host. The answers follow the shapes of the fixtures of the adapter
// (services/dpg-adapter-credebl/testdata). The operator made the DID of
// the organisation in the platform before the walkthrough, as
// docs/dpg-adapter-credebl.md tells. The agent signs each SD-JWT VC with
// the key of that DID, and a revocable offer gives the credential an
// entry in a Token Status List that the same key signs.
//
//	POST /v1/auth/signin
//	GET  /v1/orgs/{org}  and  /v1/orgs/{org}/dids
//	GET  POST /v1/orgs/{org}/oid4vc/{issuer}/template
//	POST /v1/orgs/{org}/schemas
//	POST /v1/orgs/{org}/oid4vc/{issuer}/create-offer
//	GET  /v1/orgs/{org}/oid4vc/credential-offer  and  .../{id}
//	POST /v1/orgs/{org}/openid4vc/issuance-sessions/{id}/revoke
//	GET  /oid4vci/{issuer}/offers/{id}, the metadata, POST token, credential
//	GET  /status-lists/{id}
type credeblStack struct {
	t   *testing.T
	srv *httptest.Server
	org string
	// issuer is the OID4VC issuer of the organisation.
	issuer string
	key    ed25519.PrivateKey
	did    string

	mu        sync.Mutex
	templates []credeblTemplate
	sessions  map[string]*credeblSession
	codes     map[string]string
	tokens    map[string]string
	list      *token.List
	next      int
	// unknown records the paths the double does not serve.
	unknown []string
}

// credeblTemplate is one credential template of the issuer.
type credeblTemplate struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Format string          `json:"format"`
	Body   json.RawMessage `json:"attributes"`
}

// credeblSession is one issuance session of the agent.
type credeblSession struct {
	id, template, vct, format, pin, code, state string
	payload                                     map[string]any
	revocable                                   bool
	index                                       int
	created, updated                            time.Time
}

// statusListID is the one list of the status list host.
const statusListID = "6f1e2d3c-4b5a-4968-8778-a1b2c3d4e5f6"

func newCredeblStack(t *testing.T) *credeblStack {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := did.FromPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	list, err := token.New(1, 1<<17)
	if err != nil {
		t.Fatal(err)
	}
	c := &credeblStack{
		t: t, org: "0b6c2f0e-5a38-4a1e-9d2b-3f7c1e6a9d41", issuer: "credebl-issuer", key: key, did: id,
		sessions: map[string]*credeblSession{}, codes: map[string]string{}, tokens: map[string]string{}, list: list, next: 4211,
	}
	c.srv = httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.srv.Close)
	return c
}

// envelope writes the answer shape of the api gateway.
func envelope(rw http.ResponseWriter, status int, message string, data any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	writeJSON(rw, map[string]any{"statusCode": status, "message": message, "data": data})
}

func (c *credeblStack) serve(rw http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	path := r.URL.Path
	orgs := "/v1/orgs/" + c.org
	agent := "/oid4vci/" + c.issuer
	switch {
	case path == "/v1/auth/signin" && r.Method == http.MethodPost:
		// The token names an expiry far ahead, as the fixture does.
		envelope(rw, http.StatusOK, "User signed in successfully", map[string]any{
			"access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJwbGF0Zm9ybS1hZG1pbiIsImV4cCI6NDA3MDkwODgwMH0.c2ln",
			"token_type":   "Bearer", "expires_in": 1800,
		})
	case path == "/v1/platform/ledgers" && r.Method == http.MethodGet:
		envelope(rw, http.StatusOK, "Ledgers details fetched successfully", []map[string]any{{
			"id": "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "name": "Bcovrin Testnet", "networkType": "testnet",
			"isActive": true, "networkString": "testnet", "indyNamespace": "bcovrin:testnet",
		}})
	case path == "/v1/platform/schemas" && r.Method == http.MethodGet, path == orgs+"/connections" && r.Method == http.MethodGet:
		// The platform holds no AnonCreds schema and no DIDComm
		// connection in this walkthrough.
		envelope(rw, http.StatusOK, "Details fetched successfully.", map[string]any{
			"totalItems": 0, "hasNextPage": false, "hasPreviousPage": false, "nextPage": 2, "previousPage": 0, "lastPage": 1,
			"data": []any{},
		})
	case path == orgs && r.Method == http.MethodGet:
		envelope(rw, http.StatusOK, "Organization details fetched successfully", map[string]any{
			"id": c.org, "name": "Ministry of Agriculture", "orgSlug": "ministry-of-agriculture",
			"org_agents": []map[string]any{{"orgDid": c.did}},
		})
	case path == orgs+"/dids" && r.Method == http.MethodGet:
		envelope(rw, http.StatusOK, "Organization DIDs fetched successfully", []map[string]any{{
			"id": "5e0f1a2b-3c4d-4e5f-9a6b-7c8d9e0f1a2b", "did": c.did, "isPrimaryDid": true,
			"createDateTime": "2026-09-27T08:00:00.000Z", "lastChangedDateTime": "2026-09-27T08:00:00.000Z",
		}})
	case path == orgs+"/oid4vc/"+c.issuer+"/template" && r.Method == http.MethodGet:
		c.mu.Lock()
		list := append([]credeblTemplate(nil), c.templates...)
		c.mu.Unlock()
		envelope(rw, http.StatusOK, "Templates fetched", list)
	case path == orgs+"/oid4vc/"+c.issuer+"/template" && r.Method == http.MethodPost:
		c.createTemplate(rw, body)
	case path == orgs+"/schemas" && r.Method == http.MethodPost:
		envelope(rw, http.StatusCreated, "Schema created", map[string]any{"id": randomID()})
	case path == orgs+"/oid4vc/"+c.issuer+"/create-offer" && r.Method == http.MethodPost:
		c.createOffer(rw, body)
	case path == orgs+"/oid4vc/credential-offer" && r.Method == http.MethodGet:
		c.mu.Lock()
		list := make([]*credeblSession, 0, len(c.sessions))
		for _, s := range c.sessions {
			list = append(list, s)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].created.Before(list[j].created) })
		out := make([]map[string]any, 0, len(list))
		for _, s := range list {
			out = append(out, c.sessionJSON(s))
		}
		c.mu.Unlock()
		envelope(rw, http.StatusOK, "Offers fetched", out)
	case strings.HasPrefix(path, orgs+"/oid4vc/credential-offer/") && r.Method == http.MethodGet:
		c.mu.Lock()
		s, ok := c.sessions[strings.TrimPrefix(path, orgs+"/oid4vc/credential-offer/")]
		var out map[string]any
		if ok {
			out = c.sessionJSON(s)
		}
		c.mu.Unlock()
		if !ok {
			envelope(rw, http.StatusNotFound, "Offer not found", nil)
			return
		}
		envelope(rw, http.StatusOK, "Offer fetched", out)
	case strings.HasPrefix(path, orgs+"/openid4vc/issuance-sessions/") && strings.HasSuffix(path, "/revoke") && r.Method == http.MethodPost:
		c.revoke(rw, strings.TrimSuffix(strings.TrimPrefix(path, orgs+"/openid4vc/issuance-sessions/"), "/revoke"))
	case strings.HasPrefix(path, agent+"/offers/") && r.Method == http.MethodGet:
		c.offer(rw, r, strings.TrimPrefix(path, agent+"/offers/"))
	case path == agent+"/.well-known/openid-credential-issuer":
		c.metadata(rw)
	case path == agent+"/.well-known/oauth-authorization-server":
		writeJSON(rw, map[string]any{
			"issuer": c.srv.URL + agent, "token_endpoint": c.srv.URL + agent + "/token",
			"pre-authorized_grant_anonymous_access_supported": true,
		})
	case path == agent+"/token" && r.Method == http.MethodPost:
		c.token(rw, body)
	case path == agent+"/credential" && r.Method == http.MethodPost:
		c.credential(rw, r)
	case path == "/status-lists/"+statusListID && r.Method == http.MethodGet:
		c.statusList(rw)
	default:
		c.mu.Lock()
		c.unknown = append(c.unknown, r.Method+" "+r.URL.String())
		c.mu.Unlock()
		envelope(rw, http.StatusNotFound, "Cannot "+r.Method+" "+path, nil)
	}
}

// createTemplate stores one template as the platform does.
func (c *credeblStack) createTemplate(rw http.ResponseWriter, body []byte) {
	var req struct {
		Name     string          `json:"name"`
		Format   string          `json:"format"`
		Template json.RawMessage `json:"template"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Name == "" {
		envelope(rw, http.StatusBadRequest, "The template is not valid", nil)
		return
	}
	tmpl := credeblTemplate{ID: randomUUID(), Name: req.Name, Format: req.Format, Body: req.Template}
	c.mu.Lock()
	c.templates = append(c.templates, tmpl)
	c.mu.Unlock()
	envelope(rw, http.StatusCreated, "Template created", map[string]any{"id": tmpl.ID, "name": tmpl.Name, "format": tmpl.Format})
}

// createOffer makes a pre-authorized code offer of one template.
func (c *credeblStack) createOffer(rw http.ResponseWriter, body []byte) {
	var req struct {
		AuthorizationType string `json:"authorizationType"`
		Credentials       []struct {
			TemplateID string         `json:"templateId"`
			Payload    map[string]any `json:"payload"`
		} `json:"credentials"`
		IsRevocable bool `json:"isRevocable"`
	}
	if err := json.Unmarshal(body, &req); err != nil || len(req.Credentials) != 1 || req.AuthorizationType != "preAuthorizedCodeFlow" {
		envelope(rw, http.StatusBadRequest, "The offer is not valid", nil)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var tmpl *credeblTemplate
	for i := range c.templates {
		if c.templates[i].ID == req.Credentials[0].TemplateID {
			tmpl = &c.templates[i]
		}
	}
	if tmpl == nil {
		envelope(rw, http.StatusNotFound, "Template not found", nil)
		return
	}
	var shape struct {
		Vct string `json:"vct"`
	}
	if err := json.Unmarshal(tmpl.Body, &shape); err != nil {
		envelope(rw, http.StatusInternalServerError, err.Error(), nil)
		return
	}
	now := time.Now().UTC()
	s := &credeblSession{
		id: randomUUID(), template: tmpl.Name, vct: shape.Vct, format: tmpl.Format, pin: "8143", code: randomID(),
		state: "OfferCreated", payload: req.Credentials[0].Payload, revocable: req.IsRevocable, created: now, updated: now,
	}
	if s.revocable {
		s.index = c.next
		c.next++
	}
	c.sessions[s.id] = s
	c.codes[s.code] = s.id
	offerURI := c.srv.URL + "/oid4vci/" + c.issuer + "/offers/" + s.id
	envelope(rw, http.StatusCreated, "Credential offer created", map[string]any{
		"credentialOffer": "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(offerURI),
		"issuanceSession": map[string]any{"id": s.id, "state": s.state, "userPin": s.pin},
	})
}

// sessionJSON is the session record the api gateway hands through.
func (c *credeblStack) sessionJSON(s *credeblSession) map[string]any {
	// The agent keeps the claims of the credential with its vct and, for
	// a revocable offer, its status list entry.
	payload := map[string]any{"vct": s.vct}
	for k, v := range s.payload {
		payload[k] = v
	}
	if s.revocable {
		payload["status"] = map[string]any{"status_list": map[string]any{"uri": c.listURL(), "idx": s.index}}
	}
	credential := map[string]any{"credentialSupportedId": s.template, "format": s.format, "payload": payload}
	meta := map[string]any{"issuerDid": c.did, "isRevocable": s.revocable, "credentials": []any{credential}}
	if s.revocable {
		meta["StatusListInfo"] = []any{map[string]any{
			"credentialSupportedId": s.template, "listId": statusListID, "index": s.index, "issuerDid": c.did,
		}}
	}
	return map[string]any{
		"id": s.id, "state": s.state, "issuerId": c.issuer,
		"createdAt": s.created.Format(time.RFC3339Nano), "updatedAt": s.updated.Format(time.RFC3339Nano),
		"credentialOfferPayload": map[string]any{"credential_configuration_ids": []string{s.template}},
		"issuanceMetadata":       meta,
	}
}

// offer serves the credential offer of one session.
func (c *credeblStack) offer(rw http.ResponseWriter, r *http.Request, id string) {
	c.mu.Lock()
	s, ok := c.sessions[id]
	c.mu.Unlock()
	if !ok {
		http.NotFound(rw, r)
		return
	}
	writeJSON(rw, map[string]any{
		"credential_issuer":            c.srv.URL + "/oid4vci/" + c.issuer,
		"credential_configuration_ids": []string{s.template},
		"grants": map[string]any{"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
			"pre-authorized_code": s.code, "tx_code": map[string]any{"length": len(s.pin), "input_mode": "numeric"},
		}},
	})
}

// metadata serves the issuer metadata with one entry per template.
func (c *credeblStack) metadata(rw http.ResponseWriter) {
	c.mu.Lock()
	configs := map[string]any{}
	for _, t := range c.templates {
		var shape struct {
			Vct string `json:"vct"`
		}
		if err := json.Unmarshal(t.Body, &shape); err != nil {
			c.mu.Unlock()
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		configs[t.Name] = map[string]any{"format": t.Format, "vct": shape.Vct}
	}
	c.mu.Unlock()
	base := c.srv.URL + "/oid4vci/" + c.issuer
	writeJSON(rw, map[string]any{
		"credential_issuer": base, "credential_endpoint": base + "/credential", "token_endpoint": base + "/token",
		"credential_configurations_supported": configs,
	})
}

// token trades the pre-authorized code and the transaction code.
func (c *credeblStack) token(rw http.ResponseWriter, body []byte) {
	form, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.codes[form.Get("pre-authorized_code")]
	if !ok || c.sessions[id].pin != form.Get("tx_code") {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusBadRequest)
		writeJSON(rw, map[string]any{"error": "invalid_grant"})
		return
	}
	delete(c.codes, form.Get("pre-authorized_code"))
	access := randomID()
	c.tokens[access] = id
	c.sessions[id].state = "AccessTokenCreated"
	writeJSON(rw, map[string]any{"access_token": access, "token_type": "bearer", "expires_in": 300, "c_nonce": randomID()})
}

// credential signs the SD-JWT VC of the session with the key of the DID
// of the organisation.
func (c *credeblStack) credential(rw http.ResponseWriter, r *http.Request) {
	access := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.tokens[access]
	if !ok {
		http.Error(rw, "invalid_token", http.StatusUnauthorized)
		return
	}
	delete(c.tokens, access)
	s := c.sessions[id]
	claims := map[string]any{}
	names := make([]string, 0, len(s.payload))
	for k, v := range s.payload {
		claims[k] = v
		names = append(names, k)
	}
	sort.Strings(names)
	payload, discs, err := sdjwt.Conceal(claims, names)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	payload["iss"] = c.did
	payload["iat"] = time.Now().Unix()
	payload["vct"] = s.vct
	if s.revocable {
		payload["status"] = map[string]any{"status_list": map[string]any{"uri": c.listURL(), "idx": s.index}}
	}
	jwt, err := jose.Sign(c.key, c.did+"#"+strings.TrimPrefix(c.did, "did:key:"), "dc+sd-jwt", payload)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	s.state, s.updated = "Completed", time.Now().UTC()
	writeJSON(rw, map[string]any{"credential": sdjwt.Serialize(sdjwt.Presentation{IssuerJWT: jwt, Disclosures: discs})})
}

// listURL is the address of the list on the status list host.
func (c *credeblStack) listURL() string { return c.srv.URL + "/status-lists/" + statusListID }

// revoke sets the bit of each credential of a completed session.
func (c *credeblStack) revoke(rw http.ResponseWriter, id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.sessions[id]
	if !ok || !s.revocable {
		envelope(rw, http.StatusBadRequest, "The session has no status list entry", nil)
		return
	}
	if err := c.list.Set(s.index, 1); err != nil {
		envelope(rw, http.StatusInternalServerError, err.Error(), nil)
		return
	}
	envelope(rw, http.StatusCreated, "Credentials revoked successfully", map[string]any{"revoked": 1})
}

// statusList serves the Token Status List that the key of the DID of
// the organisation signs.
func (c *credeblStack) statusList(rw http.ResponseWriter) {
	c.mu.Lock()
	claims := token.JWTClaims(token.Claims{Issuer: c.did, Subject: c.listURL(), IssuedAt: time.Now(), TTL: time.Minute}, c.list)
	c.mu.Unlock()
	jwt, err := jose.Sign(c.key, c.did+"#"+strings.TrimPrefix(c.did, "did:key:"), token.TypeJWT, claims)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "application/statuslist+jwt")
	if _, err := io.WriteString(rw, jwt); err != nil {
		c.t.Log(err)
	}
}

// randomUUID returns a random version 4 UUID.
func randomUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, v := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hex[v>>4], hex[v&0x0f])
	}
	return string(out)
}
