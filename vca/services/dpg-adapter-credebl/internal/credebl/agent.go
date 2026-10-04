// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The holder calls of the shared Credo agent of the stack (P6-C7,
// ADR-062). The adapter keeps one tenant wallet per holder in the agent
// and calls the agent directly, not the cloud wallet service of the
// platform. The sources are the controllers of the agent at the release
// that the stack file pins, read on 2026-09-27:
// https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/authentication.ts
// https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/agent/AgentController.ts
// https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/multi-tenancy/MultiTenancyController.ts
// https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/did/DidController.ts
// https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/didcomm/outofband/OutOfBandController.ts
// https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/didcomm/credentials/CredentialController.ts
// https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/didcomm/proofs/ProofController.ts
// https://raw.githubusercontent.com/credebl/agent-controller/v2.2.1-alpha-jsonld-vc.2.1/src/controllers/openid4vc/holder/holder.service.ts
// The records follow Credo 0.6.2, the release the agent builds on.

// ErrNoAgent reports that the adapter has no agent address or API key.
var ErrNoAgent = errors.New("credebl: no agent address and API key")

// Agent calls the shared agent of the stack. A nil Agent answers every
// call with ErrNoAgent.
type Agent struct {
	client *dpgclient.Client
	apiKey string

	mu sync.Mutex
	// base is the token of the base wallet, which manages the tenants.
	base string
	// tenants holds the token of each tenant.
	tenants map[string]string
}

// AgentOptions configure NewAgent.
type AgentOptions struct {
	// HTTP calls the admin port of the agent.
	HTTP *dpgclient.Client
	// APIKey is the key the agent takes for the token of the base
	// wallet.
	APIKey string
}

// NewAgent returns the agent client, or nil without an address or a
// key.
func NewAgent(opts AgentOptions) *Agent {
	if opts.HTTP == nil || opts.HTTP.BaseURL() == "" || opts.APIKey == "" {
		return nil
	}
	return &Agent{client: opts.HTTP, apiKey: opts.APIKey, tenants: map[string]string{}}
}

// tokenAnswer is the answer of a token call.
type tokenAnswer struct {
	Token string `json:"token"`
}

// baseToken returns the token of the base wallet. The agent compares
// the whole Authorization header with its API key.
func (a *Agent) baseToken(ctx context.Context) (string, error) {
	a.mu.Lock()
	token := a.base
	a.mu.Unlock()
	if token != "" {
		return token, nil
	}
	resp, err := a.client.Do(ctx, dpgclient.Request{
		Method: http.MethodPost, Path: "/agent/token", Accept: "application/json",
		Header: http.Header{"Authorization": {a.apiKey}},
	})
	if err != nil {
		return "", err
	}
	var got tokenAnswer
	if err := json.Unmarshal(resp.Body, &got); err != nil || got.Token == "" {
		return "", errors.New("credebl: the agent gave no base wallet token")
	}
	a.mu.Lock()
	a.base = got.Token
	a.mu.Unlock()
	return got.Token, nil
}

// asBase runs one call with the token of the base wallet. A refused
// token is fetched again once.
func (a *Agent) asBase(ctx context.Context, call func(*dpgclient.Client) error) error {
	if a == nil {
		return ErrNoAgent
	}
	for attempt := 0; ; attempt++ {
		token, err := a.baseToken(ctx)
		if err != nil {
			return err
		}
		err = call(a.client.WithToken(token))
		if attempt == 0 && dpgclient.IsStatus(err, http.StatusUnauthorized) {
			a.mu.Lock()
			a.base = ""
			a.mu.Unlock()
			continue
		}
		return err
	}
}

// tenantToken returns the token of a tenant.
func (a *Agent) tenantToken(ctx context.Context, tenant string) (string, error) {
	a.mu.Lock()
	token := a.tenants[tenant]
	a.mu.Unlock()
	if token != "" {
		return token, nil
	}
	var got tokenAnswer
	if err := a.asBase(ctx, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodPost, "/multi-tenancy/get-token/"+url.PathEscape(tenant), nil, &got)
	}); err != nil {
		return "", err
	}
	if got.Token == "" {
		return "", errors.New("credebl: the agent gave no tenant token")
	}
	a.mu.Lock()
	a.tenants[tenant] = got.Token
	a.mu.Unlock()
	return got.Token, nil
}

// asTenant runs one call with the token of a tenant. A refused token
// is fetched again once.
func (a *Agent) asTenant(ctx context.Context, tenant string, call func(*dpgclient.Client) error) error {
	if a == nil {
		return ErrNoAgent
	}
	for attempt := 0; ; attempt++ {
		token, err := a.tenantToken(ctx, tenant)
		if err != nil {
			return err
		}
		err = call(a.client.WithToken(token))
		if attempt == 0 && dpgclient.IsStatus(err, http.StatusUnauthorized) {
			a.mu.Lock()
			delete(a.tenants, tenant)
			a.base = ""
			a.mu.Unlock()
			continue
		}
		return err
	}
}

// CreateTenant makes a tenant wallet with the label that the other
// party of a connection sees, and returns its id.
func (a *Agent) CreateTenant(ctx context.Context, label string) (string, error) {
	var got struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	body := map[string]any{"config": map[string]any{"label": label}}
	if err := a.asBase(ctx, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodPost, "/multi-tenancy/create-tenant", body, &got)
	}); err != nil {
		return "", err
	}
	if got.ID == "" {
		return "", errors.New("credebl: the agent made a tenant with no id")
	}
	if got.Token != "" {
		a.mu.Lock()
		a.tenants[got.ID] = got.Token
		a.mu.Unlock()
	}
	return got.ID, nil
}

// CreateDidKey makes a did:key with an Ed25519 key in a tenant. The
// agent makes the key.
func (a *Agent) CreateDidKey(ctx context.Context, tenant string) (string, error) {
	var got struct {
		Did string `json:"did"`
	}
	body := map[string]any{"method": "key", "keyType": "ed25519"}
	if err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodPost, "/dids/write", body, &got)
	}); err != nil {
		return "", err
	}
	if got.Did == "" {
		return "", errors.New("credebl: the agent made no DID")
	}
	return got.Did, nil
}

// AgentDid is one DID record that a tenant made.
type AgentDid struct {
	// Did is the DID.
	Did string `json:"did"`
	// CreatedAt is when the tenant made it.
	CreatedAt time.Time `json:"createdAt"`
	// Keys name the key of the DID in the key store of the agent.
	Keys []struct {
		// KmsKeyID is the id of the key.
		KmsKeyID string `json:"kmsKeyId"`
	} `json:"keys"`
}

// Dids lists the DIDs a tenant made, a did:peer of each connection
// included.
func (a *Agent) Dids(ctx context.Context, tenant string) ([]AgentDid, error) {
	var got []AgentDid
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodGet, "/dids", nil, &got)
	})
	return got, err
}

// ResolveDid resolves a DID with the DID resolver of the agent, as a
// tenant, and returns the DID document as JSON. The agent also records
// the DID in that tenant.
func (a *Agent) ResolveDid(ctx context.Context, tenant, did string) (json.RawMessage, error) {
	var got struct {
		DidDocument json.RawMessage `json:"didDocument"`
	}
	if err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodGet, "/dids/"+url.PathEscape(did), nil, &got)
	}); err != nil {
		return nil, err
	}
	if len(got.DidDocument) == 0 || string(got.DidDocument) == "null" {
		return nil, errors.New("credebl: the agent resolved no DID document")
	}
	return got.DidDocument, nil
}

// AgentConnection is one DIDComm connection record.
type AgentConnection struct {
	// ID is the record id.
	ID string `json:"id"`
	// State is the DID exchange state, such as completed.
	State string `json:"state"`
	// TheirLabel is the label of the other party.
	TheirLabel string `json:"theirLabel"`
	// CreatedAt is when the connection began.
	CreatedAt time.Time `json:"createdAt"`
}

// Received is the answer of an invitation the agent took.
type Received struct {
	// OutOfBand is the out of band record.
	OutOfBand struct {
		// ID is the record id.
		ID string `json:"id"`
		// Invitation is the invitation as the agent read it.
		Invitation json.RawMessage `json:"outOfBandInvitation"`
	} `json:"outOfBandRecord"`
	// Connection is the connection the invitation started, when it asks
	// for one.
	Connection *AgentConnection `json:"connectionRecord"`
}

// Attached is one message that an out of band invitation carries.
type Attached struct {
	// Type is the message type URI.
	Type string
	// ThreadID is the thread of the exchange the message starts.
	ThreadID string
}

// IsOffer reports a credential offer (Aries RFC 0453).
func (m Attached) IsOffer() bool {
	return strings.Contains(m.Type, "/issue-credential/") && strings.HasSuffix(m.Type, "/offer-credential")
}

// IsProofRequest reports a proof request (Aries RFC 0454).
func (m Attached) IsProofRequest() bool {
	return strings.Contains(m.Type, "/present-proof/") && strings.HasSuffix(m.Type, "/request-presentation")
}

// invitation is the part of an out of band invitation the adapter reads.
type invitation struct {
	Label    string `json:"label"`
	Requests []struct {
		Data struct {
			Base64 string          `json:"base64"`
			JSON   json.RawMessage `json:"json"`
		} `json:"data"`
	} `json:"requests~attach"`
}

// Label returns the label of the invitation, or of the connection.
func (r Received) Label() string {
	var inv invitation
	if json.Unmarshal(r.OutOfBand.Invitation, &inv) == nil && inv.Label != "" {
		return inv.Label
	}
	if r.Connection != nil {
		return r.Connection.TheirLabel
	}
	return ""
}

// Attached returns the messages the invitation carries. The thread of
// a message is its ~thread.thid, or its own id.
func (r Received) Attached() []Attached {
	var inv invitation
	if json.Unmarshal(r.OutOfBand.Invitation, &inv) != nil {
		return nil
	}
	var out []Attached
	for _, att := range inv.Requests {
		raw := []byte(att.Data.JSON)
		if len(raw) == 0 {
			decoded, err := base64.StdEncoding.DecodeString(att.Data.Base64)
			if err != nil {
				continue
			}
			raw = decoded
		}
		var msg struct {
			Type   string `json:"@type"`
			ID     string `json:"@id"`
			Thread struct {
				ThreadID string `json:"thid"`
			} `json:"~thread"`
		}
		if json.Unmarshal(raw, &msg) != nil || msg.Type == "" {
			continue
		}
		thread := msg.Thread.ThreadID
		if thread == "" {
			thread = msg.ID
		}
		out = append(out, Attached{Type: msg.Type, ThreadID: thread})
	}
	return out
}

// ReceiveInvitation hands an invitation URL to a tenant. The tenant
// accepts it, makes or reuses the connection, and takes the message it
// carries. label is the label the other party sees.
func (a *Agent) ReceiveInvitation(ctx context.Context, tenant, invitationURL, label string) (Received, error) {
	var got Received
	body := map[string]any{
		"invitationUrl": invitationURL, "label": label,
		"autoAcceptInvitation": true, "autoAcceptConnection": true, "reuseConnection": true,
	}
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodPost, "/didcomm/oob/receive-invitation-url", body, &got)
	})
	return got, err
}

// Connections lists the connections of a tenant.
func (a *Agent) Connections(ctx context.Context, tenant string) ([]AgentConnection, error) {
	var got []AgentConnection
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodGet, "/didcomm/connections", nil, &got)
	})
	return got, err
}

// Connection reads one connection of a tenant.
func (a *Agent) Connection(ctx context.Context, tenant, id string) (AgentConnection, error) {
	var got AgentConnection
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodGet, "/didcomm/connections/"+url.PathEscape(id), nil, &got)
	})
	return got, err
}

// PreviewAttribute is one value of a credential preview.
type PreviewAttribute struct {
	// Name is the attribute name.
	Name string `json:"name"`
	// Value is the value as text.
	Value string `json:"value"`
}

// AnonCredsMetadata names the schema and the credential definition of
// an AnonCreds credential.
type AnonCredsMetadata struct {
	// SchemaID is the id of the schema.
	SchemaID string `json:"schemaId"`
	// CredDefID is the id of the credential definition.
	CredDefID string `json:"credentialDefinitionId"`
}

// AgentCredential is one credential exchange record of a holder.
type AgentCredential struct {
	// ID is the record id.
	ID string `json:"id"`
	// State is the exchange state, such as offer-received or done.
	State string `json:"state"`
	// ConnectionID names the connection of the exchange.
	ConnectionID string `json:"connectionId"`
	// ThreadID is the thread of the exchange.
	ThreadID string `json:"threadId"`
	// ErrorMessage says why an exchange stopped.
	ErrorMessage string `json:"errorMessage"`
	// CreatedAt is when the exchange began.
	CreatedAt time.Time `json:"createdAt"`
	// UpdatedAt is when the state last changed.
	UpdatedAt time.Time `json:"updatedAt"`
	// Credentials name the stored credentials of a finished exchange.
	Credentials []struct {
		// Type is anoncreds or w3c.
		Type string `json:"credentialRecordType"`
		// ID is the id of the stored credential.
		ID string `json:"credentialRecordId"`
	} `json:"credentials"`
	// Attributes are the values of the credential preview.
	Attributes []PreviewAttribute `json:"credentialAttributes"`
	// Metadata holds the AnonCreds metadata of the exchange.
	Metadata struct {
		// AnonCreds names the schema and the credential definition.
		AnonCreds *AnonCredsMetadata `json:"_anoncreds/credential"`
	} `json:"metadata"`
}

// AnonCreds returns the AnonCreds metadata, or nil.
func (c AgentCredential) AnonCreds() *AnonCredsMetadata { return c.Metadata.AnonCreds }

// RecordOf returns the id of the stored credential of a type, or "".
func (c AgentCredential) RecordOf(kind string) string {
	for _, cred := range c.Credentials {
		if cred.Type == kind {
			return cred.ID
		}
	}
	return ""
}

// CredentialQuery selects the credential exchanges of a holder.
type CredentialQuery struct {
	// ThreadID selects one thread.
	ThreadID string
	// State selects one state.
	State string
}

// Credentials lists the credential exchanges of a tenant as holder.
func (a *Agent) Credentials(ctx context.Context, tenant string, q CredentialQuery) ([]AgentCredential, error) {
	query := url.Values{"role": {"holder"}}
	if q.ThreadID != "" {
		query.Set("threadId", q.ThreadID)
	}
	if q.State != "" {
		query.Set("state", q.State)
	}
	var got []AgentCredential
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodGet, "/didcomm/credentials?"+query.Encode(), nil, &got)
	})
	return got, err
}

// Credential reads one credential exchange of a tenant.
func (a *Agent) Credential(ctx context.Context, tenant, id string) (AgentCredential, error) {
	var got AgentCredential
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodGet, "/didcomm/credentials/"+url.PathEscape(id), nil, &got)
	})
	return got, err
}

// AcceptOffer accepts an offer the tenant received. The agent asks the
// issuer for the credential and stores it when it comes.
func (a *Agent) AcceptOffer(ctx context.Context, tenant, id string) (AgentCredential, error) {
	var got AgentCredential
	body := map[string]any{"credentialExchangeRecordId": id}
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodPost, "/didcomm/credentials/accept-offer", body, &got)
	})
	return got, err
}

// CredentialFormData is what an offer carries, in the form the agent
// reads it.
type CredentialFormData struct {
	// Offer is the offer per format.
	Offer struct {
		// AnonCreds is an AnonCreds offer.
		AnonCreds *struct {
			// SchemaID is the id of the schema.
			SchemaID string `json:"schema_id"`
			// CredDefID is the id of the credential definition.
			CredDefID string `json:"cred_def_id"`
		} `json:"anoncreds"`
		// JSONLD is a W3C JSON-LD offer.
		JSONLD *struct {
			// Credential is the unsigned credential.
			Credential map[string]any `json:"credential"`
		} `json:"jsonld"`
	} `json:"offer"`
	// OfferAttributes are the values of an AnonCreds offer.
	OfferAttributes []PreviewAttribute `json:"offerAttributes"`
}

// CredentialFormData reads what an exchange of a tenant carries.
func (a *Agent) CredentialFormData(ctx context.Context, tenant, id string) (CredentialFormData, error) {
	var got CredentialFormData
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodGet, "/didcomm/credentials/"+url.PathEscape(id)+"/form-data", nil, &got)
	})
	return got, err
}

// AgentW3c is one stored W3C credential of a tenant.
type AgentW3c struct {
	// ID is the record id.
	ID string `json:"id"`
	// CreatedAt is when the tenant stored it.
	CreatedAt time.Time `json:"createdAt"`
	// Instances hold the credential, a JSON-LD object or a JWT string.
	Instances []struct {
		// Credential is one instance of the credential.
		Credential json.RawMessage `json:"credential"`
	} `json:"credentialInstances"`
	// Legacy is the credential of a record from before Credo 0.6.
	Legacy json.RawMessage `json:"credential"`
}

// Credential returns the first instance of the credential.
func (w AgentW3c) Credential() json.RawMessage {
	if len(w.Instances) > 0 {
		return w.Instances[0].Credential
	}
	return w.Legacy
}

// W3cCredentials lists the stored W3C credentials of a tenant.
func (a *Agent) W3cCredentials(ctx context.Context, tenant string) ([]AgentW3c, error) {
	var got []AgentW3c
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodGet, "/didcomm/credentials/w3c", nil, &got)
	})
	return got, err
}

// DeleteW3c removes one stored W3C credential of a tenant through the
// holder API of the agent.
func (a *Agent) DeleteW3c(ctx context.Context, tenant, id string) error {
	return a.DeleteHeld(ctx, tenant, HeldW3c, id)
}

// AgentProof is one proof exchange record of a prover.
type AgentProof struct {
	// ID is the record id.
	ID string `json:"id"`
	// State is the exchange state, such as request-received or done.
	State string `json:"state"`
	// Role is prover for a proof the tenant gives.
	Role string `json:"role"`
	// ConnectionID names the connection of the exchange.
	ConnectionID string `json:"connectionId"`
	// ThreadID is the thread of the exchange.
	ThreadID string `json:"threadId"`
	// ErrorMessage says why an exchange stopped.
	ErrorMessage string `json:"errorMessage"`
	// CreatedAt is when the exchange began.
	CreatedAt time.Time `json:"createdAt"`
	// UpdatedAt is when the state last changed.
	UpdatedAt time.Time `json:"updatedAt"`
}

// Proofs lists the proof exchanges of a tenant, of one thread when
// threadID is set.
func (a *Agent) Proofs(ctx context.Context, tenant, threadID string) ([]AgentProof, error) {
	path := "/didcomm/proofs"
	if threadID != "" {
		path += "?" + url.Values{"threadId": {threadID}}.Encode()
	}
	var got []AgentProof
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodGet, path, nil, &got)
	})
	return got, err
}

// Proof reads one proof exchange of a tenant.
func (a *Agent) Proof(ctx context.Context, tenant, id string) (AgentProof, error) {
	var got AgentProof
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodGet, "/didcomm/proofs/"+url.PathEscape(id), nil, &got)
	})
	return got, err
}

// AcceptProofRequest answers a proof request. The agent picks the
// credentials that answer it.
func (a *Agent) AcceptProofRequest(ctx context.Context, tenant, id string) (AgentProof, error) {
	var got AgentProof
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodPost, "/didcomm/proofs/"+url.PathEscape(id)+"/accept-request", map[string]any{}, &got)
	})
	return got, err
}

// IndyProofRequest is an AnonCreds proof request, or its legacy Indy
// form.
type IndyProofRequest struct {
	// Name is the name of the request.
	Name string `json:"name"`
	// Attributes are the attribute groups by referent.
	Attributes map[string]struct {
		// Name is one attribute name.
		Name string `json:"name"`
		// Names are the names of a group.
		Names []string `json:"names"`
	} `json:"requested_attributes"`
	// Predicates are the predicates by referent.
	Predicates map[string]struct {
		// Name is the attribute name.
		Name string `json:"name"`
		// Type is the operator.
		Type string `json:"p_type"`
		// Value is the number to compare with.
		Value int64 `json:"p_value"`
	} `json:"requested_predicates"`
}

// ProofFormData is what a proof request asks for, in the form the agent
// reads it.
type ProofFormData struct {
	// Request is the request per format.
	Request struct {
		// AnonCreds is an AnonCreds request.
		AnonCreds *IndyProofRequest `json:"anoncreds"`
		// Indy is a legacy Indy request.
		Indy *IndyProofRequest `json:"indy"`
		// PresentationExchange is a DIF PE request.
		PresentationExchange *struct {
			// Definition is the presentation definition.
			Definition struct {
				// Name is the name of the definition.
				Name string `json:"name"`
				// Descriptors are the input descriptors.
				Descriptors []struct {
					// Name is the name of the descriptor.
					Name string `json:"name"`
					// Constraints hold the fields.
					Constraints struct {
						// Fields name the claims by JSON path.
						Fields []struct {
							// Path lists the JSON paths of the claim.
							Path []string `json:"path"`
						} `json:"fields"`
					} `json:"constraints"`
				} `json:"input_descriptors"`
			} `json:"presentation_definition"`
		} `json:"presentationExchange"`
	} `json:"request"`
}

// Asked returns the name of the request and what it asks for as plain
// text: each attribute name, and each predicate as name, operator and
// number. The order follows the referents.
func (f ProofFormData) Asked() (string, []string) {
	req := f.Request.AnonCreds
	if req == nil {
		req = f.Request.Indy
	}
	if req != nil {
		return req.Name, req.asked()
	}
	pe := f.Request.PresentationExchange
	if pe == nil {
		return "", nil
	}
	var out []string
	for _, d := range pe.Definition.Descriptors {
		if len(d.Constraints.Fields) == 0 {
			out = append(out, d.Name)
			continue
		}
		for _, field := range d.Constraints.Fields {
			if len(field.Path) > 0 {
				out = append(out, lastSegment(field.Path[0]))
			}
		}
	}
	return pe.Definition.Name, out
}

// asked lists the attributes, then the predicates, in referent order.
func (r IndyProofRequest) asked() []string {
	var out []string
	for _, ref := range sortedKeys(r.Attributes) {
		a := r.Attributes[ref]
		if a.Name != "" {
			out = append(out, a.Name)
		}
		out = append(out, a.Names...)
	}
	for _, ref := range sortedKeys(r.Predicates) {
		p := r.Predicates[ref]
		out = append(out, p.Name+" "+p.Type+" "+strconv.FormatInt(p.Value, 10))
	}
	return out
}

// sortedKeys returns the keys of a map in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lastSegment returns the claim name of a JSON path such as
// $.credentialSubject.name.
func lastSegment(path string) string {
	path = strings.TrimSuffix(strings.TrimSuffix(path, "']"), "\"]")
	if i := strings.LastIndexAny(path, ".['\""); i >= 0 {
		return path[i+1:]
	}
	return path
}

// ProofFormData reads what a proof exchange of a tenant asks for.
func (a *Agent) ProofFormData(ctx context.Context, tenant, id string) (ProofFormData, error) {
	var got ProofFormData
	err := a.asTenant(ctx, tenant, func(c *dpgclient.Client) error {
		return c.JSON(ctx, http.MethodGet, "/didcomm/proofs/"+url.PathEscape(id)+"/form-data", nil, &got)
	})
	return got, err
}
