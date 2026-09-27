// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The DIDComm proof calls of the api gateway (P6-C6): a proof request as
// an out of band invitation or over a connection, the proof exchange,
// the verify call, the revealed values, and the list of the requests.
// The platform asks for an AnonCreds proof in the Indy format, or for a
// DIF Presentation Exchange proof. The sources are the verification
// controller and service of the platform and the proof controller of
// its agent, read on 2026-09-27:
// https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/verification/verification.controller.ts
// https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/verification/dto/request-proof.dto.ts
// https://raw.githubusercontent.com/credebl/platform/main/apps/verification/src/verification.service.ts
// https://raw.githubusercontent.com/credebl/agent-controller/main/src/controllers/didcomm/proofs/ProofController.ts

// The proof request types of the query parameter requestType
// (ProofRequestType of verification.enum.ts).
const (
	// ProofTypeIndy asks for an AnonCreds proof in the Indy format.
	ProofTypeIndy = "indy"
	// ProofTypePE asks for a DIF Presentation Exchange proof.
	ProofTypePE = "presentationExchange"
)

// The states of a proof exchange of the agent that the adapter acts on.
const (
	// ProofStateDone ends an exchange that the agent verified.
	ProofStateDone = "done"
	// ProofStatePresentationReceived is a presentation that waits for
	// the verify call.
	ProofStatePresentationReceived = "presentation-received"
	// ProofStateAbandoned ends an exchange that failed.
	ProofStateAbandoned = "abandoned"
	// ProofStateDeclined ends an exchange the holder declined.
	ProofStateDeclined = "declined"
)

// autoAccept lets the agent verify a presentation as it arrives
// (AutoAccept of libs/enum/src/enum.ts).
const autoAccept = "always"

// ProofAttribute is one line of the attribute list of a proof request
// over a connection (ProofRequestAttribute of request-proof.dto.ts). A
// line with a condition and a value is a predicate.
type ProofAttribute struct {
	// Name is one attribute to reveal or to compare. The adapter sends
	// one name per line, because the platform reads the revealed values
	// by the name of each referent.
	Name string `json:"attributeName,omitempty"`
	// Condition is the operator of a predicate, such as >=.
	Condition string `json:"condition,omitempty"`
	// Value is the number a predicate compares with.
	Value string `json:"value,omitempty"`
	// CredDefID restricts the credential definition.
	CredDefID string `json:"credDefId,omitempty"`
	// SchemaID restricts the schema.
	SchemaID string `json:"schemaId,omitempty"`
}

// ProofRequest is one DIDComm proof request.
type ProofRequest struct {
	// Type is ProofTypeIndy or ProofTypePE.
	Type string
	// Indy is the AnonCreds proof request of an out of band request, in
	// the form of the specification.
	Indy json.RawMessage
	// Attributes is the AnonCreds request of a request over a
	// connection, in the attribute list of the platform.
	Attributes []ProofAttribute
	// Definition is the DIF Presentation Exchange definition.
	Definition json.RawMessage
	// Comment is the text the wallet shows with the request.
	Comment string
}

// check reports a request that the platform would refuse.
func (r ProofRequest) check() error {
	switch r.Type {
	case ProofTypeIndy, ProofTypePE:
		return nil
	}
	return fmt.Errorf("credebl: no proof request type %q", r.Type)
}

// proofPath returns the path of one proof call with the request type.
func (c *Client) proofPath(tail, requestType string) string {
	return "/v1/orgs/" + url.PathEscape(c.orgID) + tail + "?" + url.Values{"requestType": {requestType}}.Encode()
}

// OOBProof is the out of band invitation that carries a proof request.
type OOBProof struct {
	// InvitationURL is the address of the invitation, with the
	// invitation in the query parameter oob.
	InvitationURL string `json:"invitationUrl"`
	// RecordID is the id of the proof exchange in the agent.
	RecordID string `json:"proofRecordId"`
	// ThreadID is the thread of the proof exchange.
	ThreadID string `json:"proofRecordThId"`
}

// CreateOOBProof makes an out of band invitation that carries one proof
// request. The agent verifies the presentation as it arrives. The
// platform reuses the connection of a wallet that took an invitation of
// the organisation before.
func (c *Client) CreateOOBProof(ctx context.Context, req ProofRequest) (OOBProof, error) {
	if c == nil {
		return OOBProof{}, ErrNoPlatform
	}
	if err := req.check(); err != nil {
		return OOBProof{}, err
	}
	body := map[string]any{
		"protocolVersion": "v2", "comment": req.Comment, "autoAcceptProof": autoAccept,
		"isShortenUrl": false, "reuseConnection": true,
	}
	if req.Type == ProofTypeIndy {
		body["proofFormats"] = map[string]json.RawMessage{"indy": req.Indy}
	} else {
		body["presentationDefinition"] = req.Definition
	}
	var out envelope[OOBProof]
	if err := c.call(ctx, http.MethodPost, c.proofPath("/proofs/oob", req.Type), body, &out); err != nil {
		return OOBProof{}, err
	}
	if out.Data.InvitationURL == "" || out.Data.RecordID == "" {
		return OOBProof{}, errors.New("credebl: the out of band answer has no invitation")
	}
	return out.Data, nil
}

// ProofRecord is the proof exchange record of the agent.
type ProofRecord struct {
	// ID is the id of the record.
	ID string `json:"id"`
	// State is the state of the exchange, such as request-sent or done.
	State string `json:"state"`
	// ThreadID is the thread of the exchange.
	ThreadID string `json:"threadId"`
	// ConnectionID is the connection of the exchange, when it has one.
	ConnectionID string `json:"connectionId"`
	// IsVerified is the verdict of the agent on the proof, once it
	// verified it.
	IsVerified *bool `json:"isVerified"`
	// ErrorMessage is the reason of a failed exchange.
	ErrorMessage string `json:"errorMessage"`
	// CreatedAt is when the exchange began.
	CreatedAt time.Time `json:"createdAt"`
	// UpdatedAt is the last change of the exchange.
	UpdatedAt time.Time `json:"updatedAt"`
}

// SendConnectionProof sends one proof request over a DIDComm connection
// of the organisation and returns the record the agent made.
func (c *Client) SendConnectionProof(ctx context.Context, connectionID string, req ProofRequest) (ProofRecord, error) {
	if c == nil {
		return ProofRecord{}, ErrNoPlatform
	}
	if strings.TrimSpace(connectionID) == "" {
		return ProofRecord{}, errors.New("credebl: a request over a connection needs the connection")
	}
	if err := req.check(); err != nil {
		return ProofRecord{}, err
	}
	body := map[string]any{
		"connectionId": connectionID, "comment": req.Comment, "autoAcceptProof": autoAccept, "protocolVersion": "v2",
	}
	if req.Type == ProofTypeIndy {
		body["proofFormats"] = map[string]any{"indy": map[string]any{"attributes": req.Attributes}}
	} else {
		body["presentationDefinition"] = req.Definition
	}
	var out envelope[ProofRecord]
	if err := c.call(ctx, http.MethodPost, c.proofPath("/proofs", req.Type), body, &out); err != nil {
		return ProofRecord{}, err
	}
	if out.Data.ID == "" {
		return ProofRecord{}, errors.New("credebl: the proof request answer has no record")
	}
	return out.Data, nil
}

// ProofRecord reads the proof exchange record of one request.
func (c *Client) ProofRecord(ctx context.Context, id string) (ProofRecord, error) {
	if c == nil {
		return ProofRecord{}, ErrNoPlatform
	}
	var out envelope[ProofRecord]
	if err := c.call(ctx, http.MethodGet, "/v1/orgs/"+url.PathEscape(c.orgID)+"/proofs/"+url.PathEscape(id), nil, &out); err != nil {
		return ProofRecord{}, err
	}
	return out.Data, nil
}

// VerifyProof has the agent verify a presentation that waits, and
// returns the record after the check.
func (c *Client) VerifyProof(ctx context.Context, id string) (ProofRecord, error) {
	if c == nil {
		return ProofRecord{}, ErrNoPlatform
	}
	var out envelope[ProofRecord]
	path := "/v1/orgs/" + url.PathEscape(c.orgID) + "/proofs/" + url.PathEscape(id) + "/verify"
	if err := c.call(ctx, http.MethodPost, path, nil, &out); err != nil {
		return ProofRecord{}, err
	}
	return out.Data, nil
}

// Revealed is one value of a verified proof: the attribute and its
// value, and the schema and the credential definition it came from. A
// predicate carries the operator and the number, such as >=10, and not
// the value of the holder.
type Revealed struct {
	// Name is the attribute.
	Name string
	// Value is the revealed value, or the predicate.
	Value string
	// SchemaID is the schema of the credential.
	SchemaID string
	// CredDefID is the credential definition of an AnonCreds proof.
	CredDefID string
}

// revealedKeys are the members of an entry of the verified proof that
// name the source of the value.
var revealedKeys = map[string]bool{"schemaId": true, "credDefId": true, "certificateTemplate": true}

// DroppedName reports an attribute name that the platform writes over
// with the source of the value, so its value never comes back.
func DroppedName(name string) bool { return revealedKeys[name] }

// VerifiedProof reads the revealed values of a verified proof, in the
// order of the answer. It reads the member of each entry by the names
// of the request. With no names it reads an entry only when one member
// besides the source keys holds the value.
func (c *Client) VerifiedProof(ctx context.Context, id string, names []string) ([]Revealed, error) {
	if c == nil {
		return nil, ErrNoPlatform
	}
	var out envelope[[]map[string]any]
	if err := c.call(ctx, http.MethodGet, "/v1/orgs/"+url.PathEscape(c.orgID)+"/verified-proofs/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	var list []Revealed
	for _, entry := range out.Data {
		item := Revealed{SchemaID: text(entry["schemaId"]), CredDefID: text(entry["credDefId"])}
		item.Name = memberOf(entry, names)
		if item.Name != "" {
			item.Value = text(entry[item.Name])
			list = append(list, item)
		}
	}
	return list, nil
}

// memberOf returns the member of an entry that holds the value: the
// first requested name the entry has, or with no names the one member
// besides the source keys. An entry with more such members and no
// names gives none, so no value lands under another name.
func memberOf(entry map[string]any, names []string) string {
	if len(names) > 0 {
		for _, n := range names {
			if _, ok := entry[n]; ok && !revealedKeys[n] {
				return n
			}
		}
		return ""
	}
	found := ""
	for k := range entry {
		if revealedKeys[k] {
			continue
		}
		if found != "" {
			return ""
		}
		found = k
	}
	return found
}

// text returns a JSON value as text: a string as it is, null as empty,
// and any other value in its JSON form.
func text(v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	}
	// A value that JSON decoded always encodes again.
	return string(anyval.Must(json.Marshal(v)))
}

// ProofListEntry is one proof request as the platform lists it.
type ProofListEntry struct {
	// PresentationID is the id of the proof exchange in the agent.
	PresentationID string `json:"presentationId"`
	// ConnectionID is the connection of the exchange, when it has one.
	ConnectionID string `json:"connectionId"`
	// State is the state of the exchange.
	State string `json:"state"`
	// ErrorMessage is the reason of a failed exchange.
	ErrorMessage string `json:"errorMessage"`
	// CreatedAt is when the request began.
	CreatedAt time.Time `json:"createDateTime"`
	// Connection names the wallet of the connection.
	Connection *struct {
		Label string `json:"theirLabel"`
	} `json:"connections"`
}

// pageOf is one page of a list answer of the platform.
type pageOf[T any] struct {
	TotalItems int `json:"totalItems"`
	Data       []T `json:"data"`
}

// ProofRequests reads one page of the proof requests of the
// organisation, newest first. Page numbers start at one. The platform
// answers the status not found for none. It learns each exchange from
// the webhook of the agent (ADR-058 decision 4).
func (c *Client) ProofRequests(ctx context.Context, page, size int) ([]ProofListEntry, int, error) {
	if c == nil {
		return nil, 0, ErrNoPlatform
	}
	q := url.Values{
		"pageNumber": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)},
		"sortField": {"createDateTime"}, "sortBy": {"desc"}, "search": {""},
	}
	var out envelope[pageOf[ProofListEntry]]
	if err := c.call(ctx, http.MethodGet, "/v1/orgs/"+url.PathEscape(c.orgID)+"/proofs?"+q.Encode(), nil, &out); err != nil {
		if dpgclient.IsStatus(err, http.StatusNotFound) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	return out.Data.Data, out.Data.TotalItems, nil
}

// PlatformSchema is one AnonCreds schema of the platform.
type PlatformSchema struct {
	// ID is the id of the schema on its ledger.
	ID string `json:"schemaLedgerId"`
	// Name is the name of the schema.
	Name string `json:"name"`
	// Version is the version of the schema.
	Version string `json:"version"`
	// IssuerID is the DID that wrote the schema.
	IssuerID string `json:"issuerId"`
	// Attributes are the attributes of the schema.
	Attributes []struct {
		Name string `json:"attributeName"`
		Type string `json:"schemaDataType"`
	} `json:"attributes"`
	// Organisation names the organisation that wrote the schema.
	Organisation *struct {
		Name string `json:"name"`
	} `json:"organisation"`
}

// PlatformSchemas reads one page of the AnonCreds schemas of every
// organisation of the platform. Page numbers start at one. The platform
// answers the status not found for none.
func (c *Client) PlatformSchemas(ctx context.Context, page, size int) ([]PlatformSchema, int, error) {
	if c == nil {
		return nil, 0, ErrNoPlatform
	}
	q := url.Values{"schemaType": {ProofTypeIndy}, "pageNumber": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}}
	var out envelope[pageOf[PlatformSchema]]
	if err := c.call(ctx, http.MethodGet, "/v1/platform/schemas?"+q.Encode(), nil, &out); err != nil {
		if dpgclient.IsStatus(err, http.StatusNotFound) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	return out.Data.Data, out.Data.TotalItems, nil
}

// credDefPageSize is the page size the adapter reads the credential
// definitions of the platform with.
const credDefPageSize = 1000

// PlatformCredDefs reads the credential definitions of every
// organisation of the platform, by the schema of each. The platform
// answers the status not found for none.
func (c *Client) PlatformCredDefs(ctx context.Context) (map[string][]string, error) {
	if c == nil {
		return nil, ErrNoPlatform
	}
	q := url.Values{"pageNumber": {"1"}, "pageSize": {strconv.Itoa(credDefPageSize)}}
	var out envelope[pageOf[struct {
		SchemaID  string `json:"schemaLedgerId"`
		CredDefID string `json:"credentialDefinitionId"`
	}]]
	if err := c.call(ctx, http.MethodGet, "/v1/platform/cred-defs?"+q.Encode(), nil, &out); err != nil {
		if dpgclient.IsStatus(err, http.StatusNotFound) {
			return map[string][]string{}, nil
		}
		return nil, err
	}
	bySchema := map[string][]string{}
	for _, d := range out.Data.Data {
		bySchema[d.SchemaID] = append(bySchema[d.SchemaID], d.CredDefID)
	}
	return bySchema, nil
}
