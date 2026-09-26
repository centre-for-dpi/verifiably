// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The DIDComm issuance calls of the api gateway (P6-C3): an offer over a
// connection, an out of band offer, and an out of band offer by email.
// The platform issues AnonCreds and W3C JSON-LD credentials this way.
// The sources are the issuance and connection controllers of the
// platform and the credential controller of its agent, read on
// 2026-09-27:
// https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/issuance/issuance.controller.ts
// https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/issuance/dtos/issuance.dto.ts
// https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/issuance/dtos/multi-connection.dto.ts
// https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/connection/connection.controller.ts
// https://raw.githubusercontent.com/credebl/agent-controller/main/src/controllers/didcomm/credentials/CredentialController.ts

// The credential types of the query parameter credentialType
// (IssueCredentialType of libs/enum/src/enum.ts).
const (
	// CredentialTypeIndy issues an AnonCreds credential of a credential
	// definition.
	CredentialTypeIndy = "indy"
	// CredentialTypeJSONLD issues a W3C JSON-LD credential.
	CredentialTypeJSONLD = "jsonld"
)

// W3CContext is the first context of a W3C JSON-LD credential, as the
// platform names it (CommonConstants.W3C_SCHEMA_URL).
const W3CContext = "https://www.w3.org/2018/credentials/v1"

// protocolVersion is the version of the DIDComm issue credential
// protocol the adapter asks for.
const protocolVersion = "v2"

// DidcommOffer is one credential offer over DIDComm.
type DidcommOffer struct {
	// Type is CredentialTypeIndy or CredentialTypeJSONLD.
	Type string
	// CredentialDefinitionID names the AnonCreds credential definition.
	CredentialDefinitionID string
	// Attributes holds the claims of an AnonCreds credential.
	Attributes map[string]string
	// Credential is the unsigned W3C JSON-LD credential.
	Credential map[string]any
	// Options are the proof options of a W3C JSON-LD credential.
	Options map[string]any
	// Comment is the text the wallet shows with the offer.
	Comment string
}

// JSONLDOptions returns the proof options of a JSON-LD credential that
// the agent signs with the Ed25519 key of a did:key.
func JSONLDOptions() map[string]any {
	return map[string]any{"proofType": "Ed25519Signature2018", "proofPurpose": "assertionMethod"}
}

// attribute is one claim of an AnonCreds offer (Attribute of
// issuance.dto.ts).
type attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// attributes returns the claims of an AnonCreds offer in name order, so
// the body is the same on every run.
func (o DidcommOffer) attributes() []attribute {
	names := make([]string, 0, len(o.Attributes))
	for name := range o.Attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]attribute, 0, len(names))
	for _, name := range names {
		out = append(out, attribute{Name: name, Value: o.Attributes[name]})
	}
	return out
}

// check reports an offer that the platform would refuse.
func (o DidcommOffer) check() error {
	switch o.Type {
	case CredentialTypeIndy:
		if strings.TrimSpace(o.CredentialDefinitionID) == "" || len(o.Attributes) == 0 {
			return errors.New("credebl: an AnonCreds offer needs a credential definition and claims")
		}
	case CredentialTypeJSONLD:
		if len(o.Credential) == 0 || len(o.Options) == 0 {
			return errors.New("credebl: a JSON-LD offer needs the credential and the proof options")
		}
	default:
		return fmt.Errorf("credebl: no DIDComm credential type %q", o.Type)
	}
	return nil
}

// content returns the members that carry the credential in each body:
// the claims for AnonCreds, the credential and the options for JSON-LD.
func (o DidcommOffer) content() map[string]any {
	if o.Type == CredentialTypeIndy {
		return map[string]any{"attributes": o.attributes()}
	}
	return map[string]any{"credential": o.Credential, "options": o.Options}
}

// base returns the members every DIDComm offer body carries.
func (o DidcommOffer) base() map[string]any {
	body := map[string]any{"protocolVersion": protocolVersion, "comment": o.Comment}
	if o.Type == CredentialTypeIndy {
		body["credentialDefinitionId"] = o.CredentialDefinitionID
	}
	return body
}

// path returns the path of one issuance call with the credential type.
func (c *Client) path(tail, credentialType string) string {
	return "/v1/orgs/" + url.PathEscape(c.orgID) + tail + "?" + url.Values{"credentialType": {credentialType}}.Encode()
}

// OOBOffer is the out of band invitation that carries an offer.
type OOBOffer struct {
	// InvitationURL is the address of the invitation, with the
	// invitation in the query parameter oob.
	InvitationURL string `json:"invitationUrl"`
	// RecordID is the id of the credential exchange in the agent.
	RecordID string `json:"credentialExchangeRecordId"`
	// ThreadID is the thread of the credential exchange.
	ThreadID string `json:"credentialRequestThId"`
}

// CreateOOBOffer makes an out of band invitation that carries one offer.
// The platform reuses the connection of a wallet that took an invitation
// of the organisation before. The address stays as the agent made it;
// the platform shortens it only through an object store.
func (c *Client) CreateOOBOffer(ctx context.Context, offer DidcommOffer) (OOBOffer, error) {
	if c == nil {
		return OOBOffer{}, ErrNoPlatform
	}
	if err := offer.check(); err != nil {
		return OOBOffer{}, err
	}
	body := offer.base()
	for k, v := range offer.content() {
		body[k] = v
	}
	body["isShortenUrl"] = false
	body["reuseConnection"] = true
	var out envelope[OOBOffer]
	if err := c.call(ctx, http.MethodPost, c.path("/credentials/oob/offer", offer.Type), body, &out); err != nil {
		return OOBOffer{}, err
	}
	if out.Data.InvitationURL == "" {
		return OOBOffer{}, errors.New("credebl: the out of band answer has no invitation")
	}
	return out.Data, nil
}

// CredentialRecord is the credential exchange record of the agent.
type CredentialRecord struct {
	// ID is the id of the record.
	ID string `json:"id"`
	// State is the state of the exchange, such as offer-sent or done.
	State string `json:"state"`
	// ThreadID is the thread of the exchange.
	ThreadID string `json:"threadId"`
	// ConnectionID is the connection of the exchange, when it has one.
	ConnectionID string `json:"connectionId"`
	// ErrorMessage is the reason of a failed exchange.
	ErrorMessage string `json:"errorMessage"`
	// CreatedAt is when the exchange began.
	CreatedAt time.Time `json:"createdAt"`
	// UpdatedAt is the last change of the exchange.
	UpdatedAt time.Time `json:"updatedAt"`
}

// connectionResult is one result of an offer over connections: the
// platform answers each connection with a status, a message and the
// record.
type connectionResult struct {
	StatusCode int              `json:"statusCode"`
	Message    string           `json:"message"`
	Data       CredentialRecord `json:"data"`
}

// SendConnectionOffer sends one offer over a DIDComm connection of the
// organisation and returns the record the agent made.
func (c *Client) SendConnectionOffer(ctx context.Context, connectionID string, offer DidcommOffer) (CredentialRecord, error) {
	if c == nil {
		return CredentialRecord{}, ErrNoPlatform
	}
	if strings.TrimSpace(connectionID) == "" {
		return CredentialRecord{}, errors.New("credebl: an offer over a connection needs the connection")
	}
	if err := offer.check(); err != nil {
		return CredentialRecord{}, err
	}
	entry := offer.content()
	entry["connectionId"] = connectionID
	body := offer.base()
	body["credentialData"] = []map[string]any{entry}
	var out envelope[[]connectionResult]
	if err := c.call(ctx, http.MethodPost, c.path("/credentials/offer", offer.Type), body, &out); err != nil {
		return CredentialRecord{}, err
	}
	if len(out.Data) != 1 {
		return CredentialRecord{}, errors.New("credebl: the offer answer has no result")
	}
	result := out.Data[0]
	if result.StatusCode != http.StatusCreated || result.Data.ID == "" {
		return CredentialRecord{}, fmt.Errorf("credebl: the platform refused the offer: %s", result.Message)
	}
	return result.Data, nil
}

// SendOOBEmail makes an out of band invitation that carries one offer
// and has the platform mail it to the address, with a QR code. The
// platform answers true when its mail provider took the message.
func (c *Client) SendOOBEmail(ctx context.Context, email string, offer DidcommOffer) error {
	if c == nil {
		return ErrNoPlatform
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return errors.New("credebl: an offer by email needs the address")
	}
	if err := offer.check(); err != nil {
		return err
	}
	entry := offer.content()
	entry["emailId"] = email
	body := offer.base()
	body["credentialOffer"] = []map[string]any{entry}
	body["isReuseConnection"] = true
	var out envelope[bool]
	if err := c.call(ctx, http.MethodPost, c.path("/credentials/oob/email", offer.Type), body, &out); err != nil {
		return err
	}
	if !out.Data {
		return errors.New("credebl: the platform sent no email")
	}
	return nil
}

// Connection is one DIDComm connection of the organisation.
type Connection struct {
	// ID is the id of the connection.
	ID string `json:"connectionId"`
	// Label is the label the wallet gave itself.
	Label string `json:"theirLabel"`
	// State is the state of the connection, such as completed.
	State string `json:"state"`
	// CreatedAt is when the connection began.
	CreatedAt time.Time `json:"createDateTime"`
}

// connectionPage is the answer of GET /v1/orgs/{org}/connections.
type connectionPage struct {
	TotalItems int          `json:"totalItems"`
	Data       []Connection `json:"data"`
}

// Connections reads one page of the DIDComm connections of the
// organisation, newest first. Page numbers start at one. The platform
// answers the status not found for none. It learns each connection from
// the webhook of the agent (ADR-058 decision 4).
func (c *Client) Connections(ctx context.Context, page, size int) ([]Connection, int, error) {
	if c == nil {
		return nil, 0, ErrNoPlatform
	}
	q := url.Values{"pageNumber": {strconv.Itoa(page)}, "pageSize": {strconv.Itoa(size)}}
	var out envelope[connectionPage]
	if err := c.call(ctx, http.MethodGet, "/v1/orgs/"+url.PathEscape(c.orgID)+"/connections?"+q.Encode(), nil, &out); err != nil {
		if dpgclient.IsStatus(err, http.StatusNotFound) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	return out.Data.Data, out.Data.TotalItems, nil
}

// CredentialRecord reads the credential exchange record of one DIDComm
// offer from the agent.
func (c *Client) CredentialRecord(ctx context.Context, id string) (CredentialRecord, error) {
	if c == nil {
		return CredentialRecord{}, ErrNoPlatform
	}
	var out envelope[CredentialRecord]
	if err := c.call(ctx, http.MethodGet, "/v1/orgs/"+url.PathEscape(c.orgID)+"/credentials/"+url.PathEscape(id), nil, &out); err != nil {
		return CredentialRecord{}, err
	}
	return out.Data, nil
}
