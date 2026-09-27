// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Template is one CREDEBL credential template.
//
// CREDEBL stores the body of a template in a column named attributes. A
// read therefore returns the body under that name, although a write
// sends it under the name template.
type Template struct {
	// ID is the identifier an offer uses.
	ID string `json:"id"`
	// Name is the display name.
	Name string `json:"name"`
	// Format is the OID4VCI format identifier.
	Format string `json:"format"`
	// Body holds the type and the attributes of the template.
	Body TemplateBody `json:"attributes"`
}

// TemplateBody is the shape of one template.
type TemplateBody struct {
	// Vct is the SD-JWT VC type.
	Vct string `json:"vct"`
	// Attributes lists the claims of the credential.
	Attributes []Attribute `json:"attributes"`
}

// Attribute is one claim of a template.
type Attribute struct {
	// Key is the claim name.
	Key string `json:"key"`
	// ValueType is the JSON type of the value.
	ValueType string `json:"value_type"`
	// Disclose reports whether the holder can reveal the claim alone.
	Disclose bool `json:"disclose"`
}

// templateList is the answer of the template endpoint.
type templateList struct {
	Data []Template `json:"data"`
}

// Templates reads the credential templates of the issuer.
func (c *Client) Templates(ctx context.Context) ([]Template, error) {
	if c == nil {
		return nil, ErrNoPlatform
	}
	path := fmt.Sprintf("/v1/orgs/%s/oid4vc/%s/template", c.orgID, c.issuerID)
	var out templateList
	if err := c.call(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// offerRequest is the body of the create offer endpoint.
type offerRequest struct {
	AuthorizationType string       `json:"authorizationType"`
	PIN               string       `json:"pin,omitempty"`
	Credentials       []offerEntry `json:"credentials"`
	// IsRevocable asks the platform for a status list entry in each
	// credential. The platform refuses it without a status list host.
	IsRevocable bool `json:"isRevocable,omitempty"`
}

// offerEntry is one credential of a create offer body.
type offerEntry struct {
	TemplateID string         `json:"templateId"`
	Payload    map[string]any `json:"payload"`
}

// offerResponse is the answer of the create offer endpoint.
type offerResponse struct {
	Data struct {
		CredentialOffer string `json:"credentialOffer"`
		IssuanceSession struct {
			ID      string `json:"id"`
			UserPin string `json:"userPin"`
		} `json:"issuanceSession"`
	} `json:"data"`
}

// Offer is one OID4VCI credential offer of CREDEBL.
type Offer struct {
	// URI is the openid-credential-offer address.
	URI string
	// SessionID is the issuance session of CREDEBL.
	SessionID string
	// PIN is the transaction code the citizen types.
	PIN string
}

// CreateOffer builds a pre-authorized code offer for one subject.
//
// CREDEBL checks the payload against the attributes of the template, so
// the payload carries the claims of the template and nothing else. The
// flow binds the subject to the key of the wallet during the exchange,
// so the payload carries no subject identifier. A revocable offer gives
// each credential a status list entry, which Revoke later sets.
func (c *Client) CreateOffer(ctx context.Context, templateID, pin string, payload map[string]any, revocable bool) (Offer, error) {
	if c == nil {
		return Offer{}, ErrNoPlatform
	}
	if strings.TrimSpace(templateID) == "" {
		return Offer{}, errors.New("credebl: the offer needs a template id")
	}
	body := offerRequest{
		AuthorizationType: "preAuthorizedCodeFlow",
		PIN:               pin,
		Credentials:       []offerEntry{{TemplateID: templateID, Payload: payload}},
		IsRevocable:       revocable,
	}
	path := fmt.Sprintf("/v1/orgs/%s/oid4vc/%s/create-offer", c.orgID, c.issuerID)
	var out offerResponse
	if err := c.call(ctx, http.MethodPost, path, body, &out); err != nil {
		return Offer{}, err
	}
	if out.Data.CredentialOffer == "" {
		return Offer{}, errors.New("credebl: the create offer answer has no offer")
	}
	return Offer{
		URI:       out.Data.CredentialOffer,
		SessionID: out.Data.IssuanceSession.ID,
		PIN:       out.Data.IssuanceSession.UserPin,
	}, nil
}

// RewritePublic swaps the internal host of an offer URI for the public
// one. The CREDEBL agent writes its own network name into the offer, and
// a wallet outside the deployment cannot reach that name.
//
// The agent puts the address in a query parameter, so the name appears
// in its percent encoded form as well. The swap covers both forms.
func RewritePublic(uri, internal, public string) string {
	internal = strings.TrimRight(strings.TrimSpace(internal), "/")
	public = strings.TrimRight(strings.TrimSpace(public), "/")
	if internal == "" || public == "" {
		return uri
	}
	out := strings.ReplaceAll(uri, internal, public)
	return strings.ReplaceAll(out, url.QueryEscape(internal), url.QueryEscape(public))
}

// schemaRequest is the body of the schema endpoint: GenericSchemaDTO of
// apps/api-gateway/src/dtos/create-schema.dto.ts.
type schemaRequest struct {
	Type    string        `json:"type"`
	Payload schemaPayload `json:"schemaPayload"`
}

// schemaPayload is the W3C schema the platform stores for a template:
// CreateW3CSchemaDto of the same file.
type schemaPayload struct {
	SchemaName  string             `json:"schemaName"`
	SchemaType  string             `json:"schemaType"`
	Description string             `json:"description"`
	Attributes  []schemaAttributes `json:"attributes"`
}

// schemaAttributes is one claim of a schema: W3CAttributeValue.
type schemaAttributes struct {
	AttributeName string `json:"attributeName"`
	DataType      string `json:"schemaDataType"`
	DisplayName   string `json:"displayName"`
	IsRequired    bool   `json:"isRequired"`
}

// schemaResponse is the answer of the schema endpoint.
type schemaResponse struct {
	Data struct {
		SchemaLedgerID string `json:"schemaLedgerId"`
		SchemaID       string `json:"schemaId"`
		ID             string `json:"id"`
	} `json:"data"`
}

// The values of the schema body that the enums of the platform allow
// (libs/enum/src/enum.ts): SchemaTypeEnum.JSON for the type, and
// JSONSchemaType.LEDGER_LESS for the schemaType. The platform refuses any
// other schemaType, and the stack runs no Polygon ledger.
const (
	schemaTypeJSON     = "json"
	schemaTypeNoLedger = "no_ledger"
)

// w3cDataTypes are the values of W3CSchemaDataType.
var w3cDataTypes = map[string]bool{
	"number": true, "integer": true, "string": true, "datetime-local": true, "array": true, "object": true, "boolean": true,
}

// w3cDataType maps the JSON Schema type of a claim onto W3CSchemaDataType.
// A type the enum lacks is a string.
func w3cDataType(t string) string {
	if w3cDataTypes[t] {
		return t
	}
	return "string"
}

// CreateSchema stores the W3C schema of an SD-JWT template in CREDEBL,
// with no ledger, and returns its identifier. The platform needs a
// description, so an empty one takes the name.
func (c *Client) CreateSchema(ctx context.Context, name, description string, attributes []Attribute) (string, error) {
	if c == nil {
		return "", ErrNoPlatform
	}
	if strings.TrimSpace(description) == "" {
		description = name
	}
	payload := schemaPayload{
		SchemaName:  name,
		SchemaType:  schemaTypeNoLedger,
		Description: description,
	}
	for _, a := range attributes {
		payload.Attributes = append(payload.Attributes, schemaAttributes{
			AttributeName: a.Key,
			DataType:      w3cDataType(a.ValueType),
			DisplayName:   a.Key,
			IsRequired:    true,
		})
	}
	var out schemaResponse
	path := fmt.Sprintf("/v1/orgs/%s/schemas", c.orgID)
	if err := c.call(ctx, http.MethodPost, path, schemaRequest{Type: schemaTypeJSON, Payload: payload}, &out); err != nil {
		return "", err
	}
	for _, id := range []string{out.Data.ID, out.Data.SchemaID, out.Data.SchemaLedgerID} {
		if id != "" {
			return id, nil
		}
	}
	return "", errors.New("credebl: the schema answer has no identifier")
}

// templateRequest is the body of the template endpoint.
type templateRequest struct {
	Name         string       `json:"name"`
	Format       string       `json:"format"`
	SignerOption string       `json:"signerOption"`
	CanBeRevoked bool         `json:"canBeRevoked"`
	Template     TemplateBody `json:"template"`
}

// templateResponse is the answer of the template endpoint.
type templateResponse struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

// CreateTemplate stores one credential template and returns its
// identifier.
func (c *Client) CreateTemplate(ctx context.Context, name, format, vct string, attributes []Attribute) (string, error) {
	if c == nil {
		return "", ErrNoPlatform
	}
	body := templateRequest{
		Name:         name,
		Format:       format,
		SignerOption: "DID",
		CanBeRevoked: true,
		Template:     TemplateBody{Vct: vct, Attributes: attributes},
	}
	path := fmt.Sprintf("/v1/orgs/%s/oid4vc/%s/template", c.orgID, c.issuerID)
	var out templateResponse
	if err := c.call(ctx, http.MethodPost, path, body, &out); err != nil {
		return "", err
	}
	if out.Data.ID == "" {
		return "", errors.New("credebl: the template answer has no identifier")
	}
	return out.Data.ID, nil
}

// FindTemplate returns the template with the name, or false.
func FindTemplate(templates []Template, name string) (Template, bool) {
	for _, t := range templates {
		if t.Name == name || t.ID == name {
			return t, true
		}
	}
	return Template{}, false
}
