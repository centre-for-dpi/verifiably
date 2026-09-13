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
// so the payload carries no subject identifier.
func (c *Client) CreateOffer(ctx context.Context, templateID, pin string, payload map[string]any) (Offer, error) {
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

// schemaRequest is the body of the schema endpoint.
type schemaRequest struct {
	Type    string        `json:"type"`
	Payload schemaPayload `json:"schemaPayload"`
}

// schemaPayload is the schema CREDEBL stores.
type schemaPayload struct {
	SchemaName  string             `json:"schemaName"`
	SchemaType  string             `json:"schemaType"`
	Description string             `json:"description"`
	OrgID       string             `json:"orgId"`
	Attributes  []schemaAttributes `json:"attributes"`
}

// schemaAttributes is one claim of a schema.
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

// CreateSchema stores one schema in CREDEBL and returns its identifier.
func (c *Client) CreateSchema(ctx context.Context, name, description string, attributes []Attribute) (string, error) {
	if c == nil {
		return "", ErrNoPlatform
	}
	payload := schemaPayload{
		SchemaName:  name,
		SchemaType:  "json",
		Description: description,
		OrgID:       c.orgID,
	}
	for _, a := range attributes {
		payload.Attributes = append(payload.Attributes, schemaAttributes{
			AttributeName: a.Key,
			DataType:      a.ValueType,
			DisplayName:   a.Key,
			IsRequired:    true,
		})
	}
	var out schemaResponse
	path := fmt.Sprintf("/v1/orgs/%s/schemas", c.orgID)
	if err := c.call(ctx, http.MethodPost, path, schemaRequest{Type: "json", Payload: payload}, &out); err != nil {
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
