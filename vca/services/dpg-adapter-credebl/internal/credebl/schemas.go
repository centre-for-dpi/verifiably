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

// The schema calls of the api gateway beyond the SD-JWT templates
// (P6-C2): an AnonCreds schema with its credential definition on an
// Indy ledger, and a W3C JSON-LD schema that the schema file server
// keeps. The sources are the schema, credential definition and platform
// controllers of the platform, read on 2026-09-26:
// https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/schema/schema.controller.ts
// https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/credential-definition/credential-definition.controller.ts
// https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/platform/platform.controller.ts

// SchemaAttribute is one claim of an AnonCreds or a W3C schema.
type SchemaAttribute struct {
	// AttributeName is the claim name.
	AttributeName string `json:"attributeName"`
	// SchemaDataType is the type the platform names, such as string.
	SchemaDataType string `json:"schemaDataType"`
	// DisplayName is the label of the claim.
	DisplayName string `json:"displayName"`
	// IsRequired marks a claim every credential carries.
	IsRequired bool `json:"isRequired"`
}

// Ledger is one ledger the platform knows.
type Ledger struct {
	// Name is the name the platform shows, such as Bcovrin Testnet.
	Name string `json:"name"`
	// Namespace is the Indy namespace, such as bcovrin:testnet.
	Namespace string `json:"indyNamespace"`
}

// storedSchema is the schema record the platform answers with.
type storedSchema struct {
	ID             string `json:"id"`
	SchemaLedgerID string `json:"schemaLedgerId"`
}

// CreateIndySchema writes an AnonCreds schema on the Indy ledger of the
// DID and returns the schema id on the ledger. The platform writes with
// the DID the request names when it has the four parts of a did:indy.
func (c *Client) CreateIndySchema(ctx context.Context, name, version, orgDid string, attributes []SchemaAttribute) (string, error) {
	if c == nil {
		return "", ErrNoPlatform
	}
	body := map[string]any{
		"type": "indy",
		"schemaPayload": map[string]any{
			"schemaName": name, "schemaVersion": version, "attributes": attributes, "orgId": c.orgID, "orgDid": orgDid,
		},
	}
	var out envelope[storedSchema]
	if err := c.call(ctx, http.MethodPost, "/v1/orgs/"+url.PathEscape(c.orgID)+"/schemas", body, &out); err != nil {
		return "", err
	}
	if out.Data.SchemaLedgerID == "" {
		return "", errors.New("credebl: the schema answer has no ledger id")
	}
	return out.Data.SchemaLedgerID, nil
}

// CreateW3CSchema stores a W3C JSON-LD schema with no ledger. The schema
// file server of the stack keeps the document. The answer carries its
// address.
func (c *Client) CreateW3CSchema(ctx context.Context, name, description string, attributes []SchemaAttribute) (string, error) {
	if c == nil {
		return "", ErrNoPlatform
	}
	body := map[string]any{
		"type":  "json",
		"alias": name,
		"schemaPayload": map[string]any{
			"schemaName": name, "description": description, "schemaType": "no_ledger", "attributes": attributes,
		},
	}
	var out envelope[storedSchema]
	if err := c.call(ctx, http.MethodPost, "/v1/orgs/"+url.PathEscape(c.orgID)+"/schemas", body, &out); err != nil {
		return "", err
	}
	if out.Data.SchemaLedgerID == "" {
		return "", errors.New("credebl: the schema answer has no address")
	}
	return out.Data.SchemaLedgerID, nil
}

// CreateCredentialDefinition writes the credential definition of an
// AnonCreds schema on the ledger of the DID and returns its id. The
// definition takes no revocation registry.
func (c *Client) CreateCredentialDefinition(ctx context.Context, schemaLedgerID, orgDid, tag string) (string, error) {
	if c == nil {
		return "", ErrNoPlatform
	}
	body := map[string]any{"tag": tag, "schemaLedgerId": schemaLedgerID, "orgDid": orgDid, "revocable": false}
	var out envelope[struct {
		CredentialDefinitionID string `json:"credentialDefinitionId"`
	}]
	if err := c.call(ctx, http.MethodPost, "/v1/orgs/"+url.PathEscape(c.orgID)+"/cred-defs", body, &out); err != nil {
		return "", err
	}
	if out.Data.CredentialDefinitionID == "" {
		return "", errors.New("credebl: the credential definition answer has no id")
	}
	return out.Data.CredentialDefinitionID, nil
}

// Ledgers reads the ledgers of the platform.
func (c *Client) Ledgers(ctx context.Context) ([]Ledger, error) {
	if c == nil {
		return nil, ErrNoPlatform
	}
	var out envelope[[]Ledger]
	if err := c.call(ctx, http.MethodGet, "/v1/platform/ledgers", nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// IndyNamespace returns the ledger namespace of a did:indy, such as
// bcovrin:testnet for did:indy:bcovrin:testnet:Ra8F. Any other DID gives
// false.
func IndyNamespace(did string) (string, bool) {
	parts := strings.Split(did, ":")
	if len(parts) < 5 || parts[0] != "did" || parts[1] != "indy" {
		return "", false
	}
	return fmt.Sprintf("%s:%s", parts[2], parts[3]), true
}
