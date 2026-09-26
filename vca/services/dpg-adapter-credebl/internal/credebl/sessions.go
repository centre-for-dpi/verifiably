// SPDX-License-Identifier: Apache-2.0

package credebl

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// The OID4VC issuance sessions of the agent (P6-C5). The api gateway
// hands the session records of the agent through. The sources, read on
// 2026-09-26:
// https://raw.githubusercontent.com/credebl/platform/main/apps/api-gateway/src/oid4vc-issuance/oid4vc-issuance.controller.ts
// https://raw.githubusercontent.com/credebl/agent-controller/main/src/controllers/openid4vc/issuance-sessions/issuance-sessions.service.ts

// Session states the agent names.
const (
	// SessionCompleted is a session whose credentials the wallet took.
	SessionCompleted = "Completed"
	// SessionError is a session the agent ended in error.
	SessionError = "Error"
)

// IssuanceSession is one OID4VC issuance session.
type IssuanceSession struct {
	// ID is the session id, which CreateOffer returns.
	ID string `json:"id"`
	// State is the state of the session, such as Completed.
	State string `json:"state"`
	// CreatedAt is the time of the offer.
	CreatedAt time.Time `json:"createdAt"`
	// UpdatedAt is the time of the last change.
	UpdatedAt time.Time `json:"updatedAt"`
	// ExpiresAt is the end of the offer, when the agent sets one.
	ExpiresAt *time.Time `json:"expiresAt"`
	// ErrorMessage is the reason of a session in error.
	ErrorMessage string `json:"errorMessage"`
	// OfferPayload is the credential offer.
	OfferPayload struct {
		ConfigurationIDs []string `json:"credential_configuration_ids"`
	} `json:"credentialOfferPayload"`
	// Metadata holds the credentials of the offer with their claims.
	Metadata struct {
		Credentials []SessionCredential `json:"credentials"`
	} `json:"issuanceMetadata"`
}

// SessionCredential is one credential of an offer.
type SessionCredential struct {
	// SupportedID is the configuration id of the credential.
	SupportedID string `json:"credentialSupportedId"`
	// Payload holds the claims.
	Payload map[string]json.RawMessage `json:"payload"`
}

// OfferSession reads one issuance session.
func (c *Client) OfferSession(ctx context.Context, id string) (IssuanceSession, error) {
	if c == nil {
		return IssuanceSession{}, ErrNoPlatform
	}
	var out envelope[IssuanceSession]
	path := "/v1/orgs/" + url.PathEscape(c.orgID) + "/oid4vc/credential-offer/" + url.PathEscape(id)
	if err := c.call(ctx, http.MethodGet, path, nil, &out); err != nil {
		return IssuanceSession{}, err
	}
	if out.Data.ID == "" {
		return IssuanceSession{}, errors.New("credebl: the session answer has no id")
	}
	return out.Data, nil
}

// OfferSessions reads every issuance session of the organisation.
func (c *Client) OfferSessions(ctx context.Context) ([]IssuanceSession, error) {
	if c == nil {
		return nil, ErrNoPlatform
	}
	var out envelope[[]IssuanceSession]
	if err := c.call(ctx, http.MethodGet, "/v1/orgs/"+url.PathEscape(c.orgID)+"/oid4vc/credential-offer", nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}
