// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"context"
	"errors"
	"net/http"
)

// Inji Certify 0.14.0 runs an authorization server of its own for
// presentation during issuance. A wallet reads its metadata, sends an
// interactive authorization request, presents a credential through the
// OpenID4VP request the answer carries, and receives an authorization
// code. The presentation definition comes from the deployment
// (mosip.certify.vp-request.config-file-url), and Certify checks the
// presentation with Inji Verify.

// asMetadataPath is the authorization server metadata of Certify.
const asMetadataPath = "/v1/certify/.well-known/oauth-authorization-server"

// InteractionPresentation is the interaction type of a presentation.
const InteractionPresentation = "openid4vp_presentation"

// ErrNoInteractiveEndpoint reports an authorization server that names no
// interactive authorization endpoint.
var ErrNoInteractiveEndpoint = errors.New("inji: the Certify authorization server names no interactive authorization endpoint")

// AuthorizationServer is the metadata of the authorization server of
// Certify (RFC 8414).
type AuthorizationServer struct {
	// Issuer is the identifier an offer names as its
	// authorization_server.
	Issuer string `json:"issuer"`
	// TokenEndpoint trades a code for an access token.
	TokenEndpoint string `json:"token_endpoint"`
	// GrantTypes lists the grants the server takes.
	GrantTypes []string `json:"grant_types_supported"`
	// InteractiveEndpoint takes the interactive authorization request.
	InteractiveEndpoint string `json:"interactive_authorization_endpoint"`
}

// InteractiveServer reads the authorization server metadata of Certify.
// It returns ErrNoInteractiveEndpoint when the server has no interactive
// authorization endpoint.
func (c *Certify) InteractiveServer(ctx context.Context) (AuthorizationServer, error) {
	if c == nil {
		return AuthorizationServer{}, ErrNoCertify
	}
	var out AuthorizationServer
	if err := c.client.JSON(ctx, http.MethodGet, asMetadataPath, nil, &out); err != nil {
		return AuthorizationServer{}, err
	}
	if out.InteractiveEndpoint == "" || out.Issuer == "" {
		return AuthorizationServer{}, ErrNoInteractiveEndpoint
	}
	return out, nil
}
