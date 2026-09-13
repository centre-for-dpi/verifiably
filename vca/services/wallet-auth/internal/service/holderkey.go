// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	walletauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletauth/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// RegisterHolderKey implements WalletAuthServiceHandler (ADR-020
// decision 4). The browser keeps the private key. The service stores the
// thumbprint and derives a did:jwk. The proof is a compact JWS over the
// session id, signed with the private key.
func (s *Service) RegisterHolderKey(_ context.Context, req *connect.Request[walletauthv1.RegisterHolderKeyRequest]) (*connect.Response[walletauthv1.RegisterHolderKeyResponse], error) {
	claims, err := s.d.Signer.Verify(req.Msg.GetSessionToken())
	if err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	jwk, err := jose.ParseJWK([]byte(req.Msg.GetPublicJwk()))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if !jwk.IsPublic() || !supportedKey(jwk.Key) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("public_jwk must be a public EC P-256 or Ed25519 key"))
	}
	payload, _, err := jose.Verify(req.Msg.GetProof(), jwk.Key, []jose.Algorithm{jose.ES256, jose.EdDSA})
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("proof does not verify with public_jwk"))
	}
	if !proofMatches(payload, claims.SID) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("proof must sign the session id"))
	}
	thumbprint, err := jose.Thumbprint(jwk)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	did, err := didJWK(jwk)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if _, err := s.d.Wallets.BindKey(claims.Subject, thumbprint, did); err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	return connect.NewResponse(&walletauthv1.RegisterHolderKeyResponse{Thumbprint: thumbprint, HolderDid: did}), nil
}

func supportedKey(k any) bool {
	switch key := k.(type) {
	case *ecdsa.PublicKey:
		return key.Curve == elliptic.P256()
	case ed25519.PublicKey:
		return true
	}
	return false
}

// proofMatches accepts the raw session id or a JSON object with sid.
func proofMatches(payload []byte, sid string) bool {
	if sid == "" {
		return false
	}
	if strings.TrimSpace(string(payload)) == sid || strings.TrimSpace(string(payload)) == `"`+sid+`"` {
		return true
	}
	var obj struct {
		SID string `json:"sid"`
	}
	return json.Unmarshal(payload, &obj) == nil && obj.SID == sid
}

// didJWK builds the did:jwk of a public key.
func didJWK(k jose.JWK) (string, error) {
	pub := k.Public()
	pub.KeyID = ""
	raw, err := json.Marshal(pub)
	if err != nil {
		return "", err
	}
	return "did:jwk:" + base64.RawURLEncoding.EncodeToString(raw), nil
}
