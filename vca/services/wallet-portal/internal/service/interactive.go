// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/issuers"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/present"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// Presentation during issuance follows the interactive authorization
// endpoint of the OID4VCI 1.1 draft, as an issuer of a DPG stack serves
// it:
//
//  1. The offer names an authorization server whose metadata has an
//     interactive_authorization_endpoint.
//  2. The wallet posts the authorization request there, with PKCE and
//     the interaction type openid4vp_presentation.
//  3. The server answers require_interaction with an auth_session and
//     an OpenID4VP request whose response mode is iar-post.
//  4. The holder consents on the usual screen. The wallet posts the
//     auth_session and the openid4vp_response to the same endpoint.
//  5. The server answers ok with an authorization code. The wallet
//     trades it for an access token and claims the credential with it.

// interactionPresentation is the interaction type the wallet supports.
const interactionPresentation = "openid4vp_presentation"

// iarAnswer is the answer of the interactive authorization endpoint.
type iarAnswer struct {
	Status      string          `json:"status"`
	Type        string          `json:"type"`
	AuthSession string          `json:"auth_session"`
	Request     json.RawMessage `json:"openid4vp_request"`
	Code        string          `json:"code"`
	Error       string          `json:"error"`
}

// offerGrant is the part of a credential offer the interactive flow
// needs.
type offerGrant struct {
	Issuer string   `json:"credential_issuer"`
	IDs    []string `json:"credential_configuration_ids"`
	Grants struct {
		Code *struct {
			IssuerState string `json:"issuer_state"`
			Server      string `json:"authorization_server"`
		} `json:"authorization_code"`
	} `json:"grants"`
}

// interactive starts the presentation an issuer asks for before it
// issues. It reports false when the offer does not ask for one, so the
// DPG wallet claims the offer as before. It needs a DPG wallet, which
// takes the credential afterwards.
func (s *Service) interactive(ctx context.Context, citizen session.Citizen, offer record) (string, bool, error) {
	if s.opts.Holder == nil || s.opts.Servers == nil || s.opts.Post == nil {
		return "", false, nil
	}
	grant, ok := s.readOffer(ctx, offer.URI)
	if !ok || grant.Grants.Code == nil || grant.Grants.Code.Server == "" || len(grant.IDs) == 0 {
		return "", false, nil
	}
	ends, ok := s.interactiveServer(ctx, grant.Grants.Code.Server)
	if !ok {
		return "", false, nil
	}
	verifier := randomText()
	sum := sha256.Sum256([]byte(verifier))
	details, err := json.Marshal([]map[string]string{{
		"type": "openid_credential", "credential_configuration_id": grant.IDs[0],
	}})
	if err != nil {
		return "", true, connect.NewError(connect.CodeInternal, err)
	}
	form := url.Values{
		"response_type": {"code"}, "client_id": {s.opts.ClientID},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"interaction_types_supported": {interactionPresentation}, "authorization_details": {string(details)},
	}
	if state := grant.Grants.Code.IssuerState; state != "" {
		form.Set("issuer_state", state)
	}
	answer, err := s.askIssuer(ctx, ends.Interactive, form)
	if err != nil {
		return "", true, err
	}
	if answer.Status != "require_interaction" || answer.Type != interactionPresentation ||
		answer.AuthSession == "" || len(answer.Request) == 0 {
		return "", true, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("the issuer asks for a step this wallet cannot do"))
	}
	if _, perr := present.ParseInteractive(answer.Request); perr != nil {
		return "", true, connect.NewError(connect.CodeFailedPrecondition, perr)
	}
	rec := record{
		ID: s.opts.NewID(), Issuer: firstNonEmpty(grant.Issuer, offer.Issuer), Types: grant.IDs,
		Verifier: verifier, Token: ends.Token, Interactive: ends.Interactive,
		AuthSession: answer.AuthSession, Request: string(answer.Request), Offer: offer.URI,
	}
	if err := s.put(ctx, KindPresentation, citizen.WalletKey(), rec); err != nil {
		return "", true, connect.NewError(connect.CodeInternal, err)
	}
	return rec.ID, true, nil
}

// interactiveServer returns the endpoints of an authorization server
// with an interactive endpoint. ok is false for any other server.
func (s *Service) interactiveServer(ctx context.Context, server string) (issuers.Endpoints, bool) {
	ends, err := s.opts.Servers(ctx, server)
	return ends, err == nil && ends.Interactive != ""
}

// readOffer reads the offer object of an offer URI: the value of
// credential_offer, or the document of credential_offer_uri when its
// host is on the request host allowlist.
func (s *Service) readOffer(ctx context.Context, uri string) (offerGrant, bool) {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil {
		return offerGrant{}, false
	}
	raw := []byte(u.Query().Get("credential_offer"))
	if ref := u.Query().Get("credential_offer_uri"); ref != "" {
		if s.opts.Fetch == nil || present.AllowHost(ctx, ref, s.opts.RequestHosts) != nil {
			return offerGrant{}, false
		}
		if raw, err = s.opts.Fetch(ctx, ref); err != nil {
			return offerGrant{}, false
		}
	}
	var out offerGrant
	if json.Unmarshal(raw, &out) != nil {
		return offerGrant{}, false
	}
	return out, true
}

// askIssuer posts one form to the interactive endpoint and reads the
// answer.
func (s *Service) askIssuer(ctx context.Context, endpoint string, form url.Values) (iarAnswer, error) {
	raw, err := s.opts.Post(ctx, endpoint, form)
	if err != nil {
		return iarAnswer{}, connect.NewError(connect.CodeUnavailable,
			errors.New("the issuer did not answer, try again later"))
	}
	var answer iarAnswer
	if err := json.Unmarshal(raw, &answer); err != nil {
		return iarAnswer{}, connect.NewError(connect.CodeUnavailable,
			errors.New("the issuer gave an answer the wallet cannot read"))
	}
	return answer, nil
}

// presentForIssuance sends the presentation to the issuer, trades the
// code for an access token, and claims the credential of the offer into
// the DPG wallet with it.
func (s *Service) presentForIssuance(ctx context.Context, citizen session.Citizen, rec record, chosen string,
	disclosed []string,
) (*walletportalv1.PresentConfirmResponse, error) {
	held, err := s.walletCredential(ctx, citizen, chosen)
	if err != nil {
		return nil, err
	}
	token := string(held.GetPayload())
	if held.GetFormat() == commonv1.Format_FORMAT_DC_SD_JWT || held.GetFormat() == commonv1.Format_FORMAT_VC_SD_JWT {
		if token, err = present.Disclosed(token, disclosed); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}
	response, err := openid4vpResponse(token, held.GetFormat(), rec.Request)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	answer, err := s.askIssuer(ctx, rec.Interactive, url.Values{
		"auth_session": {rec.AuthSession}, "openid4vp_response": {response},
	})
	if err != nil {
		return nil, err
	}
	refused := &walletportalv1.PresentConfirmResponse{Message: "The issuer did not accept the credential, so it gave you no new one."}
	if answer.Status != "ok" || answer.Code == "" {
		return refused, nil
	}
	access, err := s.token(ctx, rec, answer.Code)
	if err != nil {
		return nil, err
	}
	card, err := s.accept(ctx, citizen, rec.Offer, "", access)
	if err != nil {
		return nil, err
	}
	return &walletportalv1.PresentConfirmResponse{
		Accepted: true, Card: card,
		Message: "You showed the credential. The issuer gave you the new one.",
	}, nil
}

// walletCredential returns the bytes of one credential of the DPG
// wallet.
func (s *Service) walletCredential(ctx context.Context, citizen session.Citizen, id string) (*commonv1.Credential, error) {
	var token string
	for range 100 {
		resp, err := s.opts.Holder.ListCredentials(ctx, connect.NewRequest(&backendv1.ListCredentialsRequest{
			WalletId: citizen.WalletID, Page: &commonv1.Pagination{PageSize: toInt32(int64(s.opts.PageSizeMax)), PageToken: token},
		}))
		if err != nil {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("the wallet is not available, try again later"))
		}
		for _, c := range resp.Msg.GetCredentials() {
			if c.GetId() == id {
				return c.GetCredential(), nil
			}
		}
		if token = resp.Msg.GetPage().GetNextPageToken(); token == "" {
			break
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, errors.New("the wallet does not hold this credential"))
}

// openid4vpResponse builds the openid4vp_response of the interactive
// endpoint: the vp_token and a presentation_submission that maps the
// first input descriptor of the definition to the token. A JSON
// credential goes in as an object.
func openid4vpResponse(token string, format commonv1.Format, request string) (string, error) {
	var req struct {
		Definition struct {
			ID          string `json:"id"`
			Descriptors []struct {
				ID string `json:"id"`
			} `json:"input_descriptors"`
		} `json:"presentation_definition"`
	}
	if err := json.Unmarshal([]byte(request), &req); err != nil {
		return "", err
	}
	var vp any = token
	if strings.HasPrefix(strings.TrimSpace(token), "{") {
		vp = json.RawMessage(token)
	}
	body := map[string]any{"vp_token": vp}
	if d := req.Definition; d.ID != "" && len(d.Descriptors) > 0 {
		body["presentation_submission"] = map[string]any{
			"id": d.ID + "-submission", "definition_id": d.ID,
			"descriptor_map": []map[string]string{{"id": d.Descriptors[0].ID, "format": present.FormatName(format), "path": "$"}},
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// firstNonEmpty returns the first value that is not empty.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
