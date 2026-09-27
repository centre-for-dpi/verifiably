// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
)

// The OID4VC side of the holder wallet (ADR-062 decision 8). The same
// tenant claims an OID4VCI offer with a pre-authorized code, and answers
// an OID4VP request through the OID4VC holder API of the agent. The
// agent picks the credential of each query, so the adapter refuses an
// answer when the holder picked another one.

// isOid4vciOffer reports an OID4VCI credential offer, by value or by
// reference.
func isOid4vciOffer(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	q := u.Query()
	return u.Scheme == "openid-credential-offer" || q.Get("credential_offer") != "" || q.Get("credential_offer_uri") != ""
}

// oid4vpRequest returns the OID4VP request the agent reads: a URI with
// the request or its reference as it is, and the bare address of a
// request object as the request_uri of an openid4vp URI.
func oid4vpRequest(raw string) (string, bool) {
	uri := strings.TrimSpace(raw)
	u, err := url.Parse(uri)
	if err != nil || uri == "" || isInvitation(uri) {
		return "", false
	}
	switch u.Scheme {
	case "openid4vp", "eudi-openid4vp", "mdoc-openid4vp", "haip":
		return uri, true
	case "https", "http":
		q := u.Query()
		if q.Get("request_uri") != "" || q.Get("client_id") != "" {
			return uri, true
		}
		if u.RawQuery == "" {
			return "openid4vp://authorize?request_uri=" + url.QueryEscape(uri), true
		}
	}
	return "", false
}

// claimOid4vci claims an OID4VCI offer with a pre-authorized code.
func (s *Service) claimOid4vci(ctx context.Context, tenant, uri, pin string) (*connect.Response[backendv1.AcceptOfferResponse], error) {
	offer, err := s.agent.ResolveOffer(ctx, tenant, uri)
	if err != nil {
		return nil, failed("read the offer", err)
	}
	preAuthorized, needsCode := offer.PreAuthorized()
	switch {
	case !preAuthorized:
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New(
			"the wallet of this stack claims offers with a pre-authorized code only; ask the issuer for such an offer"))
	case needsCode && pin == "":
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the offer needs the transaction code of the issuer"))
	}
	stored, err := s.agent.RequestCredential(ctx, tenant, uri, offer.Payload.ConfigurationIDs, pin)
	if err != nil {
		return nil, failed("claim the offer", err)
	}
	if len(stored) == 0 {
		return nil, connect.NewError(connect.CodeInternal, errors.New("the wallet claimed the offer but holds no new credential"))
	}
	return connect.NewResponse(&backendv1.AcceptOfferResponse{Credential: storedCredential(stored[0])}), nil
}

// presentOid4vp answers an OID4VP request. The holder picked the
// credentials on the consent screen, and the agent picks its own, so
// the two must name the same credentials.
func (s *Service) presentOid4vp(ctx context.Context, tenant, uri string, msg *backendv1.PresentRequest,
) (*connect.Response[backendv1.PresentResponse], error) {
	req, err := s.agent.ResolveProofRequest(ctx, tenant, uri)
	if err != nil {
		return nil, failed("read the request", err)
	}
	if chosen := msg.GetCredentialIds(); len(chosen) > 0 {
		if perr := samePicks(chosen, req.Picks()); perr != nil {
			return nil, perr
		}
	}
	answer, err := s.agent.AcceptOid4vpRequest(ctx, tenant, uri)
	if err != nil {
		return nil, failed("answer the request", err)
	}
	return connect.NewResponse(&backendv1.PresentResponse{
		Accepted: answer.Accepted(), SharedClaims: msg.GetDisclosedClaims(), VerifierState: req.Verifier.ClientID,
	}), nil
}

// samePicks checks that the holder chose the credentials the agent
// picks.
func samePicks(chosen []string, picks map[string]string) error {
	want := make([]string, 0, len(picks))
	for _, id := range picks {
		want = append(want, id)
	}
	got := make([]string, 0, len(chosen))
	for _, id := range chosen {
		_, record := heldKind(id)
		got = append(got, record)
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(want, ",") != strings.Join(got, ",") {
		return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf(
			"the wallet of this stack answers with the first credential that matches each query (%s); pick that credential",
			strings.Join(want, ", ")))
	}
	return nil
}

// heldKind returns the removal type and the record id of a credential
// id of ListCredentials, or empty for an id the agent cannot remove.
func heldKind(id string) (string, string) {
	for prefix, kind := range map[string]string{w3cPrefix: credebl.HeldW3c, sdJwtPrefix: credebl.HeldSdJwt, mdocPrefix: credebl.HeldMdoc} {
		if strings.HasPrefix(id, prefix) {
			return kind, strings.TrimPrefix(id, prefix)
		}
	}
	return "", id
}

// storedCredential returns the wallet credential of a stored OID4VC
// record.
func storedCredential(rec credebl.AgentStored) *backendv1.WalletCredential {
	switch rec.Type {
	case credebl.RecordSdJwt:
		return sdJwtCredential(rec)
	case credebl.RecordMdoc:
		return &backendv1.WalletCredential{
			Id: mdocPrefix + rec.ID, Type: tag(rec, "docType"), ReceivedAt: timestamp(rec.CreatedAt),
			Credential: &commonv1.Credential{Format: commonv1.Format_FORMAT_MSO_MDOC, Payload: []byte(rec.Compact())},
		}
	}
	w3c := credebl.AgentW3c{ID: rec.ID, CreatedAt: rec.CreatedAt}
	if len(rec.Instances) > 0 {
		w3c.Legacy = rec.Instances[0].Credential
	}
	return w3cCredential(w3c)
}

// sdJwtCredential returns the wallet credential of an SD-JWT VC: the
// type from vct, the issuer from iss, and the format from typ.
func sdJwtCredential(rec credebl.AgentStored) *backendv1.WalletCredential {
	compact := rec.Compact()
	out := &backendv1.WalletCredential{
		Id: sdJwtPrefix + rec.ID, Type: tag(rec, "vct"), ReceivedAt: timestamp(rec.CreatedAt),
		Credential: &commonv1.Credential{Format: commonv1.Format_FORMAT_DC_SD_JWT, Payload: []byte(compact)},
	}
	parts := strings.SplitN(strings.SplitN(compact, "~", 2)[0], ".", 3)
	if len(parts) < 2 {
		return out
	}
	var header struct {
		Typ string `json:"typ"`
	}
	var payload struct {
		Iss string `json:"iss"`
		Vct string `json:"vct"`
	}
	if raw, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil && json.Unmarshal(raw, &header) == nil && header.Typ == "vc+sd-jwt" {
		out.Credential.Format = commonv1.Format_FORMAT_VC_SD_JWT
	}
	if raw, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil && json.Unmarshal(raw, &payload) == nil {
		out.Issuer = payload.Iss
		if out.Type == "" {
			out.Type = payload.Vct
		}
	}
	return out
}

// tag returns one text tag of a record.
func tag(rec credebl.AgentStored, name string) string {
	if v, ok := rec.Tags[name].(string); ok {
		return v
	}
	return ""
}
