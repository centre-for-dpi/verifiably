// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
)

// randomID returns a random identifier.
func randomID() string {
	b := make([]byte, 16)
	// crypto/rand cannot fail on a platform that Go supports.
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// offerKey returns the store key of one hosted offer.
func offerKey(id string) string { return "offer/" + id }

// hostedOffer is one authorization code offer the adapter serves.
type hostedOffer struct {
	// Document is the credential offer as a JSON string.
	Document string `json:"document"`
	// ExpiresAt is the end of the offer.
	ExpiresAt time.Time `json:"expires_at"`
}

// RegisterCredentialConfiguration is not available.
//
// Inji Certify reads its credential configurations from its own
// database. The legacy code wrote that database. ADR-002 decision 4
// forbids it, so the configuration goes in at deploy time (ADR-008).
func (s *Service) RegisterCredentialConfiguration(
	context.Context, *connect.Request[backendv1.RegisterCredentialConfigurationRequest],
) (*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error) {
	return nil, unimplemented("Inji Certify reads its credential configurations from its own " +
		"database; apply the configuration at deploy time")
}

// CreateOffer builds an OID4VCI credential offer for one subject.
//
// The pre-authorized channel asks Inji Certify to stage the claims. The
// authorization code channel builds the offer document itself, because
// Inji Certify hosts no such offer, and serves it under the public URL
// of this adapter.
func (s *Service) CreateOffer(
	ctx context.Context, req *connect.Request[backendv1.CreateOfferRequest],
) (*connect.Response[backendv1.CreateOfferResponse], error) {
	if s.certify == nil {
		return nil, unimplemented("this adapter has no Inji Certify URL, so it serves no issuer role")
	}
	spec := req.Msg.GetSpec()
	if spec == nil || strings.TrimSpace(spec.GetConfigurationId()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request needs a spec with a configuration_id"))
	}
	channel := req.Msg.GetChannel()
	if channel == backendv1.Channel_CHANNEL_UNSPECIFIED {
		channel = backendv1.Channel_CHANNEL_OID4VCI_PREAUTH
	}
	switch channel {
	case backendv1.Channel_CHANNEL_OID4VCI_PREAUTH:
		return s.preAuthorizedOffer(ctx, spec)
	case backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE:
		return s.authorizationCodeOffer(ctx, spec)
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("the Inji adapter serves the two OID4VCI channels only, not %s", channel))
	}
}

// preAuthorizedOffer stages the claims and returns the offer of Inji.
func (s *Service) preAuthorizedOffer(ctx context.Context, spec *backendv1.IssueSpec) (
	*connect.Response[backendv1.CreateOfferResponse], error,
) {
	cfg, claims, err := s.stagedClaims(ctx, spec)
	if err != nil {
		return nil, err
	}
	_ = cfg
	offerURI, serr := s.certify.Stage(ctx, spec.GetConfigurationId(), claims)
	if serr != nil {
		return nil, failed("stage the claims", serr)
	}
	return connect.NewResponse(&backendv1.CreateOfferResponse{
		OfferUri:  offerURI,
		OfferId:   offerIDOf(offerURI),
		Channel:   backendv1.Channel_CHANNEL_OID4VCI_PREAUTH,
		ExpiresAt: timestamp(s.now().UTC().Add(s.offerTTL)),
	}), nil
}

// authorizationCodeOffer builds and stores the offer document.
func (s *Service) authorizationCodeOffer(ctx context.Context, spec *backendv1.IssueSpec) (
	*connect.Response[backendv1.CreateOfferResponse], error,
) {
	if s.publicURL == "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("the authorization code channel needs a public URL for the offer document"))
	}
	issuer := s.offerIssuer
	if issuer == "" {
		issuer = s.certify.BaseURL()
	}
	document := inji.AuthorizationCodeOffer(issuer, spec.GetConfigurationId(),
		s.newID(), s.authorizationServer)
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	id := s.newID()
	expires := s.now().UTC().Add(s.offerTTL)
	stored, err := json.Marshal(hostedOffer{Document: string(raw), ExpiresAt: expires})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if err := s.store.Put(ctx, offerKey(id), stored); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	hosted := s.publicURL + "/offers/" + id
	return connect.NewResponse(&backendv1.CreateOfferResponse{
		OfferUri:  "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(hosted),
		OfferId:   id,
		Channel:   backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE,
		ExpiresAt: timestamp(expires),
	}), nil
}

// HostedOffer returns the stored offer document. The plain HTTP handler
// of the adapter serves it to a wallet (ADR-003 decision 7).
func (s *Service) HostedOffer(ctx context.Context, id string) (string, bool) {
	raw, err := s.store.Get(ctx, offerKey(id))
	if err != nil {
		return "", false
	}
	var offer hostedOffer
	if err := json.Unmarshal(raw, &offer); err != nil {
		return "", false
	}
	if s.now().UTC().After(offer.ExpiresAt) {
		return "", false
	}
	return offer.Document, true
}

// offerIDOf returns the last path part of an offer URI.
func offerIDOf(offerURI string) string {
	document, err := inji.OfferDocumentURL(offerURI)
	if err != nil {
		return ""
	}
	trimmed := strings.TrimRight(document, "/")
	if i := strings.LastIndexAny(trimmed, "/="); i >= 0 && i+1 < len(trimmed) {
		return trimmed[i+1:]
	}
	return trimmed
}

// stagedClaims reads the configuration of the spec and builds the claim
// map of the staging call.
func (s *Service) stagedClaims(ctx context.Context, spec *backendv1.IssueSpec) (
	inji.Configuration, map[string]any, error,
) {
	meta, err := s.certify.Metadata(ctx)
	if err != nil {
		return inji.Configuration{}, nil, failed("read the issuer metadata", err)
	}
	cfg, ok := meta.Configurations[spec.GetConfigurationId()]
	if !ok {
		return inji.Configuration{}, nil, connect.NewError(connect.CodeNotFound, fmt.Errorf(
			"the configuration %q is not advertised by Inji Certify", spec.GetConfigurationId()))
	}
	subject := map[string]any{}
	if raw := strings.TrimSpace(spec.GetSubjectData()); raw != "" {
		if err := json.Unmarshal([]byte(raw), &subject); err != nil {
			return inji.Configuration{}, nil, connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("subject_data is not a JSON object: %w", err))
		}
	}
	if len(subject) == 0 {
		return inji.Configuration{}, nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the claim set is empty, and Inji Certify rejects it"))
	}
	status := inji.StatusEntry{}
	if b := spec.GetStatus(); b != nil {
		status = inji.StatusEntry{Index: b.GetIndex(), URL: b.GetPublishUrl()}
	}
	validity := inji.Validity{}
	withValidity := false
	if v := spec.GetValidity(); v != nil {
		if from := v.GetValidFrom(); from != nil {
			validity.From = from.AsTime()
			withValidity = true
		}
		if until := v.GetValidUntil(); until != nil {
			validity.Until = until.AsTime()
			withValidity = true
		}
	}
	return cfg, inji.Claims(subject, cfg.Format, status, validity, withValidity), nil
}

// Issue produces one credential without a wallet.
//
// The adapter runs the whole pre-authorized flow: it stages the claims,
// reads the offer document, redeems the code, signs the holder proof,
// and asks for the credential. The citizen types nothing, which is what
// the document channel of ADR-016 decision 3 needs.
func (s *Service) Issue(
	ctx context.Context, req *connect.Request[backendv1.IssueRequest],
) (*connect.Response[backendv1.IssueResponse], error) {
	if s.certify == nil {
		return nil, unimplemented("this adapter has no Inji Certify URL, so it serves no issuer role")
	}
	spec := req.Msg.GetSpec()
	if spec == nil || strings.TrimSpace(spec.GetConfigurationId()) == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request needs a spec with a configuration_id"))
	}
	credential, err := s.issueOne(ctx, spec)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&backendv1.IssueResponse{
		Credential:   credential,
		CredentialId: inji.KeyID(credential.GetPayload()),
	}), nil
}

// issueOne runs the pre-authorized flow for one subject.
func (s *Service) issueOne(ctx context.Context, spec *backendv1.IssueSpec) (*commonv1.Credential, error) {
	cfg, claims, err := s.stagedClaims(ctx, spec)
	if err != nil {
		return nil, err
	}
	offerURI, serr := s.certify.Stage(ctx, spec.GetConfigurationId(), claims)
	if serr != nil {
		return nil, failed("stage the claims", serr)
	}
	documentURL, derr := inji.OfferDocumentURL(offerURI)
	if derr != nil {
		return nil, connect.NewError(connect.CodeInternal, derr)
	}
	offer, oerr := s.certify.FetchOffer(ctx, documentURL)
	if oerr != nil {
		return nil, failed("read the offer document", oerr)
	}
	token, terr := s.certify.Redeem(ctx, offer.PreAuthorizedCode())
	if terr != nil {
		return nil, failed("redeem the pre-authorized code", terr)
	}
	// The audience of the proof must equal the issuer identifier of the
	// offer. That identifier is right in both a local deployment and a
	// public one.
	audience := strings.TrimRight(offer.CredentialIssuer, "/")
	if audience == "" {
		audience = s.certify.BaseURL()
	}
	proof, perr := s.proofKey.Sign(audience, token.CNonce, s.now())
	if perr != nil {
		return nil, connect.NewError(connect.CodeInternal, perr)
	}
	payload, format, cerr := s.certify.RequestCredential(ctx, token.AccessToken,
		inji.BuildCredentialRequest(cfg, proof))
	if cerr != nil {
		return nil, failed("ask for the credential", cerr)
	}
	if format == "" {
		format = cfg.Format
	}
	return &commonv1.Credential{Format: contractFormat(format), Payload: payload}, nil
}

// IssueBatch produces many credentials in one call. One failure does not
// stop the others, so the caller sees every result.
func (s *Service) IssueBatch(
	ctx context.Context, req *connect.Request[backendv1.IssueBatchRequest],
) (*connect.Response[backendv1.IssueBatchResponse], error) {
	if s.certify == nil {
		return nil, unimplemented("this adapter has no Inji Certify URL, so it serves no issuer role")
	}
	specs := req.Msg.GetSpecs()
	if len(specs) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("the request needs at least one spec"))
	}
	out := &backendv1.IssueBatchResponse{Items: make([]*backendv1.IssueBatchResponse_Item, 0, len(specs))}
	for i, spec := range specs {
		item := &backendv1.IssueBatchResponse_Item{Position: toInt32(int64(i))}
		credential, err := s.issueOne(ctx, spec)
		if err != nil {
			item.Error = &commonv1.Error{
				Code:     "VCA-DPG-ISSUE",
				Message:  err.Error(),
				NextStep: "Check the claims of the row against the credential configuration.",
			}
		} else {
			item.Credential = credential
		}
		out.Items = append(out.Items, item)
	}
	return connect.NewResponse(out), nil
}

// GetIssuanceStatus is not available. Inji Certify reports no state of a
// staged offer.
func (s *Service) GetIssuanceStatus(
	context.Context, *connect.Request[backendv1.GetIssuanceStatusRequest],
) (*connect.Response[backendv1.GetIssuanceStatusResponse], error) {
	return nil, unimplemented(
		"Inji Certify reports no offer state; read the record in the issued credentials service")
}

// Revoke is not available. The status list services of VCA own the
// status bits (ADR-018, ADR-019).
func (s *Service) Revoke(
	context.Context, *connect.Request[backendv1.RevokeRequest],
) (*connect.Response[backendv1.RevokeResponse], error) {
	return nil, unimplemented(
		"Inji Certify has no revocation API; call the status list service that owns the list")
}

// GetIssuerMetadata returns the OID4VCI issuer metadata of Inji Certify.
func (s *Service) GetIssuerMetadata(
	ctx context.Context, _ *connect.Request[backendv1.GetIssuerMetadataRequest],
) (*connect.Response[backendv1.GetIssuerMetadataResponse], error) {
	if s.certify == nil {
		return nil, unimplemented("this adapter has no Inji Certify URL, so it has no issuer metadata")
	}
	meta, err := s.certify.Metadata(ctx)
	if err != nil {
		return nil, failed("read the issuer metadata", err)
	}
	return connect.NewResponse(&backendv1.GetIssuerMetadataResponse{
		Issuer:         meta.CredentialIssuer,
		MetadataJson:   string(meta.Raw),
		Configurations: configurations(meta),
	}), nil
}

// ListCredentialTypes returns one page of the Inji catalogue.
func (s *Service) ListCredentialTypes(
	ctx context.Context, req *connect.Request[backendv1.ListCredentialTypesRequest],
) (*connect.Response[backendv1.ListCredentialTypesResponse], error) {
	if s.certify == nil {
		return nil, unimplemented("this adapter has no Inji Certify URL, so it has no credential catalogue")
	}
	meta, err := s.certify.Metadata(ctx)
	if err != nil {
		return nil, failed("read the issuer metadata", err)
	}
	all := configurations(meta)
	size := int(req.Msg.GetPage().GetPageSize())
	if size <= 0 || size > s.pageSizeMax {
		size = s.pageSizeMax
	}
	start := 0
	if token := req.Msg.GetPage().GetPageToken(); token != "" {
		if n, perr := parseToken(token); perr == nil {
			start = n
		}
	}
	page := &commonv1.PageResult{TotalSize: int64(len(all))}
	if start >= len(all) {
		return connect.NewResponse(&backendv1.ListCredentialTypesResponse{Page: page}), nil
	}
	end := start + size
	if end < len(all) {
		page.NextPageToken = fmt.Sprintf("%d", end)
	} else {
		end = len(all)
	}
	return connect.NewResponse(&backendv1.ListCredentialTypesResponse{
		Configurations: all[start:end],
		Page:           page,
	}), nil
}

// parseToken reads a page token.
func parseToken(token string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(token, "%d", &n); err != nil || n < 0 {
		return 0, errors.New("service: bad page token")
	}
	return n, nil
}

// toInt32 converts n to int32. A value out of range clamps to the limit.
func toInt32(n int64) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < math.MinInt32 {
		return math.MinInt32
	}
	return int32(n)
}
