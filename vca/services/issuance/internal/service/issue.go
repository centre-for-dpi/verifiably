// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/jsonschema"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	statusv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/clients"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/delivery"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/offers"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/render"
)

// DocumentPath is the endpoint that serves a rendered document.
const DocumentPath = "/issuance/pdf/"

// request is one issuance the service works on.
type request struct {
	schemaID      string
	schemaVersion int32
	claims        map[string]string
	subject       *commonv1.Subject
	format        commonv1.Format
	channel       backendv1.Channel
	delivery      *issuancev1.Delivery
	validity      *commonv1.ValidityWindow
	statusPurpose string
	holderProof   string
}

// Issue issues one credential to one subject.
func (s *Service) Issue(
	ctx context.Context, req *connect.Request[issuancev1.IssueRequest],
) (*connect.Response[issuancev1.IssueResponse], error) {
	msg := req.Msg
	claims, err := readClaims(msg.GetSubjectData())
	if err != nil {
		return nil, err
	}
	offer, err := s.issueOne(ctx, request{
		schemaID:      msg.GetSchemaId(),
		schemaVersion: msg.GetSchemaVersion(),
		claims:        claims,
		subject:       msg.GetSubject(),
		format:        msg.GetFormat(),
		channel:       msg.GetDelivery().GetChannel(),
		delivery:      msg.GetDelivery(),
		validity:      msg.GetValidity(),
		statusPurpose: msg.GetStatusPurpose(),
		holderProof:   msg.GetHolderKeyProof(),
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&issuancev1.IssueResponse{Offer: view(offer)}), nil
}

// readClaims reads the subject data of a request.
func readClaims(raw string) (map[string]string, error) {
	claims := map[string]string{}
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil, badRequest("the request needs subject_data")
	}
	var values map[string]any
	if err := json.Unmarshal([]byte(text), &values); err != nil {
		return nil, badRequest("subject_data is not a JSON object")
	}
	for name, value := range values {
		claims[name] = fmt.Sprint(value)
	}
	if len(claims) == 0 {
		return nil, badRequest("subject_data names no claim")
	}
	return claims, nil
}

// issueOne runs the whole issuance of one subject.
func (s *Service) issueOne(ctx context.Context, r request) (offers.Offer, error) {
	if strings.TrimSpace(r.schemaID) == "" {
		return offers.Offer{}, badRequest("the request needs a schema_id")
	}
	caps, err := s.opts.Capabilities.Get(ctx)
	if err != nil {
		return offers.Offer{}, connect.NewError(connect.CodeUnavailable, err)
	}
	schema, err := s.schema(ctx, r.schemaID, r.schemaVersion)
	if err != nil {
		return offers.Offer{}, err
	}
	if err := checkClaims(schema, r.claims); err != nil {
		return offers.Offer{}, err
	}
	format := formatOf(r.format, schema.GetFormats(), caps)
	if !caps.SupportsFormat(format) {
		return offers.Offer{}, badRequest(fmt.Sprintf(
			"the DPG adapter cannot issue the format %s", format))
	}
	channel := r.channel
	if channel == backendv1.Channel_CHANNEL_UNSPECIFIED {
		channel = backendv1.Channel_CHANNEL_OID4VCI_PREAUTH
	}
	if err := s.checkChannel(caps, channel); err != nil {
		return offers.Offer{}, err
	}
	binding, err := s.allocateStatus(ctx, r.statusPurpose, format)
	if err != nil {
		return offers.Offer{}, err
	}
	spec := &backendv1.IssueSpec{
		ConfigurationId: configurationOf(schema),
		Format:          format,
		SubjectData:     mustJSON(r.claims),
		Subject:         r.subject,
		Validity:        r.validity,
		Status:          binding,
		HolderKeyProof:  r.holderProof,
	}
	now := s.opts.Now().UTC()
	offer := offers.Offer{
		ID:            s.opts.NewID(),
		Channel:       channel.String(),
		State:         offers.StatePending,
		SchemaID:      schema.GetId(),
		SchemaVersion: schema.GetVersion(),
		SubjectRef:    r.subject.GetRef(),
		Format:        int32(format),
		Claims:        searchable(schema, r.claims),
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.opts.OfferTTL),
	}
	r.channel = channel
	switch channel {
	case backendv1.Channel_CHANNEL_PDF, backendv1.Channel_CHANNEL_LINK:
		err = s.issueDocument(ctx, &offer, spec, schema, r)
	default:
		err = s.issueOffer(ctx, &offer, spec, channel, r)
	}
	if err != nil {
		return offers.Offer{}, err
	}
	if rerr := s.record(ctx, &offer, binding, r.validity); rerr != nil {
		s.opts.Log.Warn("the issued record did not reach the log", "error", rerr)
	}
	if perr := s.opts.Store.PutOffer(ctx, offer); perr != nil {
		return offers.Offer{}, internal("store the offer", perr)
	}
	return offer, nil
}

// checkChannel reports whether the deployment can serve the channel.
//
// The document channel and the link channel need a credential from the
// adapter. The email channel and the SMS channel carry an offer, so they
// need the pre-authorized channel of the adapter.
func (s *Service) checkChannel(caps clients.Capabilities, channel backendv1.Channel) error {
	switch channel {
	case backendv1.Channel_CHANNEL_PDF, backendv1.Channel_CHANNEL_LINK:
		if !caps.SupportsChannel(backendv1.Channel_CHANNEL_PDF) {
			return badRequest("the DPG adapter cannot return a credential, so the document channel is off")
		}
	case backendv1.Channel_CHANNEL_EMAIL, backendv1.Channel_CHANNEL_SMS,
		backendv1.Channel_CHANNEL_OID4VCI_PREAUTH:
		if !caps.SupportsChannel(backendv1.Channel_CHANNEL_OID4VCI_PREAUTH) {
			return badRequest("the DPG adapter cannot build a pre-authorized offer")
		}
	case backendv1.Channel_CHANNEL_OID4VCI_AUTHCODE:
		if !caps.SupportsChannel(channel) {
			return badRequest("the DPG adapter cannot build an authorization code offer")
		}
	default:
		return badRequest(fmt.Sprintf("the channel %s is not a delivery channel", channel))
	}
	return nil
}

// issueOffer asks the adapter for an OID4VCI offer and delivers it.
func (s *Service) issueOffer(ctx context.Context, offer *offers.Offer,
	spec *backendv1.IssueSpec, channel backendv1.Channel, r request,
) error {
	adapterChannel := channel
	switch channel {
	case backendv1.Channel_CHANNEL_EMAIL, backendv1.Channel_CHANNEL_SMS:
		adapterChannel = backendv1.Channel_CHANNEL_OID4VCI_PREAUTH
	}
	resp, err := s.opts.Issuer.CreateOffer(ctx, connect.NewRequest(&backendv1.CreateOfferRequest{
		Spec: spec, Channel: adapterChannel,
	}))
	if err != nil {
		offer.State = offers.StateFailed
		offer.Error = err.Error()
		return connect.NewError(connect.CodeOf(err), fmt.Errorf("create the offer: %w", err))
	}
	offer.OfferURI = resp.Msg.GetOfferUri()
	offer.Pin = resp.Msg.GetPin()
	if expires := resp.Msg.GetExpiresAt(); expires != nil {
		offer.ExpiresAt = expires.AsTime()
	}
	if channel == backendv1.Channel_CHANNEL_EMAIL || channel == backendv1.Channel_CHANNEL_SMS {
		message := delivery.Message{
			Channel: channelName(channel),
			Address: addressOf(r.delivery, channel),
			Locale:  r.delivery.GetLocale(),
			Subject: "Your credential is ready",
			Body:    offerText(offer.OfferURI, offer.Pin),
			Link:    offer.OfferURI,
		}
		if derr := s.opts.Delivery.Send(ctx, message); derr != nil {
			offer.State = offers.StateFailed
			offer.Error = derr.Error()
			return deliveryError(derr)
		}
		offer.State = offers.StateDelivered
	}
	return nil
}

// issueDocument asks the adapter for a credential and renders the page.
func (s *Service) issueDocument(ctx context.Context, offer *offers.Offer,
	spec *backendv1.IssueSpec, schema *schemav1.Schema, r request,
) error {
	resp, err := s.opts.Issuer.Issue(ctx, connect.NewRequest(&backendv1.IssueRequest{Spec: spec}))
	if err != nil {
		offer.State = offers.StateFailed
		offer.Error = err.Error()
		return connect.NewError(connect.CodeOf(err), fmt.Errorf("ask for the credential: %w", err))
	}
	credential := resp.Msg.GetCredential()
	payload, perr := render.CredentialPayload(credential.GetPayload())
	if perr != nil {
		return internal("build the QR payload", perr)
	}
	document, rerr := render.Render(render.Document{
		Title:     displayName(schema, s.opts.DocumentTitle),
		Issuer:    s.opts.DocumentIssuer,
		Claims:    r.claims,
		Order:     schema.GetSdClaims(),
		Note:      "Scan the QR code to check this credential.",
		Footer:    s.opts.DocumentFooter,
		QRPayload: payload,
		IssuedAt:  s.opts.Now().UTC(),
	})
	if rerr != nil {
		return internal("render the document", rerr)
	}
	ref := s.opts.NewID()
	if serr := s.opts.Store.PutDocument(ctx, ref, document); serr != nil {
		return internal("store the document", serr)
	}
	offer.PdfRef = ref
	offer.Credential = credential.GetPayload()
	offer.Format = int32(credential.GetFormat())
	offer.State = offers.StateDelivered
	offer.ClaimedAt = s.opts.Now().UTC()
	if s.opts.PublicURL != "" {
		offer.Link = s.opts.PublicURL + DocumentPath + ref
	}
	if r.channel == backendv1.Channel_CHANNEL_LINK ||
		r.delivery.GetEmail() != "" || r.delivery.GetPhone() != "" {
		message := delivery.Message{
			Channel:        channelName(r.channel),
			Address:        addressOf(r.delivery, r.channel),
			Locale:         r.delivery.GetLocale(),
			Subject:        "Your credential document",
			Body:           "Your credential document is ready.",
			Link:           offer.Link,
			Attachment:     document,
			AttachmentName: "credential.pdf",
		}
		if derr := s.opts.Delivery.Send(ctx, message); derr != nil {
			return deliveryError(derr)
		}
	}
	return nil
}

// deliveryError maps a delivery failure onto a Connect error.
func deliveryError(err error) *connect.Error {
	if errors.Is(err, delivery.ErrNotConfigured) {
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
	if errors.Is(err, delivery.ErrNoAddress) {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return internal("deliver the message", err)
}

// addressOf returns the address of the delivery of a channel.
func addressOf(d *issuancev1.Delivery, channel backendv1.Channel) string {
	if channel == backendv1.Channel_CHANNEL_SMS {
		return d.GetPhone()
	}
	return d.GetEmail()
}

// offerText is the message body of an offer.
func offerText(offerURI, pin string) string {
	var b strings.Builder
	b.WriteString("Open this address in your wallet to get your credential:\n")
	b.WriteString(offerURI)
	if pin != "" {
		b.WriteString("\n\nThe wallet asks for this code: ")
		b.WriteString(pin)
	}
	return b.String()
}

// schema reads one schema version. A deployment without a schema
// registry gets an empty schema and no claim check.
func (s *Service) schema(ctx context.Context, id string, version int32) (*schemav1.Schema, error) {
	if s.opts.Schemas == nil {
		return &schemav1.Schema{Id: id, Version: version}, nil
	}
	resp, err := s.opts.Schemas.Get(ctx, connect.NewRequest(&schemav1.GetRequest{
		Id: id, Version: version,
	}))
	if err != nil {
		return nil, connect.NewError(connect.CodeOf(err), fmt.Errorf("read the schema: %w", err))
	}
	schema := resp.Msg.GetSchema()
	if schema == nil {
		return nil, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("the schema registry has no schema %q", id))
	}
	return schema, nil
}

// checkClaims checks the claims against the JSON Schema of the version.
func checkClaims(schema *schemav1.Schema, claims map[string]string) error {
	raw := strings.TrimSpace(schema.GetJsonSchema())
	if raw == "" {
		return nil
	}
	parsed, err := jsonschema.Parse([]byte(raw))
	if err != nil {
		return internal("read the JSON Schema of the version", err)
	}
	instance := make(map[string]any, len(claims))
	for name, value := range claims {
		instance[name] = value
	}
	problems := parsed.Validate(instance)
	if len(problems) == 0 {
		return nil
	}
	texts := make([]string, 0, len(problems))
	for _, p := range problems {
		texts = append(texts, p.Error())
	}
	return badRequest("the claims do not match the schema: " + strings.Join(texts, "; "))
}

// configurationOf returns the credential configuration id of a schema.
func configurationOf(schema *schemav1.Schema) string {
	if id := strings.TrimSpace(schema.GetType()); id != "" {
		return id
	}
	return schema.GetId()
}

// displayName returns the heading of the document of a schema.
func displayName(schema *schemav1.Schema, fallback string) string {
	for _, d := range schema.GetDisplay() {
		if name := strings.TrimSpace(d.GetName()); name != "" {
			return name
		}
	}
	if t := strings.TrimSpace(schema.GetType()); t != "" {
		return render.Humanise(lastPart(t))
	}
	return fallback
}

// lastPart returns the part of a value after its last slash.
func lastPart(value string) string {
	if i := strings.LastIndex(value, "/"); i >= 0 && i+1 < len(value) {
		return value[i+1:]
	}
	return value
}

// searchable returns the claims the schema marks as searchable
// (ADR-017 decision 2). Every other claim stays out of the record.
func searchable(schema *schemav1.Schema, claims map[string]string) map[string]string {
	names := schema.GetSearchableClaims()
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]string, len(names))
	for _, name := range names {
		if value, ok := claims[name]; ok {
			out[name] = value
		}
	}
	return out
}

// allocateStatus reserves the status list entry of a credential. The
// purpose none makes the credential not revocable.
func (s *Service) allocateStatus(ctx context.Context, purpose string, format commonv1.Format) (
	*backendv1.StatusListBinding, error,
) {
	name := strings.ToLower(strings.TrimSpace(purpose))
	if name == "none" {
		return nil, nil
	}
	if s.opts.Status == nil {
		s.opts.Log.Warn("no status service, so the credential is not revocable")
		return nil, nil
	}
	kind := statusv1.Kind_KIND_BITSTRING
	bindingKind := backendv1.StatusListBinding_KIND_BITSTRING
	if format == commonv1.Format_FORMAT_VC_SD_JWT || format == commonv1.Format_FORMAT_DC_SD_JWT {
		kind = statusv1.Kind_KIND_TOKEN
		bindingKind = backendv1.StatusListBinding_KIND_TOKEN
	}
	statusPurpose := statusv1.Purpose_PURPOSE_REVOCATION
	switch name {
	case "", "revocation":
	case "suspension":
		statusPurpose = statusv1.Purpose_PURPOSE_SUSPENSION
	case "message":
		statusPurpose = statusv1.Purpose_PURPOSE_MESSAGE
	default:
		return nil, badRequest(fmt.Sprintf("the status purpose %q is not known", purpose))
	}
	resp, err := s.opts.Status.AllocateIndex(ctx, connect.NewRequest(&statusv1.AllocateIndexRequest{
		Purpose: statusPurpose, Kind: kind,
	}))
	if err != nil {
		return nil, connect.NewError(connect.CodeOf(err),
			fmt.Errorf("allocate the status index: %w", err))
	}
	return &backendv1.StatusListBinding{
		Kind:       bindingKind,
		ListId:     resp.Msg.GetListId(),
		Index:      resp.Msg.GetIndex(),
		PublishUrl: resp.Msg.GetUrl(),
	}, nil
}

// record writes the issued record and stores its id on the offer.
func (s *Service) record(ctx context.Context, offer *offers.Offer,
	binding *backendv1.StatusListBinding, validity *commonv1.ValidityWindow,
) error {
	payload := offer.Credential
	if len(payload) == 0 {
		payload = []byte(offer.OfferURI)
	}
	id, err := s.opts.Recorder.Record(ctx, &issuedv1.IssuedRecord{
		SchemaId:         offer.SchemaID,
		SchemaVersion:    offer.SchemaVersion,
		Subject:          &commonv1.Subject{Ref: offer.SubjectRef},
		Format:           commonv1.Format(offer.Format),
		StatusBinding:    binding,
		Status:           issuedv1.Status_STATUS_ACTIVE,
		Dpg:              s.opts.AdapterName,
		IssuedAt:         timestamp(offer.CreatedAt),
		Hash:             hashOf(payload),
		SearchableClaims: offer.Claims,
		Validity:         validity,
		OfferId:          offer.ID,
	})
	if err != nil {
		return err
	}
	offer.RecordID = id
	return nil
}

// mustJSON returns the JSON form of the claims. The map holds strings
// only, so the call never fails.
func mustJSON(claims map[string]string) string {
	raw, _ := json.Marshal(claims)
	return string(raw)
}

// Document returns the bytes of one rendered document. The plain HTTP
// handler of the service serves them (ADR-003 decision 7).
func (s *Service) Document(ctx context.Context, ref string) ([]byte, bool) {
	document, err := s.opts.Store.Document(ctx, ref)
	if err != nil {
		return nil, false
	}
	return document, true
}

// GetOffer returns the state of one offer.
func (s *Service) GetOffer(
	ctx context.Context, req *connect.Request[issuancev1.GetOfferRequest],
) (*connect.Response[issuancev1.GetOfferResponse], error) {
	id := strings.TrimSpace(req.Msg.GetId())
	if id == "" {
		return nil, badRequest("the request needs an id")
	}
	offer, err := s.opts.Store.Offer(ctx, id)
	if errors.Is(err, offers.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	if err != nil {
		return nil, internal("read the offer", err)
	}
	return connect.NewResponse(&issuancev1.GetOfferResponse{Offer: view(offer)}), nil
}

// Deferred completes a deferred issuance when the DPG supports it.
func (s *Service) Deferred(
	ctx context.Context, req *connect.Request[issuancev1.DeferredRequest],
) (*connect.Response[issuancev1.DeferredResponse], error) {
	id := strings.TrimSpace(req.Msg.GetOfferId())
	if id == "" {
		return nil, badRequest("the request needs an offer_id")
	}
	offer, err := s.opts.Store.Offer(ctx, id)
	if errors.Is(err, offers.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	if err != nil {
		return nil, internal("read the offer", err)
	}
	resp, serr := s.opts.Issuer.GetIssuanceStatus(ctx,
		connect.NewRequest(&backendv1.GetIssuanceStatusRequest{
			OfferId: offer.ID, TransactionId: offer.TransactionID,
		}))
	if serr != nil {
		return nil, connect.NewError(connect.CodeOf(serr),
			fmt.Errorf("read the issuance state: %w", serr))
	}
	applyState(&offer, resp.Msg, s.opts.Now().UTC())
	if perr := s.opts.Store.PutOffer(ctx, offer); perr != nil {
		return nil, internal("store the offer", perr)
	}
	return connect.NewResponse(&issuancev1.DeferredResponse{Offer: view(offer)}), nil
}

// applyState copies the answer of the adapter onto the offer.
func applyState(offer *offers.Offer, msg *backendv1.GetIssuanceStatusResponse, now time.Time) {
	switch msg.GetState() {
	case backendv1.GetIssuanceStatusResponse_STATE_ISSUED:
		offer.State = offers.StateDelivered
		offer.ClaimedAt = now
		if claimed := msg.GetClaimedAt(); claimed != nil {
			offer.ClaimedAt = claimed.AsTime()
		}
		if credential := msg.GetCredential(); credential != nil {
			offer.Credential = credential.GetPayload()
			offer.Format = int32(credential.GetFormat())
		}
	case backendv1.GetIssuanceStatusResponse_STATE_DEFERRED:
		offer.State = offers.StateDeferred
	case backendv1.GetIssuanceStatusResponse_STATE_EXPIRED:
		offer.State = offers.StateExpired
	case backendv1.GetIssuanceStatusResponse_STATE_FAILED:
		offer.State = offers.StateFailed
		offer.Error = msg.GetError()
	default:
		offer.State = offers.StatePending
	}
	if expires := msg.GetExpiresAt(); expires != nil {
		offer.ExpiresAt = expires.AsTime()
	}
}
