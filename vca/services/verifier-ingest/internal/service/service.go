// SPDX-License-Identifier: Apache-2.0

// Package service implements vca.ingest.v1.IngestService (ADR-023).
// Every carrier decodes to one RawPresentation with the pure decoders of
// core/ingest. The OID4VP RPCs create a transaction, serve a signed
// request object, and take the answer of the wallet.
package service

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/ingest"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1/ingestv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/oid4vp"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// RequestPath is the path prefix of a served request object.
const RequestPath = "/oid4vp/request/"

// ResponsePath is the direct post endpoint wallets answer to.
const ResponsePath = "/oid4vp/response"

// Options configure the service.
type Options struct {
	// Store keeps the transactions.
	Store *txn.Store
	// Discovery reads a presentation template. Nil refuses a request
	// that names a template.
	Discovery discoveryv1connect.DiscoveryServiceClient
	// Fetcher reads a request object from an allowed host.
	Fetcher oid4vp.Fetcher
	// SigningKey signs the request object.
	SigningKey crypto.PrivateKey
	// KeyID is the kid header of the request object.
	KeyID string
	// BaseURL is the public root of the service.
	BaseURL string
	// ClientID is the OID4VP client identifier of the verifier.
	ClientID string
	// RequestTTL is how long a request works.
	RequestTTL time.Duration
	// MaxInputBytes caps one ingestion.
	MaxInputBytes int
	// XML is the default XML configuration.
	XML ingest.XMLConfig
	// RedirectURI is the URI the wallet opens after a direct post.
	RedirectURI string
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Service is the IngestService handler. It also satisfies the client
// interface, so the pages call it in process.
type Service struct {
	ingestv1connect.UnimplementedIngestServiceHandler
	opts Options
}

var _ ingestv1connect.IngestServiceClient = (*Service)(nil)

// New builds the service.
func New(opts Options) (*Service, error) {
	if opts.Store == nil {
		return nil, errors.New("service: a transaction store is required")
	}
	if opts.SigningKey == nil {
		return nil, errors.New("service: a signing key is required")
	}
	if opts.RequestTTL <= 0 {
		opts.RequestTTL = 5 * time.Minute
	}
	if opts.MaxInputBytes <= 0 {
		opts.MaxInputBytes = ingest.MaxInputBytes
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Service{opts: opts}, nil
}

// Ready reports whether the service can take traffic.
func (s *Service) Ready() bool { return s.opts.Store != nil }

// Store returns the transaction store, so the HTTP handlers read it.
func (s *Service) Store() *txn.Store { return s.opts.Store }

// Ingest decodes bytes of one carrier into a raw presentation.
func (s *Service) Ingest(ctx context.Context, req *connect.Request[ingestv1.IngestRequest]) (*connect.Response[ingestv1.IngestResponse], error) {
	opts := ingest.Options{
		Carrier:   CarrierOf(req.Msg.GetCarrier()),
		MediaType: req.Msg.GetMediaType(),
		XML:       s.xmlConfig(req.Msg.GetXml()),
		MaxBytes:  s.opts.MaxInputBytes,
	}
	res, err := ingest.Decode(req.Msg.GetPayload(), opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if res.Carrier == ingest.CarrierOID4VPRequest {
		if resolved, ok := s.resolveRequest(ctx, res); ok {
			res = resolved
		}
	}
	ref, err := txn.NewID()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&ingestv1.IngestResponse{
		Presentation: ToProto(res, ref, "", s.opts.Now()),
		Steps:        res.Steps,
	}), nil
}

// resolveRequest reads the request object of a request URI. The fetch is
// allowlisted and size limited (ADR-023 decision 5). A failure keeps the
// parameters the decoder already found.
func (s *Service) resolveRequest(ctx context.Context, res ingest.Result) (ingest.Result, bool) {
	params := map[string]string{}
	if err := unmarshalParams(res.Payload, &params); err != nil {
		return res, false
	}
	uri := params["request_uri"]
	if uri == "" {
		return res, false
	}
	token, err := s.opts.Fetcher.Fetch(ctx, uri)
	if err != nil {
		return res, false
	}
	claims, err := oid4vp.ReadRequestObject(token)
	if err != nil {
		return res, false
	}
	payload, err := marshalClaims(claims)
	if err != nil {
		return res, false
	}
	res.Payload = payload
	res.Steps = append(res.Steps, "request_uri", "jwt")
	return res, true
}

// xmlConfig returns the XML configuration of a request, or the default.
func (s *Service) xmlConfig(m *ingestv1.XmlConfig) ingest.XMLConfig {
	if m == nil || strings.TrimSpace(m.GetXpath()) == "" {
		return s.opts.XML
	}
	cfg := ingest.XMLConfig{Path: m.GetXpath(), Namespaces: m.GetNamespaces()}
	switch m.GetEncoding() {
	case ingestv1.XmlConfig_ENCODING_BASE64:
		cfg.Encoding = ingest.XMLBase64
	default:
		cfg.Encoding = ingest.XMLText
	}
	return cfg
}

// CreateOid4vpRequest starts a transaction and returns the request URI.
func (s *Service) CreateOid4VpRequest(ctx context.Context, req *connect.Request[ingestv1.CreateOid4VpRequestRequest]) (*connect.Response[ingestv1.CreateOid4VpRequestResponse], error) {
	mode, err := oid4vp.ParseResponseMode(req.Msg.GetResponseMode())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	query, version, err := s.query(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	id, err := txn.NewID()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	nonce, err := txn.NewID()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	state, err := txn.NewID()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	now := s.opts.Now()
	record := txn.Transaction{
		ID: id, Nonce: nonce, StateParam: state,
		TemplateID: req.Msg.GetTemplateId(), TemplateVersion: version,
		DCQL: query, ResponseMode: mode, State: txn.StatePending,
		CreatedAt: now, ExpiresAt: now.Add(s.opts.RequestTTL),
	}
	if err := s.opts.Store.Put(ctx, record); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	requestURI := s.opts.BaseURL + RequestPath + id
	return connect.NewResponse(&ingestv1.CreateOid4VpRequestResponse{
		TransactionId: id,
		RequestUri:    requestURI,
		QrPayload:     oid4vp.AuthorizeURL(oid4vp.DefaultScheme, s.opts.ClientID, requestURI),
		Nonce:         nonce,
		ExpiresAt:     timestamppb.New(record.ExpiresAt),
	}), nil
}

// query returns the DCQL of a request and the template version it used.
func (s *Service) query(ctx context.Context, msg *ingestv1.CreateOid4VpRequestRequest) (string, int32, error) {
	if raw := strings.TrimSpace(msg.GetDcql()); raw != "" {
		if err := checkQuery(raw); err != nil {
			return "", 0, connect.NewError(connect.CodeInvalidArgument, err)
		}
		return raw, 0, nil
	}
	id := strings.TrimSpace(msg.GetTemplateId())
	if id == "" {
		return "", 0, connect.NewError(connect.CodeInvalidArgument, errors.New("service: the request names no template and carries no query"))
	}
	if s.opts.Discovery == nil {
		return "", 0, connect.NewError(connect.CodeFailedPrecondition, errors.New("service: no discovery service is configured, so a template cannot be read"))
	}
	resp, err := s.opts.Discovery.GetTemplate(ctx, connect.NewRequest(&discoveryv1.GetTemplateRequest{
		Id: id, Version: msg.GetTemplateVersion(),
	}))
	if err != nil {
		return "", 0, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("service: read the template %q: %w", id, err))
	}
	return resp.Msg.GetTemplate().GetDcql(), resp.Msg.GetTemplate().GetVersion(), nil
}

// ReceiveDirectPost takes the answer of a wallet.
func (s *Service) ReceiveDirectPost(ctx context.Context, req *connect.Request[ingestv1.ReceiveDirectPostRequest]) (*connect.Response[ingestv1.ReceiveDirectPostResponse], error) {
	record, err := s.opts.Store.FindByState(ctx, req.Msg.GetState())
	if errors.Is(err, txn.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	now := s.opts.Now()
	if record.Expired(now) {
		record.State = txn.StateExpired
		if putErr := s.opts.Store.Put(ctx, record); putErr != nil {
			return nil, connect.NewError(connect.CodeInternal, putErr)
		}
		return nil, connect.NewError(connect.CodeDeadlineExceeded, fmt.Errorf("service: the request of transaction %q expired", record.ID))
	}
	if reason := strings.TrimSpace(req.Msg.GetError()); reason != "" {
		record.State, record.Error, record.AnsweredAt = txn.StateRefused, reason, now
		if putErr := s.opts.Store.Put(ctx, record); putErr != nil {
			return nil, connect.NewError(connect.CodeInternal, putErr)
		}
		return connect.NewResponse(&ingestv1.ReceiveDirectPostResponse{RedirectUri: s.opts.RedirectURI}), nil
	}
	token := strings.TrimSpace(req.Msg.GetVpToken())
	if token == "" {
		token = strings.TrimSpace(req.Msg.GetResponseJwt())
	}
	if token == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("service: the answer carries no vp_token"))
	}
	res, err := ingest.Decode([]byte(token), ingest.Options{
		Carrier: ingest.CarrierOID4VPResponse, MaxBytes: s.opts.MaxInputBytes,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	record.State, record.AnsweredAt = txn.StateReceived, now
	record.Presentation = ToRecord(res, record.ID, record.Nonce, now)
	if err := s.opts.Store.Put(ctx, record); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&ingestv1.ReceiveDirectPostResponse{
		Presentation: RecordToProto(record.Presentation, record.ID),
		RedirectUri:  s.opts.RedirectURI,
	}), nil
}

// GetTransaction returns the state of one transaction.
func (s *Service) GetTransaction(ctx context.Context, req *connect.Request[ingestv1.GetTransactionRequest]) (*connect.Response[ingestv1.GetTransactionResponse], error) {
	record, err := s.opts.Store.Get(ctx, req.Msg.GetTransactionId())
	if errors.Is(err, txn.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&ingestv1.GetTransactionResponse{
		State:           txn.ProtoState(record.StateAt(s.opts.Now())),
		Presentation:    RecordToProto(record.Presentation, record.ID),
		TemplateId:      record.TemplateID,
		TemplateVersion: record.TemplateVersion,
	}), nil
}

// RequestObject returns the signed request object of one transaction.
// The HTTP handler at GET /oid4vp/request/{id} serves it.
func (s *Service) RequestObject(ctx context.Context, id string) (string, error) {
	record, err := s.opts.Store.Get(ctx, id)
	if err != nil {
		return "", err
	}
	now := s.opts.Now()
	if record.Expired(now) {
		return "", fmt.Errorf("%w: the request of transaction %q expired", txn.ErrNotFound, id)
	}
	request := oid4vp.Request{
		ClientID:     s.opts.ClientID,
		ResponseURI:  s.opts.BaseURL + ResponsePath,
		ResponseMode: record.ResponseMode,
		Nonce:        record.Nonce,
		State:        record.StateParam,
		DCQL:         record.DCQL,
		IssuedAt:     record.CreatedAt,
		ExpiresAt:    record.ExpiresAt,
	}
	return request.Sign(s.opts.SigningKey, s.opts.KeyID)
}

// FormatName returns the format identifier of a core format.
func FormatName(f vc.Format) string {
	switch f {
	case vc.FormatSDJWT:
		return "dc+sd-jwt"
	case vc.FormatJWT:
		return "jwt_vc_json"
	case vc.FormatJSONLD:
		return "ldp_vc"
	case vc.FormatMdoc:
		return "mso_mdoc"
	case vc.FormatJSON:
		return "json"
	}
	return ""
}

// ProtoFormat returns the proto format of a format identifier.
func ProtoFormat(name string) commonv1.Format {
	switch name {
	case "vc+sd-jwt":
		return commonv1.Format_FORMAT_VC_SD_JWT
	case "dc+sd-jwt":
		return commonv1.Format_FORMAT_DC_SD_JWT
	case "jwt_vc_json":
		return commonv1.Format_FORMAT_JWT_VC_JSON
	case "ldp_vc":
		return commonv1.Format_FORMAT_LDP_VC
	case "mso_mdoc":
		return commonv1.Format_FORMAT_MSO_MDOC
	}
	return commonv1.Format_FORMAT_UNSPECIFIED
}

// CarrierOf returns the core carrier of a proto carrier.
func CarrierOf(c ingestv1.Carrier) ingest.Carrier {
	switch c {
	case ingestv1.Carrier_CARRIER_OID4VP:
		return ingest.CarrierOID4VPResponse
	case ingestv1.Carrier_CARRIER_IMAGE:
		return ingest.CarrierImage
	case ingestv1.Carrier_CARRIER_PDF:
		return ingest.CarrierPDF
	case ingestv1.Carrier_CARRIER_XML:
		return ingest.CarrierXML
	case ingestv1.Carrier_CARRIER_JSON:
		return ingest.CarrierJSON
	case ingestv1.Carrier_CARRIER_QR:
		return ingest.CarrierQR
	case ingestv1.Carrier_CARRIER_QR_CLAIM169:
		return ingest.CarrierClaim169
	}
	return ingest.CarrierUnknown
}

// ProtoCarrier returns the proto carrier of a core carrier. The proto
// has one value for both OID4VP directions.
func ProtoCarrier(c ingest.Carrier) ingestv1.Carrier {
	switch c {
	case ingest.CarrierOID4VPRequest, ingest.CarrierOID4VPResponse:
		return ingestv1.Carrier_CARRIER_OID4VP
	case ingest.CarrierImage:
		return ingestv1.Carrier_CARRIER_IMAGE
	case ingest.CarrierPDF:
		return ingestv1.Carrier_CARRIER_PDF
	case ingest.CarrierXML:
		return ingestv1.Carrier_CARRIER_XML
	case ingest.CarrierJSON:
		return ingestv1.Carrier_CARRIER_JSON
	case ingest.CarrierQR:
		return ingestv1.Carrier_CARRIER_QR
	case ingest.CarrierClaim169:
		return ingestv1.Carrier_CARRIER_QR_CLAIM169
	}
	return ingestv1.Carrier_CARRIER_UNSPECIFIED
}

// ProtoDetected returns the proto detected type of a core type.
func ProtoDetected(d ingest.DetectedType) ingestv1.DetectedType {
	switch d {
	case ingest.TypeCredential:
		return ingestv1.DetectedType_DETECTED_TYPE_CREDENTIAL
	case ingest.TypePresentation, ingest.TypeRequest:
		return ingestv1.DetectedType_DETECTED_TYPE_PRESENTATION
	case ingest.TypeCWTClaim169:
		return ingestv1.DetectedType_DETECTED_TYPE_CWT_CLAIM169
	case ingest.TypePixelPass:
		return ingestv1.DetectedType_DETECTED_TYPE_PIXELPASS
	}
	return ingestv1.DetectedType_DETECTED_TYPE_UNKNOWN
}

// ToRecord turns a decoder result into the stored presentation.
func ToRecord(res ingest.Result, ref, nonce string, now time.Time) *txn.Presentation {
	out := &txn.Presentation{
		Ref: ref, Carrier: string(res.Carrier), Format: FormatName(res.Format),
		Payload: res.Payload, DetectedType: string(res.Detected), KeyBinding: res.KeyBinding,
		Nonce: nonce, InputHash: res.InputHash, ReceivedAt: now,
	}
	for _, c := range res.Credentials {
		out.Credentials = append(out.Credentials, txn.Credential{Format: FormatName(c.Format), Payload: c.Payload})
	}
	return out
}

// ToProto turns a decoder result into the proto message.
func ToProto(res ingest.Result, ref, nonce string, now time.Time) *ingestv1.RawPresentation {
	out := &ingestv1.RawPresentation{
		Ref:          ref,
		Carrier:      ProtoCarrier(res.Carrier),
		Format:       ProtoFormat(FormatName(res.Format)),
		Payload:      res.Payload,
		DetectedType: ProtoDetected(res.Detected),
		Nonce:        nonce,
		KeyBinding:   res.KeyBinding,
		ReceivedAt:   timestamppb.New(now),
		InputHash:    res.InputHash,
	}
	for _, c := range res.Credentials {
		out.Credentials = append(out.Credentials, &commonv1.Credential{
			Format: ProtoFormat(FormatName(c.Format)), Payload: c.Payload,
		})
	}
	return out
}

// RecordToProto turns a stored presentation into the proto message.
func RecordToProto(p *txn.Presentation, transactionID string) *ingestv1.RawPresentation {
	if p == nil {
		return nil
	}
	out := &ingestv1.RawPresentation{
		Ref:           p.Ref,
		Carrier:       ProtoCarrier(ingest.Carrier(p.Carrier)),
		Format:        ProtoFormat(p.Format),
		Payload:       p.Payload,
		DetectedType:  ProtoDetected(ingest.DetectedType(p.DetectedType)),
		TransactionId: transactionID,
		Nonce:         p.Nonce,
		KeyBinding:    p.KeyBinding,
		ReceivedAt:    timestamppb.New(p.ReceivedAt),
		InputHash:     p.InputHash,
	}
	for _, c := range p.Credentials {
		out.Credentials = append(out.Credentials, &commonv1.Credential{Format: ProtoFormat(c.Format), Payload: c.Payload})
	}
	return out
}
