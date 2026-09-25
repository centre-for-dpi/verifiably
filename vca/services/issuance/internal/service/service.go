// SPDX-License-Identifier: Apache-2.0

// Package service serves vca.issuance.v1 (ADR-016). One issue request
// takes these steps:
//
//  1. Read the schema and check the claims against it.
//  2. Allocate the status list entry of the credential.
//  3. Call the DPG adapter the configuration names (ADR-016 decision 1).
//  4. Deliver the result over the chosen channel (ADR-016 decision 5).
//  5. Write the record to the issued credentials service (ADR-017).
//
// The service offers only what the adapter can do. It reads that from
// the capability answer of the adapter (ADR-016 decision 6).
package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuancev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/clients"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/delivery"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/offers"
)

// Options configure New.
type Options struct {
	// Capabilities reads what the DPG adapter can do.
	Capabilities *clients.CapabilityCache
	// Issuer drives the DPG adapter.
	Issuer clients.Issuer
	// Schemas reads a published schema. Nil turns the claim check off.
	Schemas clients.Schemas
	// Status allocates a status list entry. Nil makes every credential
	// not revocable.
	Status clients.Status
	// Recorder writes the issued record.
	Recorder clients.Recorder
	// Rows reads the rows of a data source job. Nil rejects a batch with
	// a source job id.
	Rows clients.Rows
	// Delivery sends a message to a citizen.
	Delivery *delivery.Registry
	// Store keeps the offers and the batch jobs.
	Store *offers.Store
	// AdapterName names the DPG in the issued record.
	AdapterName string
	// PublicURL is the address a citizen reaches this service on.
	PublicURL string
	// DocumentTitle is the default heading of a document.
	DocumentTitle string
	// DocumentIssuer is the line above the heading of a document.
	DocumentIssuer string
	// DocumentFooter is the line at the foot of a document.
	DocumentFooter string
	// OfferTTL is the life of an offer and of a document.
	OfferTTL time.Duration
	// BatchWorkers is the number of rows the service issues at once.
	BatchWorkers int
	// PageSizeMax caps a list page.
	PageSizeMax int
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// NewID returns a new identifier. Nil uses crypto/rand.
	NewID func() string
	// Log receives the warnings. Nil means slog.Default.
	Log *slog.Logger
	// Audit keeps one event for each issue, alone or in a batch
	// (ADR-039 decision 1). Nil keeps the events in memory.
	Audit *auditlog.Log
}

// Name is the service name that every audit event carries.
const Name = "issuance"

// ActionIssue is the audit action of one issue.
const ActionIssue = "issuance.Issue"

// Service implements vca.issuance.v1.IssuanceService.
type Service struct {
	opts Options
}

// New returns the service.
func New(opts Options) (*Service, error) {
	if opts.Capabilities == nil {
		return nil, errors.New("service: no capability cache")
	}
	if opts.Issuer == nil {
		return nil, errors.New("service: no DPG adapter client")
	}
	if opts.Store == nil {
		return nil, errors.New("service: no store")
	}
	if opts.Delivery == nil {
		return nil, errors.New("service: no delivery registry")
	}
	if opts.Recorder == nil {
		return nil, errors.New("service: no recorder")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.NewID == nil {
		opts.NewID = offers.NewID
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.OfferTTL <= 0 {
		opts.OfferTTL = 24 * time.Hour
	}
	if opts.BatchWorkers <= 0 {
		opts.BatchWorkers = 4
	}
	if opts.PageSizeMax <= 0 {
		opts.PageSizeMax = 50
	}
	if opts.DocumentTitle == "" {
		opts.DocumentTitle = "Credential"
	}
	opts.PublicURL = strings.TrimRight(opts.PublicURL, "/")
	if opts.Audit == nil {
		// A memory store with a clock cannot fail to open.
		opts.Audit = anyval.Must(auditlog.New(store.Memory(), opts.Now))
	}
	return &Service{opts: opts}, nil
}

// Audit returns the audit store of the service.
func (s *Service) Audit() *auditlog.Log { return s.opts.Audit }

// Ready reports whether the service can take traffic.
func (s *Service) Ready() bool { return s != nil }

// badRequest returns an invalid argument error.
func badRequest(text string) *connect.Error {
	return connect.NewError(connect.CodeInvalidArgument, errors.New(text))
}

// internal returns an internal error.
func internal(action string, err error) *connect.Error {
	return connect.NewError(connect.CodeInternal, fmt.Errorf("%s: %w", action, err))
}

// hashOf returns the hex SHA-256 hash of the bytes.
func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// timestamp returns a protobuf time or nil for the zero time.
func timestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// channelName maps a contract channel onto a delivery channel.
func channelName(c backendv1.Channel) delivery.Channel {
	switch c {
	case backendv1.Channel_CHANNEL_PDF:
		return delivery.ChannelPDF
	case backendv1.Channel_CHANNEL_EMAIL:
		return delivery.ChannelEmail
	case backendv1.Channel_CHANNEL_SMS:
		return delivery.ChannelSMS
	case backendv1.Channel_CHANNEL_LINK:
		return delivery.ChannelLink
	default:
		return delivery.ChannelOID4VCI
	}
}

// stateOf maps a stored state onto the contract state.
func stateOf(s offers.State) issuancev1.Offer_State {
	switch s {
	case offers.StateDelivered:
		return issuancev1.Offer_STATE_DELIVERED
	case offers.StateDeferred:
		return issuancev1.Offer_STATE_DEFERRED
	case offers.StateExpired:
		return issuancev1.Offer_STATE_EXPIRED
	case offers.StateFailed:
		return issuancev1.Offer_STATE_FAILED
	default:
		return issuancev1.Offer_STATE_PENDING
	}
}

// view maps a stored offer onto the contract message.
func view(o offers.Offer) *issuancev1.Offer {
	out := &issuancev1.Offer{
		Id:            o.ID,
		Channel:       backendv1.Channel(backendv1.Channel_value[o.Channel]),
		State:         stateOf(o.State),
		OfferUri:      o.OfferURI,
		Pin:           o.Pin,
		PdfRef:        o.PdfRef,
		Link:          o.Link,
		RecordId:      o.RecordID,
		TransactionId: o.TransactionID,
		SchemaId:      o.SchemaID,
		SchemaVersion: o.SchemaVersion,
		CreatedAt:     timestamp(o.CreatedAt),
		ExpiresAt:     timestamp(o.ExpiresAt),
		ClaimedAt:     timestamp(o.ClaimedAt),
	}
	if len(o.Credential) > 0 {
		out.Credential = &commonv1.Credential{
			Format:  commonv1.Format(o.Format),
			Payload: o.Credential,
		}
	}
	return out
}

// label returns a one line name of a subject for the operator.
func label(claims map[string]string) string {
	for _, name := range []string{
		"fullName", "full_name", "holder", "name", "given_name", "firstName",
	} {
		if v := strings.TrimSpace(claims[name]); v != "" {
			return v
		}
	}
	best := ""
	for name, value := range claims {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if best == "" || name < best {
			best = name
		}
	}
	if best == "" {
		return "(empty row)"
	}
	return strings.TrimSpace(claims[best])
}

// formatOf reads the format of the request, of the schema, or of the
// adapter, in that order.
func formatOf(requested commonv1.Format, schemaFormats []commonv1.Format, caps clients.Capabilities) commonv1.Format {
	if requested != commonv1.Format_FORMAT_UNSPECIFIED {
		return requested
	}
	for _, f := range schemaFormats {
		if caps.SupportsFormat(f) {
			return f
		}
	}
	return caps.FirstFormat()
}
