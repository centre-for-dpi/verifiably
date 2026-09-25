// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// Session callbacks of the walt.id issuer (P6-W5).
//
// walt.id 0.18.2 posts each event of an issuance session to the URL of
// the header statusCallbackUri of the issue request: {"id": session,
// "type": event, "data": {...}}. The events are
// resolved_credential_offer, requested_token, jwt_issue, sdjwt_issue,
// generated_mdoc, and issuance_status with the status SUCCESSFUL,
// UNSUCCESSFUL, or EXPIRED.
//
// The callback URL is the internal URL of the adapter on the compose
// network, so no public route leads to it (ADR-047). Its path carries
// the offer id and a random token of 128 bits for that offer only. The
// adapter keeps the SHA-256 of the token and compares in constant time.
//
//	POST /callbacks/issuance/{offer}/{token}

// CallbackPrefix is the path of the callback routes.
const CallbackPrefix = "/callbacks/issuance/"

// maxCallbackBytes caps one callback body. An mdoc in hex fits.
const maxCallbackBytes = 1 << 20

// offerRecord is the state of one offer that walt.id reports on.
type offerRecord struct {
	TokenHash  string    `json:"token_hash"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
	ClaimedAt  time.Time `json:"claimed_at,omitempty"`
	Format     string    `json:"format,omitempty"`
	Credential string    `json:"credential,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// The states of an offer record.
const (
	offerPending = "pending"
	offerIssued  = "issued"
	offerFailed  = "failed"
	offerExpired = "expired"
)

// offerKey returns the store key of one offer record.
func offerKey(id string) string { return "offer/" + storeSafe(id) }

// hashToken returns the stored form of a callback token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// randomText returns n random bytes as base64url.
func randomText(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// callbacks reports whether walt.id reports the sessions of this
// adapter.
func (s *Service) callbacks() bool { return s.callbackURL != "" && s.client.HasIssuer() }

// newCallback makes the offer id, the callback URL, and the record of a
// new offer. Without a callback URL it returns empty values.
func (s *Service) newCallback(ctx context.Context) (string, string, error) {
	if !s.callbacks() {
		return "", "", nil
	}
	id, err := randomText(16)
	if err != nil {
		return "", "", err
	}
	token, err := randomText(16)
	if err != nil {
		return "", "", err
	}
	if err := s.putOffer(ctx, id, offerRecord{TokenHash: hashToken(token), State: offerPending, CreatedAt: s.now().UTC()}); err != nil {
		return "", "", err
	}
	return id, s.callbackURL + CallbackPrefix + url.PathEscape(id) + "/" + url.PathEscape(token), nil
}

// putOffer stores one offer record.
func (s *Service) putOffer(ctx context.Context, id string, rec offerRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.store.Put(ctx, offerKey(id), raw)
}

// getOffer reads one offer record.
func (s *Service) getOffer(ctx context.Context, id string) (offerRecord, error) {
	raw, err := s.store.Get(ctx, offerKey(id))
	if err != nil {
		return offerRecord{}, err
	}
	var rec offerRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return offerRecord{}, err
	}
	return rec, nil
}

// callbackEvent is the body walt.id posts.
type callbackEvent struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Data struct {
		JWT    string `json:"jwt"`
		SDJWT  string `json:"sdjwt"`
		Mdoc   string `json:"mdoc"`
		Status string `json:"status"`
		Reason string `json:"reason"`
	} `json:"data"`
}

// CallbackHandler serves the callback routes. An unknown offer or a
// wrong token answers 404, so a caller learns nothing about the offers.
func (s *Service) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, CallbackPrefix)
		id, token, split := strings.Cut(rest, "/")
		if !ok || !split || r.Method != http.MethodPost || !s.callbacks() {
			http.NotFound(w, r)
			return
		}
		rec, err := s.getOffer(r.Context(), id)
		if err != nil || subtle.ConstantTimeCompare([]byte(rec.TokenHash), []byte(hashToken(token))) != 1 {
			http.NotFound(w, r)
			return
		}
		var ev callbackEvent
		if err := json.NewDecoder(io.LimitReader(r.Body, maxCallbackBytes)).Decode(&ev); err != nil {
			http.Error(w, "the callback is not JSON", http.StatusBadRequest)
			return
		}
		if err := s.putOffer(r.Context(), id, s.apply(rec, ev)); err != nil {
			http.Error(w, "the adapter did not keep the event", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// apply moves an offer record by one event. An issued credential stays
// issued whatever comes after it.
func (s *Service) apply(rec offerRecord, ev callbackEvent) offerRecord {
	if rec.State == offerIssued {
		return rec
	}
	issued := func(format, credential string) offerRecord {
		rec.State, rec.Format, rec.Credential, rec.ClaimedAt, rec.Error = offerIssued, format, credential, s.now().UTC(), ""
		return rec
	}
	switch ev.Type {
	case "jwt_issue":
		return issued("jwt_vc_json", ev.Data.JWT)
	case "sdjwt_issue":
		return issued("vc+sd-jwt", ev.Data.SDJWT)
	case "generated_mdoc":
		return issued("mso_mdoc", ev.Data.Mdoc)
	case "issuance_status":
		switch ev.Data.Status {
		case "SUCCESSFUL":
			return issued(rec.Format, rec.Credential)
		case "UNSUCCESSFUL":
			rec.State, rec.Error = offerFailed, ev.Data.Reason
		case "EXPIRED":
			rec.State = offerExpired
		}
	}
	return rec
}

// GetIssuanceStatus reports the state of one offer from the callbacks of
// walt.id.
func (s *Service) GetIssuanceStatus(
	ctx context.Context, req *connect.Request[backendv1.GetIssuanceStatusRequest],
) (*connect.Response[backendv1.GetIssuanceStatusResponse], error) {
	if !s.callbacks() {
		return nil, unimplemented("the adapter learns the issuance state from walt.id callbacks; set VCA_WALTID_CALLBACK_URL")
	}
	rec, err := s.getOffer(ctx, req.Msg.GetOfferId())
	if errors.Is(err, store.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("the adapter made no offer %q", req.Msg.GetOfferId()))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &backendv1.GetIssuanceStatusResponse{State: backendv1.GetIssuanceStatusResponse_STATE_PENDING, Error: rec.Error}
	switch rec.State {
	case offerIssued:
		out.State, out.ClaimedAt = backendv1.GetIssuanceStatusResponse_STATE_ISSUED, timestamp(rec.ClaimedAt)
		if rec.Credential != "" {
			out.Credential = &commonv1.Credential{Format: contractFormat(rec.Format), Payload: []byte(rec.Credential)}
		}
	case offerFailed:
		out.State = backendv1.GetIssuanceStatusResponse_STATE_FAILED
	case offerExpired:
		out.State = backendv1.GetIssuanceStatusResponse_STATE_EXPIRED
	}
	return connect.NewResponse(out), nil
}
