// SPDX-License-Identifier: Apache-2.0

// Package txn holds the OID4VP transaction record and its store
// (ADR-023 decision 5). A transaction lives from the moment the verifier
// creates a request until the wallet answers or the request expires.
package txn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// ErrNotFound reports that the store holds no such transaction.
var ErrNotFound = errors.New("txn: not found")

// Prefix of every transaction key.
const Prefix = "transactions/"

// State names the phase of a transaction.
type State string

const (
	// StatePending means no wallet has answered yet.
	StatePending State = "pending"
	// StateReceived means the wallet answered.
	StateReceived State = "received"
	// StateRefused means the wallet refused.
	StateRefused State = "refused"
	// StateExpired means the request expired.
	StateExpired State = "expired"
)

// Transaction is one OID4VP exchange.
type Transaction struct {
	// ID names the transaction. It is also the path of the request URI.
	ID string `json:"id"`
	// Nonce is the value the wallet must bind its answer to.
	Nonce string `json:"nonce"`
	// StateParam is the state parameter of the request.
	StateParam string `json:"state"`
	// TemplateID is the presentation template of the request.
	TemplateID string `json:"template_id,omitempty"`
	// TemplateVersion is the template version.
	TemplateVersion int32 `json:"template_version,omitempty"`
	// DCQL is the query the wallet receives, as a JSON string.
	DCQL string `json:"dcql"`
	// ResponseMode is direct_post or direct_post.jwt.
	ResponseMode string `json:"response_mode"`
	// State is the phase of the transaction.
	State State `json:"phase"`
	// CreatedAt is the creation time.
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt is the time the request stops working.
	ExpiresAt time.Time `json:"expires_at"`
	// AnsweredAt is the time the wallet answered.
	AnsweredAt time.Time `json:"answered_at,omitempty"`
	// Presentation is the normalised answer of the wallet.
	Presentation *Presentation `json:"presentation,omitempty"`
	// Error is the error parameter of a refused answer, or why the
	// service could not evaluate or store the answer.
	Error string `json:"error,omitempty"`
	// RequestURI is the URI the wallet opens. The QR code carries it.
	RequestURI string `json:"request_uri,omitempty"`
	// PolicySetID is the policy set of the template. The evaluation of
	// the answer uses it. Empty uses the default set.
	PolicySetID string `json:"policy_set_id,omitempty"`
	// ResultID is the id of the stored verification result.
	ResultID string `json:"result_id,omitempty"`
	// Stack is the pair of the stack verifier that answers the request.
	// Empty means the VCA verifier.
	Stack string `json:"stack,omitempty"`
	// Adapter is the internal URL of the adapter of the stack.
	Adapter string `json:"adapter,omitempty"`
	// StackState is the state GetResult of the adapter takes.
	StackState string `json:"stack_state,omitempty"`
	// StackChecks are the checks the stack ran on the answer.
	StackChecks []StackCheck `json:"stack_checks,omitempty"`
	// StackName is the display name of the stack verifier, as its
	// adapter reports it.
	StackName string `json:"stack_name,omitempty"`
	// Verdict is the verdict of the evaluation of the answer, as the
	// number of vca.common.v1.Verdict. Zero until the evaluation.
	Verdict int32 `json:"verdict,omitempty"`
}

// StackCheck is one check a stack verifier ran.
type StackCheck struct {
	// Name is the name of the check at the stack.
	Name string `json:"name"`
	// Passed is true when the check passed.
	Passed bool `json:"passed"`
	// Reason is the text of the stack when the check failed.
	Reason string `json:"reason,omitempty"`
}

// Presentation is the stored form of a decoded wallet answer.
type Presentation struct {
	// Ref is the reference the results service stores.
	Ref string `json:"ref"`
	// Carrier is the carrier name.
	Carrier string `json:"carrier"`
	// Format is the credential format identifier.
	Format string `json:"format,omitempty"`
	// Payload is the decoded payload.
	Payload []byte `json:"payload,omitempty"`
	// DetectedType is what the decoder found.
	DetectedType string `json:"detected_type"`
	// Credentials holds the credentials of the payload.
	Credentials []Credential `json:"credentials,omitempty"`
	// KeyBinding is the holder key binding JWT, when the answer has one.
	KeyBinding string `json:"key_binding,omitempty"`
	// Nonce is the nonce of the request.
	Nonce string `json:"nonce,omitempty"`
	// InputHash is the hex SHA-256 of the input bytes.
	InputHash string `json:"input_hash,omitempty"`
	// ReceivedAt is the time of ingestion.
	ReceivedAt time.Time `json:"received_at"`
}

// Credential is one credential of a presentation.
type Credential struct {
	// Format is the wire format identifier.
	Format string `json:"format,omitempty"`
	// Payload is the credential bytes.
	Payload []byte `json:"payload"`
}

// Expired reports whether the request stopped working at now.
func (t Transaction) Expired(now time.Time) bool {
	return t.State == StatePending && !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt)
}

// StateAt returns the state of the transaction at now.
func (t Transaction) StateAt(now time.Time) State {
	if t.Expired(now) {
		return StateExpired
	}
	return t.State
}

// ProtoState returns the proto state of a state name.
func ProtoState(s State) ingestv1.GetTransactionResponse_State {
	switch s {
	case StatePending:
		return ingestv1.GetTransactionResponse_STATE_PENDING
	case StateReceived:
		return ingestv1.GetTransactionResponse_STATE_RECEIVED
	case StateRefused:
		return ingestv1.GetTransactionResponse_STATE_REFUSED
	case StateExpired:
		return ingestv1.GetTransactionResponse_STATE_EXPIRED
	}
	return ingestv1.GetTransactionResponse_STATE_UNSPECIFIED
}

// NewID returns a random identifier of 22 URL safe characters.
func NewID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("txn: read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ValidID reports whether the id is a safe store key segment.
func ValidID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// Store keeps transactions in the shared key value store.
type Store struct {
	kv store.KeyValue
}

// NewStore wraps a key value backend.
func NewStore(kv store.KeyValue) (*Store, error) {
	if kv == nil {
		return nil, errors.New("txn: a key value backend is required")
	}
	return &Store{kv: kv}, nil
}

// key returns the store key of one transaction id.
func key(id string) string { return Prefix + id }

// Put writes one transaction.
func (s *Store) Put(ctx context.Context, t Transaction) error {
	if !ValidID(t.ID) {
		return fmt.Errorf("txn: the transaction id %q is not valid", t.ID)
	}
	// The record holds strings, numbers, bytes, and times, so it writes.
	data, ignored := json.Marshal(t)
	_ = ignored
	return s.kv.Put(ctx, key(t.ID), data)
}

// Get reads one transaction.
func (s *Store) Get(ctx context.Context, id string) (Transaction, error) {
	if !ValidID(id) {
		return Transaction{}, fmt.Errorf("%w: the transaction id %q is not valid", ErrNotFound, id)
	}
	data, err := s.kv.Get(ctx, key(id))
	if errors.Is(err, store.ErrNotFound) {
		return Transaction{}, fmt.Errorf("%w: no transaction %q", ErrNotFound, id)
	}
	if err != nil {
		return Transaction{}, err
	}
	var t Transaction
	if err := json.Unmarshal(data, &t); err != nil {
		return Transaction{}, fmt.Errorf("txn: read the transaction: %w", err)
	}
	return t, nil
}

// FindByState returns the transaction with the state parameter. The
// direct post handler uses it, because the wallet sends the state, not
// the id.
func (s *Store) FindByState(ctx context.Context, state string) (Transaction, error) {
	if state == "" {
		return Transaction{}, fmt.Errorf("%w: the response carries no state", ErrNotFound)
	}
	list, err := s.List(ctx)
	if err != nil {
		return Transaction{}, err
	}
	for _, t := range list {
		if t.StateParam == state {
			return t, nil
		}
	}
	return Transaction{}, fmt.Errorf("%w: no transaction has the state %q", ErrNotFound, state)
}

// List returns every transaction, ordered by creation time.
func (s *Store) List(ctx context.Context) ([]Transaction, error) {
	keys, err := s.kv.List(ctx, Prefix)
	if err != nil {
		return nil, err
	}
	out := make([]Transaction, 0, len(keys))
	for _, k := range keys {
		data, err := s.kv.Get(ctx, k)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var t Transaction
		if err := json.Unmarshal(data, &t); err != nil {
			return nil, fmt.Errorf("txn: read the transaction %q: %w", k, err)
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// Prune removes every transaction that ended before the cut time.
func (s *Store) Prune(ctx context.Context, cut time.Time) (int, error) {
	list, err := s.List(ctx)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, t := range list {
		if t.CreatedAt.After(cut) {
			continue
		}
		if err := s.kv.Delete(ctx, key(t.ID)); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
