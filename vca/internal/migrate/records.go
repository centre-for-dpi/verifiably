// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/hashchain"
)

// The types below mirror the stored records of the services. The
// migrator writes the store documents of a service without importing
// its internal packages. A change of a service record needs the same
// change here, and the tests of this package check the field names.
//
// See services/issued-credentials/internal/record,
// services/internal/status/lists, and
// services/trust-registry/internal/entry.

// Status names the status of an issued credential.
type Status string

// The status values of the issued-credentials service.
const (
	StatusActive  Status = "active"
	StatusRevoked Status = "revoked"
)

// Binding points at the status list entry of a credential. It mirrors
// record.Binding.
type Binding struct {
	Kind       string `json:"kind,omitempty"`
	ListID     string `json:"list_id,omitempty"`
	Index      int64  `json:"index,omitempty"`
	PublishURL string `json:"publish_url,omitempty"`
}

// IssuedRecord is one record of the issued-credentials log. It mirrors
// record.Record.
type IssuedRecord struct {
	ID               string            `json:"id"`
	SchemaID         string            `json:"schema_id"`
	SchemaVersion    int               `json:"schema_version"`
	SubjectRef       string            `json:"subject_ref"`
	Format           string            `json:"format,omitempty"`
	Binding          Binding           `json:"binding,omitempty"`
	Status           Status            `json:"status"`
	DPG              string            `json:"dpg,omitempty"`
	IssuedAt         time.Time         `json:"issued_at"`
	SearchableClaims map[string]string `json:"searchable_claims,omitempty"`
}

// IssuedChange is one status change of the issued-credentials log. It
// mirrors record.Change.
type IssuedChange struct {
	RecordID  string    `json:"record_id"`
	Status    Status    `json:"status"`
	Reason    string    `json:"reason"`
	ChangedAt time.Time `json:"changed_at"`
}

// EventKind names what an event of the log does.
type EventKind string

// The event kinds of the issued-credentials log.
const (
	EventIssue  EventKind = "issue"
	EventStatus EventKind = "status"
)

// IssuedEvent is one body of the hash chain. It mirrors record.Event.
type IssuedEvent struct {
	Kind   EventKind     `json:"kind"`
	Record *IssuedRecord `json:"record,omitempty"`
	Change *IssuedChange `json:"change,omitempty"`
}

// IssuedDocument is the saved log of the issued-credentials service. It
// mirrors the document type of that service store.
type IssuedDocument struct {
	Entries []hashchain.Entry `json:"entries"`
}

// ListRecord is one status list of a status service. It mirrors
// lists.Record.
type ListRecord struct {
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	Purpose        string    `json:"purpose"`
	Bits           int       `json:"bits"`
	Size           int       `json:"size"`
	IssuerSlug     string    `json:"issuer_slug"`
	CreatedAt      time.Time `json:"created_at"`
	Allocated      []byte    `json:"allocated"`
	AllocatedCount int       `json:"allocated_count"`
	Values         []byte    `json:"values"`
}

// TrustEntry is one entry of the trust registry. It mirrors entry.Entry.
type TrustEntry struct {
	DID                 string    `json:"did,omitempty"`
	DisplayName         string    `json:"display_name,omitempty"`
	Role                string    `json:"role"`
	Status              string    `json:"status"`
	ValidFrom           time.Time `json:"valid_from,omitempty"`
	ValidUntil          time.Time `json:"valid_until,omitempty"`
	CredentialTypes     []string  `json:"credential_types,omitempty"`
	ServiceEndpoint     string    `json:"service_endpoint,omitempty"`
	StatusListEndpoints []string  `json:"status_list_endpoints,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
	Version             uint64    `json:"version"`
	Source              string    `json:"source,omitempty"`
}

// TrustDocument is the saved state of the trust-registry service. It
// mirrors the document type of that service store.
type TrustDocument struct {
	Revision uint64                `json:"revision"`
	Entries  map[string]TrustEntry `json:"entries"`
}

// RoleIssuer is the trust registry role of every migrated entry.
const RoleIssuer = "issuer"

// TrustStatusActive is the trust status of every migrated entry.
const TrustStatusActive = "active"

// SourceAdmin marks an entry an administrator owns.
const SourceAdmin = "admin"

// PurposeRevocation is the purpose of every migrated status list. The
// legacy lists carry revocation only.
const PurposeRevocation = "revocation"

// decodeRawBytes reads the base64url form the legacy store writes.
func decodeRawBytes(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode base64url: %w", err)
	}
	return raw, nil
}
