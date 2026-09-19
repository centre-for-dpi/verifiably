// SPDX-License-Identifier: Apache-2.0

// Package entry holds the canonical trust entry of the trust registry
// (ADR-011 decision 1). The package is pure. It converts entries to and
// from the proto messages and evaluates trust lookups.
package entry

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
)

// Role names the role of an entity in the ecosystem.
type Role string

// Roles the registry accepts.
const (
	RoleIssuer   Role = "issuer"
	RoleHolder   Role = "holder"
	RoleVerifier Role = "verifier"
)

// Status names the trust state of an entity.
type Status string

// Status values the registry accepts.
const (
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
	StatusRevoked   Status = "revoked"
)

// Outcome names the result of a lookup.
type Outcome string

// Lookup outcomes.
const (
	Trusted   Outcome = "trusted"
	Untrusted Outcome = "untrusted"
	Unknown   Outcome = "unknown"
)

// Source values for provenance.
const (
	SourceAdmin      = "admin"
	SourceEtsiImport = "etsi-import"
)

// x509Prefix marks an x509 subject in an entity id.
const x509Prefix = "x509:"

// Entry is the canonical trust record of one entity.
type Entry struct {
	// DID is set when the entity has a DID. It is empty for x509 entries.
	DID string `json:"did,omitempty"`
	// X509Subject is the subject distinguished name of an ETSI entry.
	X509Subject string `json:"x509_subject,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Role        Role   `json:"role"`
	Status      Status `json:"status"`
	// ValidFrom is zero when the entry is valid from creation.
	ValidFrom time.Time `json:"valid_from,omitempty"`
	// ValidUntil is zero when the entry has no end.
	ValidUntil time.Time `json:"valid_until,omitempty"`
	// CredentialTypes lists the types the entity can issue or request.
	// Empty means every type.
	CredentialTypes     []string  `json:"credential_types,omitempty"`
	ServiceEndpoint     string    `json:"service_endpoint,omitempty"`
	StatusListEndpoints []string  `json:"status_list_endpoints,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
	// Version counts the changes of this entry. The store sets it.
	Version uint64 `json:"version"`
	// Source says who created the entry: admin or etsi-import.
	Source string `json:"source,omitempty"`
}

// ID returns the store key of the entry: the DID, or x509: plus the subject.
func (e Entry) ID() string {
	if e.DID != "" {
		return e.DID
	}
	return x509Prefix + e.X509Subject
}

// IDFromX509 returns the store key of an x509 subject.
func IDFromX509(subject string) string {
	return x509Prefix + subject
}

// Validate checks the entry fields.
func (e Entry) Validate() error {
	if (e.DID == "") == (e.X509Subject == "") {
		return errors.New("entry: set exactly one of did or x509_subject")
	}
	if e.DID != "" && !strings.HasPrefix(e.DID, "did:") {
		return fmt.Errorf("entry: %q is not a DID", e.DID)
	}
	switch e.Role {
	case RoleIssuer, RoleHolder, RoleVerifier:
	default:
		return fmt.Errorf("entry: unknown role %q", e.Role)
	}
	switch e.Status {
	case StatusActive, StatusSuspended, StatusRevoked:
	default:
		return fmt.Errorf("entry: unknown status %q", e.Status)
	}
	if !e.ValidFrom.IsZero() && !e.ValidUntil.IsZero() && e.ValidUntil.Before(e.ValidFrom) {
		return errors.New("entry: valid_until is before valid_from")
	}
	return nil
}

// ValidAt reports whether the validity window covers t.
func (e Entry) ValidAt(t time.Time) bool {
	if !e.ValidFrom.IsZero() && t.Before(e.ValidFrom) {
		return false
	}
	if !e.ValidUntil.IsZero() && t.After(e.ValidUntil) {
		return false
	}
	return true
}

// Covers reports whether the entry allows credentialType.
// An empty type or an empty list matches.
func (e Entry) Covers(credentialType string) bool {
	if credentialType == "" || len(e.CredentialTypes) == 0 {
		return true
	}
	for _, t := range e.CredentialTypes {
		if t == credentialType {
			return true
		}
	}
	return false
}

// Sorted returns a copy of entries ordered by ID.
func Sorted(entries []Entry) []Entry {
	out := make([]Entry, len(entries))
	copy(out, entries)
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Result is the outcome of Evaluate.
type Result struct {
	Outcome Outcome
	// Entry is set when the lookup found the entity.
	Entry *Entry
	// Reason explains an untrusted outcome in Simplified Technical English.
	Reason string
}

// Evaluate finds the entry with id and role and checks it at time at.
func Evaluate(entries []Entry, id string, role Role, credentialType string, at time.Time) Result {
	var found *Entry
	for i := range entries {
		e := entries[i]
		if e.ID() != id {
			continue
		}
		if e.Role == role {
			found = &e
			break
		}
		if found == nil {
			found = &e
		}
	}
	if found == nil {
		return Result{Outcome: Unknown, Reason: "No enabled list names the entity."}
	}
	if found.Role != role {
		return Result{Outcome: Untrusted, Entry: found, Reason: fmt.Sprintf("The entity has the role %s, not %s.", found.Role, role)}
	}
	switch found.Status {
	case StatusSuspended:
		return Result{Outcome: Untrusted, Entry: found, Reason: "The entry is suspended."}
	case StatusRevoked:
		return Result{Outcome: Untrusted, Entry: found, Reason: "The entry is revoked."}
	}
	if !found.ValidAt(at) {
		return Result{Outcome: Untrusted, Entry: found, Reason: "The entry is not valid at the requested time."}
	}
	if !found.Covers(credentialType) {
		return Result{Outcome: Untrusted, Entry: found, Reason: fmt.Sprintf("The entry does not cover the credential type %s.", credentialType)}
	}
	return Result{Outcome: Trusted, Entry: found}
}

// RoleFromProto converts a proto role. Admin and unspecified are not allowed.
func RoleFromProto(r commonv1.Role) (Role, error) {
	switch r {
	case commonv1.Role_ROLE_ISSUER:
		return RoleIssuer, nil
	case commonv1.Role_ROLE_HOLDER:
		return RoleHolder, nil
	case commonv1.Role_ROLE_VERIFIER:
		return RoleVerifier, nil
	}
	return "", fmt.Errorf("entry: role %s is not allowed", r)
}

// RoleToProto converts a role to its proto value.
func RoleToProto(r Role) commonv1.Role {
	switch r {
	case RoleIssuer:
		return commonv1.Role_ROLE_ISSUER
	case RoleHolder:
		return commonv1.Role_ROLE_HOLDER
	case RoleVerifier:
		return commonv1.Role_ROLE_VERIFIER
	}
	return commonv1.Role_ROLE_UNSPECIFIED
}

// StatusFromProto converts a proto status.
func StatusFromProto(s trustv1.Status) (Status, error) {
	switch s {
	case trustv1.Status_STATUS_ACTIVE:
		return StatusActive, nil
	case trustv1.Status_STATUS_SUSPENDED:
		return StatusSuspended, nil
	case trustv1.Status_STATUS_REVOKED:
		return StatusRevoked, nil
	}
	return "", fmt.Errorf("entry: status %s is not allowed", s)
}

// StatusToProto converts a status to its proto value.
func StatusToProto(s Status) trustv1.Status {
	switch s {
	case StatusActive:
		return trustv1.Status_STATUS_ACTIVE
	case StatusSuspended:
		return trustv1.Status_STATUS_SUSPENDED
	case StatusRevoked:
		return trustv1.Status_STATUS_REVOKED
	}
	return trustv1.Status_STATUS_UNSPECIFIED
}

// IDFromProto returns the store key of a proto identifier.
func IDFromProto(id *trustv1.TrustEntry_Identifier) (string, error) {
	switch v := id.GetId().(type) {
	case *trustv1.TrustEntry_Identifier_Did:
		if !strings.HasPrefix(v.Did, "did:") {
			return "", fmt.Errorf("entry: %q is not a DID", v.Did)
		}
		return v.Did, nil
	case *trustv1.TrustEntry_Identifier_X509Subject:
		if v.X509Subject == "" {
			return "", errors.New("entry: x509_subject is empty")
		}
		return IDFromX509(v.X509Subject), nil
	}
	return "", errors.New("entry: identifier is empty")
}

// FromProto converts a proto entry and validates it.
func FromProto(p *trustv1.TrustEntry) (Entry, error) {
	if p == nil {
		return Entry{}, errors.New("entry: entry is empty")
	}
	e := Entry{
		DisplayName:         p.GetDisplayName(),
		CredentialTypes:     p.GetCredentialTypes(),
		ServiceEndpoint:     p.GetServiceEndpoint(),
		StatusListEndpoints: p.GetStatusListEndpoints(),
	}
	switch v := p.GetIdentifier().GetId().(type) {
	case *trustv1.TrustEntry_Identifier_Did:
		e.DID = v.Did
	case *trustv1.TrustEntry_Identifier_X509Subject:
		e.X509Subject = v.X509Subject
	}
	role, err := RoleFromProto(p.GetRole())
	if err != nil {
		return Entry{}, err
	}
	e.Role = role
	status, err := StatusFromProto(p.GetStatus())
	if err != nil {
		return Entry{}, err
	}
	e.Status = status
	if from := p.GetValidity().GetValidFrom(); from != nil {
		e.ValidFrom = from.AsTime()
	}
	if until := p.GetValidity().GetValidUntil(); until != nil {
		e.ValidUntil = until.AsTime()
	}
	if err := e.Validate(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// ToProto converts an entry to its proto message.
func ToProto(e Entry) *trustv1.TrustEntry {
	p := &trustv1.TrustEntry{
		Identifier:          &trustv1.TrustEntry_Identifier{},
		DisplayName:         e.DisplayName,
		Role:                RoleToProto(e.Role),
		Status:              StatusToProto(e.Status),
		CredentialTypes:     e.CredentialTypes,
		ServiceEndpoint:     e.ServiceEndpoint,
		StatusListEndpoints: e.StatusListEndpoints,
	}
	if e.DID != "" {
		p.Identifier.Id = &trustv1.TrustEntry_Identifier_Did{Did: e.DID}
	} else {
		p.Identifier.Id = &trustv1.TrustEntry_Identifier_X509Subject{X509Subject: e.X509Subject}
	}
	if !e.ValidFrom.IsZero() || !e.ValidUntil.IsZero() {
		p.Validity = &commonv1.ValidityWindow{}
		if !e.ValidFrom.IsZero() {
			p.Validity.ValidFrom = timestamppb.New(e.ValidFrom)
		}
		if !e.ValidUntil.IsZero() {
			p.Validity.ValidUntil = timestamppb.New(e.ValidUntil)
		}
	}
	if !e.UpdatedAt.IsZero() {
		p.UpdatedAt = timestamppb.New(e.UpdatedAt)
	}
	return p
}
