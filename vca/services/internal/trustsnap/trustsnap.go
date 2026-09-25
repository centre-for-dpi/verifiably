// SPDX-License-Identifier: Apache-2.0

// Package trustsnap is the wire form of the signed trust snapshot that
// ExportSnapshot of the trust registry returns (ADR-041 decision 1). The
// trust registry writes it. The verifier policy service checks it, keeps
// it, and answers trust lookups from it when the registry does not
// answer.
//
// A snapshot holds one list per source: the entries of the registry of
// the deployment first, then the checked copy of each external registry
// with its provenance. The entities use the JSON form of the ETSI list
// of the trust registry.
package trustsnap

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// Type is the typ header of a signed snapshot.
const Type = "trust-snapshot+jwt"

// The role and status words a lookup reads.
const (
	RoleIssuer   = "issuer"
	StatusActive = "active"
)

// ErrExpired reports a snapshot past its exp claim.
var ErrExpired = errors.New("trustsnap: the snapshot expired")

// Claims is the payload of a signed snapshot.
type Claims struct {
	Issuer    string `json:"iss"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Lists     []List `json:"lists"`
}

// List is the entries of one source with its provenance.
type List struct {
	// RegistryID is the id of the external registry. Empty means the
	// registry of the deployment.
	RegistryID string `json:"registry_id,omitempty"`
	// RegistryName is the display name of the external registry.
	RegistryName string `json:"registry_name,omitempty"`
	// ListURL is the URL of the list the entries come from.
	ListURL string `json:"list_url,omitempty"`
	// SignedBy is the key id or the certificate subject that signed the
	// list.
	SignedBy string `json:"signed_by,omitempty"`
	// CheckedAt is the time the registry checked the list signature.
	CheckedAt time.Time `json:"checked_at"`
	// X509Chain holds the PEM anchor certificates of an external
	// registry, when its anchor is a certificate.
	X509Chain string   `json:"x509_chain,omitempty"`
	Entities  []Entity `json:"entities"`
}

// Entity is one trusted entity in the JSON form of the ETSI list.
type Entity struct {
	Name                string     `json:"name,omitempty"`
	Role                string     `json:"role"`
	Identities          []Identity `json:"serviceDigitalIdentities"`
	Status              string     `json:"status"`
	ValidFrom           *time.Time `json:"statusStartingTime,omitempty"`
	ValidUntil          *time.Time `json:"validUntil,omitempty"`
	CredentialTypes     []string   `json:"credentialTypes,omitempty"`
	ServiceEndpoint     string     `json:"serviceEndpoint,omitempty"`
	StatusListEndpoints []string   `json:"statusListEndpoints,omitempty"`
}

// Identity names an entity by DID or by X.509 subject.
type Identity struct {
	DID         string `json:"did,omitempty"`
	X509Subject string `json:"x509SubjectName,omitempty"`
}

// ID returns the identifier of the entity, or an empty string.
func (e Entity) ID() string {
	if len(e.Identities) == 0 {
		return ""
	}
	if e.Identities[0].DID != "" {
		return e.Identities[0].DID
	}
	return e.Identities[0].X509Subject
}

// Verify checks the signature of a snapshot with set, its typ header,
// and its exp claim at now. It returns the claims and the key id.
func Verify(token string, set jose.JWKS, now time.Time) (Claims, string, error) {
	raw, hdr, err := jose.VerifyWithJWKS(token, set, jose.SigningAlgorithms)
	if err != nil {
		return Claims{}, "", fmt.Errorf("trustsnap: %w", err)
	}
	if hdr.Typ != Type {
		return Claims{}, "", fmt.Errorf("trustsnap: typ %q is not %s", hdr.Typ, Type)
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return Claims{}, "", fmt.Errorf("trustsnap: claims: %w", err)
	}
	if c.ExpiresAt == 0 {
		return Claims{}, "", errors.New("trustsnap: the exp claim is missing")
	}
	if now.After(time.Unix(c.ExpiresAt, 0)) {
		return Claims{}, "", ErrExpired
	}
	return c, hdr.Kid, nil
}

// Count returns the number of entities in every list.
func (c Claims) Count() int {
	n := 0
	for _, l := range c.Lists {
		n += len(l.Entities)
	}
	return n
}

// Outcome names the answer of a lookup.
type Outcome int

// The outcomes of a lookup.
const (
	// Unknown means no list names the entity.
	Unknown Outcome = iota
	// Trusted means a list names the entity as an active issuer, valid
	// at the time, for the credential type.
	Trusted
	// Untrusted means a list names the entity, but not as a trusted
	// issuer of the type at the time.
	Untrusted
)

// Answer is the result of a lookup with its provenance.
type Answer struct {
	Outcome      Outcome
	Name         string
	Reason       string
	ListURL      string
	RegistryID   string
	RegistryName string
}

// Lookup answers whether the lists trust the issuer id for
// credentialType at time at. It reads the lists in order. A trusted
// answer wins; otherwise the first untrusted answer.
func (c Claims) Lookup(id, credentialType string, at time.Time) Answer {
	best := Answer{Outcome: Unknown, Reason: "no list in the cached snapshot names the issuer"}
	for _, l := range c.Lists {
		for _, e := range l.Entities {
			if e.ID() != id {
				continue
			}
			a := Answer{Name: e.Name, ListURL: l.ListURL, RegistryID: l.RegistryID, RegistryName: l.RegistryName}
			a.Outcome, a.Reason = judge(e, credentialType, at)
			if a.Outcome == Trusted {
				return a
			}
			if best.Outcome == Unknown {
				best = a
			}
		}
	}
	return best
}

// judge checks one entity the way the trust registry does.
func judge(e Entity, credentialType string, at time.Time) (Outcome, string) {
	switch {
	case e.Role != RoleIssuer:
		return Untrusted, "the entity has the role " + e.Role + ", not issuer"
	case e.Status != StatusActive:
		return Untrusted, "the entry is " + e.Status
	case e.ValidFrom != nil && at.Before(*e.ValidFrom), e.ValidUntil != nil && at.After(*e.ValidUntil):
		return Untrusted, "the entry is not valid at the time of the check"
	case !covers(e.CredentialTypes, credentialType):
		return Untrusted, "the entry does not cover the credential type " + credentialType
	}
	return Trusted, ""
}

// covers reports whether a type list allows credentialType. An empty
// list or an empty type allows every type.
func covers(types []string, credentialType string) bool {
	if credentialType == "" || len(types) == 0 {
		return true
	}
	for _, t := range types {
		if t == credentialType {
			return true
		}
	}
	return false
}

// Issuer is one active issuer with a DID, and where it is listed.
type Issuer struct {
	ID           string
	Name         string
	RegistryID   string
	RegistryName string
	StatusLists  []string
}

// Issuers returns the active issuers with a DID, once each, in list
// order. The trust cache reads their keys and status lists.
func (c Claims) Issuers() []Issuer {
	seen := map[string]bool{}
	var out []Issuer
	for _, l := range c.Lists {
		for _, e := range l.Entities {
			if e.Role != RoleIssuer || e.Status != StatusActive || len(e.Identities) == 0 || e.Identities[0].DID == "" {
				continue
			}
			if seen[e.ID()] {
				continue
			}
			seen[e.ID()] = true
			out = append(out, Issuer{
				ID: e.ID(), Name: e.Name, RegistryID: l.RegistryID, RegistryName: l.RegistryName,
				StatusLists: e.StatusListEndpoints,
			})
		}
	}
	return out
}

// Chain is the anchor certificates of one external registry.
type Chain struct {
	RegistryID   string
	RegistryName string
	PEM          string
}

// Chains returns the X.509 anchor chains of the external registries.
func (c Claims) Chains() []Chain {
	var out []Chain
	for _, l := range c.Lists {
		if l.X509Chain != "" {
			out = append(out, Chain{RegistryID: l.RegistryID, RegistryName: l.RegistryName, PEM: l.X509Chain})
		}
	}
	return out
}
