// SPDX-License-Identifier: Apache-2.0

// Package etsi publishes the trust entries as a List of Trusted Entities
// in the JSON binding of ETSI TS 119 602 V1.1.1 and signs it as a JWS
// (ADR-011 decision 2). The package also imports ETSI TS 119 612 XML
// trusted lists, see xml.go.
//
// Field names follow the data model of TS 119 602: scheme information,
// list issuer, entities with service digital identities, status, and
// validity. The names are plain camelCase JSON members.
package etsi

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
)

// TypeJWS is the typ header of the signed list.
const TypeJWS = "trust-list+jwt"

// Paths of the published files.
const (
	PathJSON = "/trust-list/etsi.json"
	PathJWS  = "/trust-list/etsi.jws"
)

// Content types of the published files.
const (
	ContentTypeJSON = "application/json"
	ContentTypeJWS  = "application/jose"
)

// ListType is the type URI of the list. It marks a VCA list of trusted
// entities in the TS 119 602 data model.
const ListType = "https://github.com/centre-for-dpi/vc-adapters/trust-list/etsi/v1"

// Service status URIs of ETSI TS 119 612 clause 5.5.4.
const (
	StatusGranted   = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
	StatusWithdrawn = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"
)

// List is the List of Trusted Entities.
type List struct {
	SchemeInformation SchemeInformation `json:"schemeInformation"`
	Entities          []Entity          `json:"entities"`
}

// SchemeInformation describes the list and its issuer.
type SchemeInformation struct {
	// Version is the version of this JSON binding. It is 1.
	Version int `json:"version"`
	// SequenceNumber rises with every publication.
	SequenceNumber uint64     `json:"sequenceNumber"`
	Type           string     `json:"type"`
	ListIssuer     ListIssuer `json:"listIssuer"`
	IssueDateTime  time.Time  `json:"issueDateTime"`
	NextUpdate     time.Time  `json:"nextUpdate"`
	// DistributionPoints are the URLs where the list is published.
	DistributionPoints []string `json:"distributionPoints,omitempty"`
}

// ListIssuer identifies the operator of the list.
type ListIssuer struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Territory string `json:"territory,omitempty"`
}

// Entity is one trusted entity.
type Entity struct {
	Name string `json:"name,omitempty"`
	// Role is issuer, holder, or verifier.
	Role                     string            `json:"role"`
	ServiceDigitalIdentities []DigitalIdentity `json:"serviceDigitalIdentities"`
	// Status is active, suspended, or revoked.
	Status string `json:"status"`
	// StatusURI is the ETSI service status URI that matches Status.
	StatusURI string `json:"statusUri"`
	// StatusStartingTime is the start of the validity, when known.
	StatusStartingTime *time.Time `json:"statusStartingTime,omitempty"`
	// ValidUntil is the end of the validity, when known.
	ValidUntil          *time.Time `json:"validUntil,omitempty"`
	CredentialTypes     []string   `json:"credentialTypes,omitempty"`
	ServiceEndpoint     string     `json:"serviceEndpoint,omitempty"`
	StatusListEndpoints []string   `json:"statusListEndpoints,omitempty"`
}

// DigitalIdentity names an entity by DID or by x509 subject.
type DigitalIdentity struct {
	DID             string `json:"did,omitempty"`
	X509SubjectName string `json:"x509SubjectName,omitempty"`
}

// Claims is the payload of the signed list.
type Claims struct {
	Issuer    string `json:"iss"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	List
}

// Build converts the input into a list.
func Build(in publish.Input) List {
	now := in.Now.UTC()
	entities := make([]Entity, 0, len(in.Entries))
	for _, e := range entry.Sorted(in.Entries) {
		entities = append(entities, FromEntry(e))
	}
	return List{
		SchemeInformation: SchemeInformation{
			Version:        1,
			SequenceNumber: in.Sequence,
			Type:           ListType,
			ListIssuer:     ListIssuer{ID: in.Issuer.ID, Name: in.Issuer.Name, Territory: in.Issuer.Territory},
			IssueDateTime:  now,
			NextUpdate:     now.Add(in.TTL),
			DistributionPoints: []string{
				publish.JoinURL(in.BaseURL, PathJWS),
				publish.JoinURL(in.BaseURL, PathJSON),
			},
		},
		Entities: entities,
	}
}

// FromEntry converts one canonical entry to an entity.
func FromEntry(e entry.Entry) Entity {
	ent := Entity{
		Name:                e.DisplayName,
		Role:                string(e.Role),
		Status:              string(e.Status),
		StatusURI:           StatusWithdrawn,
		CredentialTypes:     e.CredentialTypes,
		ServiceEndpoint:     e.ServiceEndpoint,
		StatusListEndpoints: e.StatusListEndpoints,
	}
	if e.Status == entry.StatusActive {
		ent.StatusURI = StatusGranted
	}
	if e.DID != "" {
		ent.ServiceDigitalIdentities = []DigitalIdentity{{DID: e.DID}}
	} else {
		ent.ServiceDigitalIdentities = []DigitalIdentity{{X509SubjectName: e.X509Subject}}
	}
	if !e.ValidFrom.IsZero() {
		t := e.ValidFrom.UTC()
		ent.StatusStartingTime = &t
	}
	if !e.ValidUntil.IsZero() {
		t := e.ValidUntil.UTC()
		ent.ValidUntil = &t
	}
	return ent
}

// ToEntry converts an entity to a canonical entry.
func ToEntry(ent Entity) (entry.Entry, error) {
	if len(ent.ServiceDigitalIdentities) == 0 {
		return entry.Entry{}, errors.New("etsi: entity has no service digital identity")
	}
	id := ent.ServiceDigitalIdentities[0]
	e := entry.Entry{
		DID:                 id.DID,
		X509Subject:         id.X509SubjectName,
		DisplayName:         ent.Name,
		Role:                entry.Role(ent.Role),
		Status:              entry.Status(ent.Status),
		CredentialTypes:     ent.CredentialTypes,
		ServiceEndpoint:     ent.ServiceEndpoint,
		StatusListEndpoints: ent.StatusListEndpoints,
	}
	if ent.StatusStartingTime != nil {
		e.ValidFrom = *ent.StatusStartingTime
	}
	if ent.ValidUntil != nil {
		e.ValidUntil = *ent.ValidUntil
	}
	if err := e.Validate(); err != nil {
		return entry.Entry{}, err
	}
	return e, nil
}

// ToEntries converts every entity. It fails on the first invalid entity.
func ToEntries(entities []Entity) ([]entry.Entry, error) {
	out := make([]entry.Entry, 0, len(entities))
	for i, ent := range entities {
		e, err := ToEntry(ent)
		if err != nil {
			return nil, fmt.Errorf("etsi: entity %d: %w", i, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// Publisher is the etsi method.
type Publisher struct{}

// Method returns etsi.
func (Publisher) Method() string { return publish.MethodEtsi }

// Publish builds the list, signs it, and returns both files.
func (Publisher) Publish(in publish.Input) (publish.Publication, error) {
	if in.TTL <= 0 {
		return publish.Publication{}, errors.New("etsi: ttl must be positive")
	}
	list := Build(in)
	// The list holds only strings, numbers, and times, so Marshal cannot fail.
	body, _ := json.Marshal(list)
	claims := Claims{
		Issuer:    in.Issuer.ID,
		IssuedAt:  list.SchemeInformation.IssueDateTime.Unix(),
		ExpiresAt: list.SchemeInformation.NextUpdate.Unix(),
		List:      list,
	}
	token, err := jose.Sign(in.Signer.Private, in.Signer.ID, TypeJWS, claims)
	if err != nil {
		return publish.Publication{}, err
	}
	return publish.Publication{
		Method: publish.MethodEtsi,
		URL:    publish.JoinURL(in.BaseURL, PathJWS),
		Files: map[string]publish.File{
			PathJSON: {ContentType: ContentTypeJSON, Body: body},
			PathJWS:  {ContentType: ContentTypeJWS, Body: []byte(token)},
		},
		EntryCount:  len(list.Entities),
		PublishedAt: list.SchemeInformation.IssueDateTime,
		KeyID:       in.Signer.ID,
		Sequence:    in.Sequence,
	}, nil
}

// Verify checks the JWS file with the JWKS and returns its entries.
func (Publisher) Verify(files map[string]publish.File, set jose.JWKS, now time.Time) (publish.Verified, error) {
	f, ok := files[PathJWS]
	if !ok {
		return publish.Verified{}, fmt.Errorf("etsi: file %s is missing", PathJWS)
	}
	claims, hdr, err := VerifyJWS(string(f.Body), set, now)
	if err != nil {
		return publish.Verified{}, err
	}
	entries, err := ToEntries(claims.Entities)
	if err != nil {
		return publish.Verified{}, err
	}
	return publish.Verified{
		Entries:   entries,
		Sequence:  claims.SchemeInformation.SequenceNumber,
		KeyID:     hdr.Kid,
		ListURL:   firstOr(claims.SchemeInformation.DistributionPoints, ""),
		IssuedAt:  time.Unix(claims.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	}, nil
}

// VerifyJWS checks the signature, the typ header, and the exp claim.
func VerifyJWS(token string, set jose.JWKS, now time.Time) (Claims, jose.Header, error) {
	raw, hdr, err := jose.VerifyWithJWKS(token, set, jose.SigningAlgorithms)
	if err != nil {
		return Claims{}, hdr, fmt.Errorf("etsi: %w", err)
	}
	if hdr.Typ != TypeJWS {
		return Claims{}, hdr, fmt.Errorf("etsi: typ %q is not %s", hdr.Typ, TypeJWS)
	}
	var claims Claims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return Claims{}, hdr, fmt.Errorf("etsi: claims: %w", err)
	}
	if claims.ExpiresAt == 0 {
		return Claims{}, hdr, errors.New("etsi: exp claim missing")
	}
	if now.After(time.Unix(claims.ExpiresAt, 0)) {
		return Claims{}, hdr, errors.New("etsi: list expired")
	}
	return claims, hdr, nil
}

func firstOr(items []string, fallback string) string {
	if len(items) > 0 {
		return items[0]
	}
	return fallback
}
