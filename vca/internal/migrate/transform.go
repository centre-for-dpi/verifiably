// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/hashchain"
)

// Options steer the transform.
type Options struct {
	// Salt keys the one way subject reference (ADR-017 decision 2). It
	// is required. Keep the same salt in the issued-credentials service.
	Salt string
	// KeepClaims names the legacy subject fields the export keeps as
	// searchable claims. The export keeps no other claim.
	KeepClaims []string
	// IssuerDID names the issuer that signs the migrated status lists.
	// Empty uses the default issuer of the status service.
	IssuerDID string
	// StatusBaseURL is the public root URL of the status services. The
	// export writes a binding URL when it is not empty.
	StatusBaseURL string
	// Reason explains the migrated status changes.
	Reason string
	// Now is the time the export stamps on the trust entries.
	Now time.Time
}

// DefaultReason explains a status change the migrator wrote.
const DefaultReason = "migrated from verifiably-go"

// StatusPathPrefix is the URL path of a list under the base URL.
const StatusPathPrefix = "/status/"

// check fills the defaults of o and reports a wrong option.
func (o Options) check() (Options, error) {
	if strings.TrimSpace(o.Salt) == "" {
		return Options{}, fmt.Errorf("%w: the subject salt is empty", ErrOptions)
	}
	if o.Reason == "" {
		o.Reason = DefaultReason
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	o.Now = o.Now.UTC()
	o.StatusBaseURL = strings.TrimRight(o.StatusBaseURL, "/")
	return o, nil
}

// SubjectRef returns the salted, one way reference of subject. It is the
// same HMAC-SHA256 the issued-credentials service uses.
func SubjectRef(salt, subject string) string {
	m := hmac.New(sha256.New, []byte(salt))
	m.Write([]byte(subject))
	return hex.EncodeToString(m.Sum(nil))
}

// SubjectOf returns the legacy identifier of the credential subject. It
// takes the first value that is not empty: the "id" subject field, the
// holder hint, the owner key, then the credential id.
func SubjectOf(c LegacyIssued) string {
	for _, v := range []string{c.SubjectFields["id"], c.HolderHint, c.OwnerKey, c.ID} {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// Keep returns the claims of c whose names are in allowed. A short allow
// list keeps the export free of personal data.
func Keep(claims map[string]string, allowed []string) map[string]string {
	if len(claims) == 0 || len(allowed) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, name := range allowed {
		if v, ok := claims[name]; ok {
			out[name] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// IssuedSchemaID returns the schema id of a legacy credential. The
// schema name is the fallback, because early entries carry no id.
func IssuedSchemaID(c LegacyIssued) string {
	if strings.TrimSpace(c.SchemaID) != "" {
		return c.SchemaID
	}
	return strings.TrimSpace(c.SchemaName)
}

// ToIssuedRecord returns the issued-credentials record of one legacy
// credential. The record holds no personal data beyond the claims that
// o.KeepClaims names.
func ToIssuedRecord(c LegacyIssued, o Options) (IssuedRecord, error) {
	if strings.TrimSpace(c.ID) == "" {
		return IssuedRecord{}, fmt.Errorf("%w: a credential has no id", ErrInput)
	}
	schema := IssuedSchemaID(c)
	if schema == "" {
		return IssuedRecord{}, fmt.Errorf("%w: credential %s has no schema", ErrInput, c.ID)
	}
	subject := SubjectOf(c)
	issued := c.IssuedAt.UTC()
	if issued.IsZero() {
		return IssuedRecord{}, fmt.Errorf("%w: credential %s has no issuance time", ErrInput, c.ID)
	}
	r := IssuedRecord{
		ID:               c.ID,
		SchemaID:         schema,
		SchemaVersion:    1,
		SubjectRef:       SubjectRef(o.Salt, subject),
		Format:           c.Format,
		Status:           StatusActive,
		DPG:              c.IssuerDpg,
		IssuedAt:         issued,
		SearchableClaims: Keep(c.SubjectFields, o.KeepClaims),
	}
	if c.StatusList != nil {
		r.Binding = Binding{
			Kind:   c.StatusList.Type,
			ListID: c.StatusList.ListID,
			Index:  int64(c.StatusList.Index),
		}
		if base := strings.TrimRight(o.StatusBaseURL, "/"); base != "" {
			r.Binding.PublishURL = base + StatusPathPrefix + c.StatusList.ListID
		}
	}
	return r, nil
}

// BuildIssuedDocument returns the store document of the
// issued-credentials service. It writes one issue event per credential
// in the order of the legacy log, then one status event per revoked
// credential. The hash chain is built again over the new events.
func BuildIssuedDocument(items []LegacyIssued, opts Options) (IssuedDocument, error) {
	o, err := opts.check()
	if err != nil {
		return IssuedDocument{}, err
	}
	chain := hashchain.New()
	seen := map[string]bool{}
	var revoked []IssuedChange
	for _, c := range items {
		r, err := ToIssuedRecord(c, o)
		if err != nil {
			return IssuedDocument{}, err
		}
		if seen[r.ID] {
			return IssuedDocument{}, fmt.Errorf("%w: credential %s is in the log twice", ErrInput, r.ID)
		}
		seen[r.ID] = true
		record := r
		// The event holds strings, times, and a string map, so it
		// always encodes and Append cannot fail.
		chain, _, _ = chain.Append(IssuedEvent{Kind: EventIssue, Record: &record})
		if c.RevokedAt != nil {
			revoked = append(revoked, IssuedChange{
				RecordID: r.ID, Status: StatusRevoked, Reason: o.Reason, ChangedAt: c.RevokedAt.UTC(),
			})
		}
	}
	sort.SliceStable(revoked, func(i, j int) bool {
		if revoked[i].ChangedAt.Equal(revoked[j].ChangedAt) {
			return revoked[i].RecordID < revoked[j].RecordID
		}
		return revoked[i].ChangedAt.Before(revoked[j].ChangedAt)
	})
	for i := range revoked {
		change := revoked[i]
		chain, _, _ = chain.Append(IssuedEvent{Kind: EventStatus, Change: &change})
	}
	return IssuedDocument{Entries: chain.Entries()}, nil
}

// IssuerSlug returns the store name of an issuer DID. It is the same
// name the status services use.
func IssuerSlug(issuerDID string) string {
	if issuerDID == "" {
		return "default"
	}
	sum := sha256.Sum256([]byte(issuerDID))
	return hex.EncodeToString(sum[:8])
}

// AllocatedBits returns the allocation bit map of a list with size
// entries where the first count indices are allocated. Bit 0 is the most
// significant bit of byte 0. Every padding bit past size is set, as the
// status services expect.
func AllocatedBits(size, count int) []byte {
	out := make([]byte, (size+7)/8)
	for i := 0; i < count && i < size; i++ {
		out[i/8] |= 1 << (7 - i%8)
	}
	for i := size; i < len(out)*8; i++ {
		out[i/8] |= 1 << (7 - i%8)
	}
	return out
}

// ToListRecord returns the status service record of one legacy list.
// The bit array and the allocated indices stay as they are.
func ToListRecord(l LegacyList, opts Options) (ListRecord, error) {
	o, err := opts.check()
	if err != nil {
		return ListRecord{}, err
	}
	if l.Kind != KindBitstring && l.Kind != KindToken {
		return ListRecord{}, fmt.Errorf("%w: list %s has the kind %q", ErrInput, l.ListID, l.Kind)
	}
	if strings.TrimSpace(l.ListID) == "" {
		return ListRecord{}, fmt.Errorf("%w: a status list has no id", ErrInput)
	}
	size := l.Size
	if size <= 0 {
		size = len(l.Bits) * 8
	}
	if size > len(l.Bits)*8 {
		return ListRecord{}, fmt.Errorf("%w: list %s holds %d bytes for %d entries",
			ErrInput, l.ListID, len(l.Bits), size)
	}
	count := l.NextFree
	if count < 0 || count > size {
		return ListRecord{}, fmt.Errorf("%w: list %s allocated %d of %d entries",
			ErrInput, l.ListID, l.NextFree, size)
	}
	return ListRecord{
		ID:             l.ListID,
		Kind:           l.Kind,
		Purpose:        PurposeRevocation,
		Bits:           1,
		Size:           size,
		IssuerSlug:     IssuerSlug(o.IssuerDID),
		CreatedAt:      o.Now,
		Allocated:      AllocatedBits(size, count),
		AllocatedCount: count,
		Values:         append([]byte(nil), l.Bits...),
	}, nil
}

// ToTrustEntry returns the trust registry entry of one legacy row. The
// verifier API key is a secret, so the export drops it. The status list
// policy has no field in the new registry, so the export drops it too.
func ToTrustEntry(t LegacyTrust, opts Options) (TrustEntry, error) {
	o, err := opts.check()
	if err != nil {
		return TrustEntry{}, err
	}
	if !strings.HasPrefix(t.DID, "did:") {
		return TrustEntry{}, fmt.Errorf("%w: %q is not a DID", ErrInput, t.DID)
	}
	if !t.ValidUntil.IsZero() && !t.AccreditedAt.IsZero() && t.ValidUntil.Before(t.AccreditedAt) {
		return TrustEntry{}, fmt.Errorf("%w: entry %s ends before it starts", ErrInput, t.DID)
	}
	return TrustEntry{
		DID:                 t.DID,
		DisplayName:         t.DisplayName,
		Role:                RoleIssuer,
		Status:              TrustStatusActive,
		ValidFrom:           t.AccreditedAt.UTC(),
		ValidUntil:          t.ValidUntil.UTC(),
		CredentialTypes:     t.Schemas,
		ServiceEndpoint:     t.ServiceEndpoint,
		StatusListEndpoints: t.StatusListEndpoints,
		UpdatedAt:           o.Now,
		Version:             1,
		Source:              SourceAdmin,
	}, nil
}

// BuildTrustDocument returns the store document of the trust-registry
// service. The revision counts one change per entry.
func BuildTrustDocument(items []LegacyTrust, opts Options) (TrustDocument, error) {
	doc := TrustDocument{Entries: map[string]TrustEntry{}}
	for _, t := range items {
		e, err := ToTrustEntry(t, opts)
		if err != nil {
			return TrustDocument{}, err
		}
		if _, ok := doc.Entries[e.DID]; ok {
			return TrustDocument{}, fmt.Errorf("%w: the DID %s is in the registry twice", ErrInput, e.DID)
		}
		doc.Entries[e.DID] = e
		doc.Revision++
	}
	return doc, nil
}

// Bundle holds every document an export writes.
type Bundle struct {
	Issued    IssuedDocument
	Bitstring []ListRecord
	Token     []ListRecord
	Trust     TrustDocument
}

// Build returns the whole export bundle of one legacy deployment.
func Build(l Legacy, opts Options) (Bundle, error) {
	o, err := opts.check()
	if err != nil {
		return Bundle{}, err
	}
	var b Bundle
	if b.Issued, err = BuildIssuedDocument(l.Issued, o); err != nil {
		return Bundle{}, err
	}
	for _, list := range l.Lists {
		rec, recErr := ToListRecord(list, o)
		if recErr != nil {
			return Bundle{}, recErr
		}
		if rec.Kind == KindToken {
			b.Token = append(b.Token, rec)
			continue
		}
		b.Bitstring = append(b.Bitstring, rec)
	}
	if b.Trust, err = BuildTrustDocument(l.Trust, o); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

// Counts reports the size of a bundle.
type Counts struct {
	Issued    int
	Bitstring int
	Token     int
	Trust     int
}

// Counts returns the number of records in each part of the bundle.
func (b Bundle) Counts() Counts {
	return Counts{
		Issued:    len(b.Issued.Entries),
		Bitstring: len(b.Bitstring),
		Token:     len(b.Token),
		Trust:     len(b.Trust.Entries),
	}
}
