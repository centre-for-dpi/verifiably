// SPDX-License-Identifier: Apache-2.0

// Package dedi publishes the trust entries as signed Decentralized
// Directory files with a signed manifest at /.well-known/dedi.index.json
// (ADR-011 decision 3). The file layout lives in schema.go only.
package dedi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/keys"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
)

// JWKSPath is the path of the key set the manifest points at.
const JWKSPath = "/.well-known/jwks.json"

// directoryNames lists the directories in publication order.
// Each role has one directory.
var directoryNames = []struct {
	name string
	role entry.Role
}{
	{"issuers", entry.RoleIssuer},
	{"holders", entry.RoleHolder},
	{"verifiers", entry.RoleVerifier},
}

// Publisher is the dedi method.
type Publisher struct{}

// Method returns dedi.
func (Publisher) Method() string { return publish.MethodDedi }

// FromEntry converts one canonical entry to a record.
func FromEntry(e entry.Entry) Record {
	r := Record{
		ID:                  e.ID(),
		Name:                e.DisplayName,
		Role:                string(e.Role),
		Status:              string(e.Status),
		CredentialTypes:     e.CredentialTypes,
		ServiceEndpoint:     e.ServiceEndpoint,
		StatusListEndpoints: e.StatusListEndpoints,
	}
	if !e.ValidFrom.IsZero() {
		t := e.ValidFrom.UTC()
		r.ValidFrom = &t
	}
	if !e.ValidUntil.IsZero() {
		t := e.ValidUntil.UTC()
		r.ValidUntil = &t
	}
	return r
}

// ToEntry converts a record to a canonical entry.
func ToEntry(r Record) (entry.Entry, error) {
	e := entry.Entry{
		DisplayName:         r.Name,
		Role:                entry.Role(r.Role),
		Status:              entry.Status(r.Status),
		CredentialTypes:     r.CredentialTypes,
		ServiceEndpoint:     r.ServiceEndpoint,
		StatusListEndpoints: r.StatusListEndpoints,
	}
	if len(r.ID) > 5 && r.ID[:5] == "x509:" {
		e.X509Subject = r.ID[5:]
	} else {
		e.DID = r.ID
	}
	if r.ValidFrom != nil {
		e.ValidFrom = *r.ValidFrom
	}
	if r.ValidUntil != nil {
		e.ValidUntil = *r.ValidUntil
	}
	if err := e.Validate(); err != nil {
		return entry.Entry{}, err
	}
	return e, nil
}

// Publish builds one directory file per role and the manifest, and
// signs each file with the active key.
func (Publisher) Publish(in publish.Input) (publish.Publication, error) {
	if in.TTL <= 0 {
		return publish.Publication{}, errors.New("dedi: ttl must be positive")
	}
	now := in.Now.UTC()
	expires := now.Add(in.TTL)
	pub := PublisherInfo{ID: in.Issuer.ID, Name: in.Issuer.Name}
	files := map[string]publish.File{}
	index := Index{
		SchemaVersion: SchemaVersion,
		URL:           publish.JoinURL(in.BaseURL, IndexPath),
		Publisher:     pub,
		JWKSURL:       publish.JoinURL(in.BaseURL, JWKSPath),
		Sequence:      in.Sequence,
		IssuedAt:      now,
		ExpiresAt:     expires,
	}
	jwk, err := jose.JWKToMap(in.Signer.Public())
	if err != nil {
		return publish.Publication{}, fmt.Errorf("dedi: %w", err)
	}
	index.SigningKey = SigningKey{KeyID: in.Signer.ID, Alg: string(in.Signer.Alg), JWK: jwk}
	sorted := entry.Sorted(in.Entries)
	total := 0
	for _, d := range directoryNames {
		doc := DirectoryFile{SchemaVersion: SchemaVersion, Name: d.name, Publisher: pub, Sequence: in.Sequence, IssuedAt: now, ExpiresAt: expires, Records: []Record{}}
		for _, e := range sorted {
			if e.Role == d.role {
				doc.Records = append(doc.Records, FromEntry(e))
			}
		}
		body, err := sign(doc, in.Signer)
		if err != nil {
			return publish.Publication{}, err
		}
		files[DirectoryPath(d.name)] = publish.File{ContentType: ContentType, Body: body}
		index.Directories = append(index.Directories, Directory{
			Name:       d.name,
			File:       FileName(d.name),
			URL:        publish.JoinURL(in.BaseURL, DirectoryPath(d.name)),
			Digest:     digest(body),
			EntryCount: len(doc.Records),
		})
		total += len(doc.Records)
	}
	body, err := sign(index, in.Signer)
	if err != nil {
		return publish.Publication{}, err
	}
	files[IndexPath] = publish.File{ContentType: ContentType, Body: body}
	return publish.Publication{
		Method:      publish.MethodDedi,
		URL:         publish.JoinURL(in.BaseURL, IndexPath),
		Files:       files,
		EntryCount:  total,
		PublishedAt: now,
		KeyID:       in.Signer.ID,
		Sequence:    in.Sequence,
	}, nil
}

// Verify checks the manifest and every directory file it lists.
func (Publisher) Verify(files map[string]publish.File, set jose.JWKS, now time.Time) (publish.Verified, error) {
	f, ok := files[IndexPath]
	if !ok {
		return publish.Verified{}, fmt.Errorf("dedi: file %s is missing", IndexPath)
	}
	var index Index
	hdr, err := open(f.Body, set, &index)
	if err != nil {
		return publish.Verified{}, err
	}
	if now.After(index.ExpiresAt) {
		return publish.Verified{}, errors.New("dedi: manifest expired")
	}
	var entries []entry.Entry
	for _, d := range index.Directories {
		df, ok := files[DirectoryPath(d.Name)]
		if !ok {
			return publish.Verified{}, fmt.Errorf("dedi: directory %s is missing", d.Name)
		}
		body := df.Body
		if digest(body) != d.Digest {
			return publish.Verified{}, fmt.Errorf("dedi: digest of %s does not match the manifest", d.Name)
		}
		var doc DirectoryFile
		if _, err := open(body, set, &doc); err != nil {
			return publish.Verified{}, err
		}
		for i, r := range doc.Records {
			e, err := ToEntry(r)
			if err != nil {
				return publish.Verified{}, fmt.Errorf("dedi: %s record %d: %w", d.Name, i, err)
			}
			entries = append(entries, e)
		}
	}
	return publish.Verified{
		Entries:   entries,
		Sequence:  index.Sequence,
		KeyID:     hdr.Kid,
		ListURL:   index.URL,
		IssuedAt:  index.IssuedAt,
		ExpiresAt: index.ExpiresAt,
	}, nil
}

// sign wraps doc in a Signed envelope with a compact JWS over doc.
func sign(doc any, signer keys.Key) ([]byte, error) {
	jws, err := jose.Sign(signer.Private, signer.ID, TypeJWS, doc)
	if err != nil {
		return nil, fmt.Errorf("dedi: %w", err)
	}
	// doc signed one line above, so it encodes.
	body, _ := json.Marshal(Signed{
		Document: doc,
		Proof:    Signature{Type: SignatureType, KeyID: signer.ID, Alg: string(signer.Alg), JWS: jws},
	})
	return body, nil
}

// open checks the envelope signature and decodes the JWS payload into out.
func open(body []byte, set jose.JWKS, out any) (jose.Header, error) {
	var env struct {
		Proof Signature `json:"proof"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return jose.Header{}, fmt.Errorf("dedi: parse envelope: %w", err)
	}
	raw, hdr, err := jose.VerifyWithJWKS(env.Proof.JWS, set, jose.SigningAlgorithms)
	if err != nil {
		return hdr, fmt.Errorf("dedi: %w", err)
	}
	if hdr.Typ != TypeJWS {
		return hdr, fmt.Errorf("dedi: typ %q is not %s", hdr.Typ, TypeJWS)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return hdr, fmt.Errorf("dedi: parse document: %w", err)
	}
	return hdr, nil
}

func digest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
