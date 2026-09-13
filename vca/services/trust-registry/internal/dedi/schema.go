// SPDX-License-Identifier: Apache-2.0

package dedi

import (
	"strings"
	"time"
)

// This file holds the whole file layout of the dedi method: the manifest
// at /.well-known/dedi.index.json and the directory files at
// /dedi/<name>.json. The Decentralized Directory protocol repository
// (LF-Decentralized-Trust-labs/decentralized-directory-protocol) is the
// normative source (ADR-011 decision 3). The build network could not
// reach it, so the fields below follow the ADR description with plain
// names. To adopt the vendored schema, replace this file and record the
// commit hash in SchemaVersion. The publisher and the verifier in dedi.go
// depend on the exported types only.

// SchemaVersion names the layout in this file. Replace it with the
// vendored schema version and commit hash once the schema is vendored.
const SchemaVersion = "vca-dedi-draft-1"

// Paths of the published files. A directory file is named
// dedi.<name>.json and served under /dedi/.
const (
	IndexPath  = "/.well-known/dedi.index.json"
	DirPrefix  = "/dedi/"
	FilePrefix = "dedi."
	FileSuffix = ".json"
)

// ContentType of every dedi file.
const ContentType = "application/json"

// TypeJWS is the typ header of the signatures on the dedi files.
const TypeJWS = "dedi+jwt"

// Index is the manifest. It declares the signing key and lists each
// directory file.
type Index struct {
	SchemaVersion string `json:"schemaVersion"`
	// URL is the public URL of this manifest.
	URL       string        `json:"url"`
	Publisher PublisherInfo `json:"publisher"`
	// SigningKey is the public key that signs the manifest and the
	// directory files. Retired keys stay in the JWKS at JWKSURL.
	SigningKey  SigningKey  `json:"signingKey"`
	JWKSURL     string      `json:"jwksUrl"`
	Directories []Directory `json:"directories"`
	// Sequence rises with every publication.
	Sequence  uint64    `json:"sequence"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// PublisherInfo identifies the operator of the directory.
type PublisherInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// SigningKey names the active key.
type SigningKey struct {
	KeyID string         `json:"kid"`
	Alg   string         `json:"alg"`
	JWK   map[string]any `json:"jwk"`
}

// Directory is one row of the manifest.
type Directory struct {
	// Name is the file name without the dedi. prefix and .json suffix,
	// for example issuers.
	Name string `json:"name"`
	// File is the file name, dedi.<name>.json.
	File string `json:"file"`
	URL  string `json:"url"`
	// Digest is the SHA-256 of the file body, hex encoded.
	Digest     string `json:"digest"`
	EntryCount int    `json:"entryCount"`
}

// DirectoryFile is the content of one directory file.
type DirectoryFile struct {
	SchemaVersion string        `json:"schemaVersion"`
	Name          string        `json:"name"`
	Publisher     PublisherInfo `json:"publisher"`
	Sequence      uint64        `json:"sequence"`
	IssuedAt      time.Time     `json:"issuedAt"`
	ExpiresAt     time.Time     `json:"expiresAt"`
	Records       []Record      `json:"records"`
}

// Record is one entity in a directory.
type Record struct {
	// ID is the DID of the entity, or the x509 subject with prefix x509:.
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	// Role is issuer, holder, or verifier.
	Role string `json:"role"`
	// Status is active, suspended, or revoked.
	Status              string     `json:"status"`
	ValidFrom           *time.Time `json:"validFrom,omitempty"`
	ValidUntil          *time.Time `json:"validUntil,omitempty"`
	CredentialTypes     []string   `json:"credentialTypes,omitempty"`
	ServiceEndpoint     string     `json:"serviceEndpoint,omitempty"`
	StatusListEndpoints []string   `json:"statusListEndpoints,omitempty"`
}

// Signed wraps a manifest or a directory file with its signature.
// The signature is a compact JWS whose payload is the JSON of the
// document. A reader checks the JWS and uses the JWS payload as the
// document. The clear copy is for people and for tools with no JOSE.
type Signed struct {
	Document any       `json:"document"`
	Proof    Signature `json:"proof"`
}

// Signature carries the JWS.
type Signature struct {
	Type  string `json:"type"`
	KeyID string `json:"kid"`
	Alg   string `json:"alg"`
	JWS   string `json:"jws"`
}

// SignatureType is the type name of Signature.
const SignatureType = "JsonWebSignature2020"

// FileName returns the file name of a directory, dedi.<name>.json.
func FileName(name string) string {
	return FilePrefix + name + FileSuffix
}

// DirectoryPath returns the URL path of a directory file.
func DirectoryPath(name string) string {
	return DirPrefix + FileName(name)
}

// DirectoryNameFromPath returns the name of a directory file path.
// ok is false when the path is not a directory file path.
func DirectoryNameFromPath(path string) (name string, ok bool) {
	rest, hasDir := strings.CutPrefix(path, DirPrefix)
	if !hasDir {
		return "", false
	}
	rest, hasPrefix := strings.CutPrefix(rest, FilePrefix)
	rest, hasSuffix := strings.CutSuffix(rest, FileSuffix)
	if !hasPrefix || !hasSuffix || rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	return rest, true
}
