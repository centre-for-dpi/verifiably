// Package didresolver resolves DIDs to their DID Documents.
// Only did:web is implemented; other methods return an error.
package didresolver

import "context"

// Resolver resolves a DID to its DID Document.
type Resolver interface {
	Resolve(ctx context.Context, did string) (DIDDocument, error)
}

// DIDDocument is a minimal representation of a W3C DID Document.
// Only the fields required for cryptographic key resolution are captured.
type DIDDocument struct {
	ID                  string
	VerificationMethods []VerificationMethod
}

// VerificationMethod is one key entry in a DID Document.
type VerificationMethod struct {
	ID           string
	Type         string
	PublicKeyJWK map[string]any
}
