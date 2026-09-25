// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
)

// The ledger and status endpoints of Inji Certify 0.14.0.
//
//   - POST /v1/certify/v2/ledger-search finds issued credentials by
//     issuer, type, and indexed attributes. It answers 204 when nothing
//     matches.
//   - POST /v1/certify/credentials/status sets the status bit of one
//     credential of the ledger. A scheduled job of Certify then writes
//     the status list credential.
//   - GET /v1/certify/.well-known/did.json serves the DID document of
//     the issuer.
const (
	ledgerSearchPath = "/v1/certify/v2/ledger-search"
	statusPath       = "/v1/certify/credentials/status"
	didDocumentPath  = "/v1/certify/.well-known/did.json"
)

// ErrCredentialNotFound reports a credential that the ledger does not
// hold.
var ErrCredentialNotFound = errors.New("inji: the Certify ledger holds no credential with this id")

// certifyTimeLayout is the Jackson pattern of a Certify LocalDateTime.
const certifyTimeLayout = "2006-01-02T15:04:05"

// CertifyTime is a time as Certify writes it: a local date time in UTC
// without a zone.
type CertifyTime struct{ time.Time }

// UnmarshalJSON reads the Certify layout, and RFC 3339 as well.
func (t *CertifyTime) UnmarshalJSON(raw []byte) error {
	var s string
	// A null or an empty string is no time, which the zero value says.
	if json.Unmarshal(raw, &s) == nil && s != "" {
		for _, layout := range []string{certifyTimeLayout, time.RFC3339Nano} {
			if parsed, err := time.Parse(layout, s); err == nil {
				t.Time = parsed.UTC()
				return nil
			}
		}
		return fmt.Errorf("inji: %q is not a Certify time", s)
	}
	return nil
}

// LedgerSearch selects entries of the ledger.
type LedgerSearch struct {
	// IssuerID is the DID of the issuer. Certify needs it.
	IssuerID string `json:"issuerId"`
	// CredentialType is the sorted, comma separated type list. Certify
	// needs it.
	CredentialType string `json:"credentialType"`
	// CredentialID narrows the search to one credential.
	CredentialID string `json:"credentialId,omitempty"`
	// Attributes are the indexed attributes to match. Certify needs at
	// least one.
	Attributes map[string]string `json:"indexedAttributesEquals"`
}

// LedgerEntry is one answer of a ledger search or a status update.
type LedgerEntry struct {
	CredentialID            string      `json:"credentialId"`
	IssuerID                string      `json:"issuerId"`
	StatusListCredentialURL string      `json:"statusListCredentialUrl"`
	StatusListIndex         int64       `json:"statusListIndex"`
	StatusPurpose           string      `json:"statusPurpose"`
	IssuanceDate            CertifyTime `json:"issuanceDate"`
	IssueDate               CertifyTime `json:"issueDate"`
	ExpirationDate          CertifyTime `json:"expirationDate"`
	CredentialType          string      `json:"credentialType"`
	StatusTimestamp         CertifyTime `json:"statusTimestamp"`
}

// Issued returns the issuance time of either answer version.
func (e LedgerEntry) Issued() time.Time {
	if !e.IssuanceDate.IsZero() {
		return e.IssuanceDate.Time
	}
	return e.IssueDate.Time
}

// LedgerType returns the credential type as the ledger stores it: the
// type names sorted and joined with commas.
func LedgerType(types []string) string {
	seen := map[string]bool{}
	var out []string
	for _, t := range types {
		if t = strings.TrimSpace(t); t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// SearchLedger returns the entries that match q.
func (c *Certify) SearchLedger(ctx context.Context, q LedgerSearch) ([]LedgerEntry, error) {
	if c == nil {
		return nil, ErrNoCertify
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("inji: encode the ledger search: %w", err)
	}
	resp, err := c.client.Do(ctx, dpgclient.Request{
		Method: http.MethodPost, Path: ledgerSearchPath, Body: raw, ContentType: "application/json", Accept: "application/json",
	})
	if err != nil {
		return nil, err
	}
	body := bytes.TrimSpace(resp.Body)
	if resp.Status == http.StatusNoContent || len(body) == 0 {
		return nil, nil
	}
	if aerr := errorOf(body); aerr != nil {
		return nil, aerr
	}
	var out []LedgerEntry
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("inji: read the ledger search: %w", err)
	}
	return out, nil
}

// statusUpdate is the body of POST /v1/certify/credentials/status.
type statusUpdate struct {
	CredentialID     string `json:"credentialId"`
	CredentialStatus struct {
		StatusPurpose string `json:"statusPurpose"`
	} `json:"credentialStatus"`
	Status bool `json:"status"`
}

// UpdateStatus sets or clears the status bit of one credential of the
// ledger for a purpose, such as revocation.
func (c *Certify) UpdateStatus(ctx context.Context, credentialID, purpose string, set bool) (LedgerEntry, error) {
	if c == nil {
		return LedgerEntry{}, ErrNoCertify
	}
	body := statusUpdate{CredentialID: credentialID, Status: set}
	body.CredentialStatus.StatusPurpose = purpose
	raw, err := json.Marshal(body)
	if err != nil {
		return LedgerEntry{}, fmt.Errorf("inji: encode the status update: %w", err)
	}
	resp, err := c.client.Do(ctx, dpgclient.Request{
		Method: http.MethodPost, Path: statusPath, Body: raw, ContentType: "application/json", Accept: "application/json",
	})
	if dpgclient.IsStatus(err, http.StatusNotFound) {
		return LedgerEntry{}, ErrCredentialNotFound
	}
	if err != nil {
		return LedgerEntry{}, err
	}
	if aerr := errorOf(resp.Body); aerr != nil {
		return LedgerEntry{}, aerr
	}
	var out LedgerEntry
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return LedgerEntry{}, fmt.Errorf("inji: read the status answer: %w", err)
	}
	return out, nil
}

// DIDDocument is the DID document of the issuer as Certify serves it.
type DIDDocument struct {
	// ID is the DID.
	ID string `json:"id"`
	// VerificationMethod lists the public keys.
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	// Raw is the document as Certify served it.
	Raw json.RawMessage `json:"-"`
}

// VerificationMethod is one public key of the DID document.
type VerificationMethod struct {
	ID                 string          `json:"id"`
	Type               string          `json:"type"`
	Controller         string          `json:"controller"`
	PublicKeyMultibase string          `json:"publicKeyMultibase,omitempty"`
	PublicKeyJwk       json.RawMessage `json:"publicKeyJwk,omitempty"`
}

// ReadDIDDocument reads the DID document of the issuer.
func (c *Certify) ReadDIDDocument(ctx context.Context) (DIDDocument, error) {
	if c == nil {
		return DIDDocument{}, ErrNoCertify
	}
	resp, err := c.client.Do(ctx, dpgclient.Request{Method: http.MethodGet, Path: didDocumentPath, Accept: "application/json"})
	if err != nil {
		return DIDDocument{}, err
	}
	var out DIDDocument
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return DIDDocument{}, fmt.Errorf("inji: read the DID document: %w", err)
	}
	if out.ID == "" {
		return DIDDocument{}, errors.New("inji: the DID document has no id")
	}
	out.Raw = resp.Body
	return out, nil
}
