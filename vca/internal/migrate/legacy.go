// SPDX-License-Identifier: Apache-2.0

// Package migrate carries the data of a verifiably-go deployment into
// the Verifiable Credentials Adapters services (ADR-030 decision 8).
//
// The package reads the legacy issuance log, the legacy status lists,
// and the legacy trust registry. It writes the store documents of the
// issued-credentials service, the two status services, and the
// trust-registry service. Sessions and caches are not migrated.
//
// Every transform is a pure function. The reader functions and the
// writer functions hold the only side effects.
package migrate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Errors the package returns.
var (
	// ErrInput reports data that the migrator cannot read.
	ErrInput = errors.New("migrate: the legacy data is not valid")
	// ErrOptions reports a missing or wrong option.
	ErrOptions = errors.New("migrate: the options are not valid")
	// ErrExists reports an output file that already exists.
	ErrExists = errors.New("migrate: the file exists")
)

// KindBitstring names a W3C Bitstring Status List.
const KindBitstring = "bitstring"

// KindToken names an IETF Token Status List.
const KindToken = "token"

// Legacy holds every record one legacy deployment owns.
type Legacy struct {
	Issued []LegacyIssued
	Lists  []LegacyList
	Trust  []LegacyTrust
}

// LegacyStatusRef is the status list entry of one legacy credential. It
// mirrors issuance.StatusListEntry of verifiably-go.
type LegacyStatusRef struct {
	Type   string `json:"type"`
	ListID string `json:"listId"`
	Index  int    `json:"index"`
}

// LegacyIssued is one row of issued_credentials, or one entry of
// issued-credentials.json. The JSON tags match the legacy file.
type LegacyIssued struct {
	ID            string            `json:"id"`
	SchemaID      string            `json:"schemaId"`
	SchemaName    string            `json:"schemaName"`
	Std           string            `json:"std"`
	Format        string            `json:"format"`
	IssuerDpg     string            `json:"issuerDpg"`
	OwnerKey      string            `json:"ownerKey,omitempty"`
	HolderHint    string            `json:"holderHint,omitempty"`
	SubjectFields map[string]string `json:"subjectFields,omitempty"`
	OfferURI      string            `json:"offerUri,omitempty"`
	IssuedAt      time.Time         `json:"issuedAt"`
	RevokedAt     *time.Time        `json:"revokedAt,omitempty"`
	StatusList    *LegacyStatusRef  `json:"statusList,omitempty"`
}

// LegacyList is one status list: one row of status_lists, or one
// status-list-<id>.json file.
type LegacyList struct {
	// Kind is "bitstring" or "token".
	Kind string
	// ListID is the legacy list id, for example "bitstring-v1".
	ListID string
	// Size is the number of entries.
	Size int
	// NextFree is the first index the legacy allocator never gave out.
	// Every index below it is allocated.
	NextFree int
	// Bits holds the status bits in the layout of the kind.
	Bits []byte
}

// LegacyTrust is one row of trusted_issuers.
type LegacyTrust struct {
	DID                 string    `json:"did"`
	DisplayName         string    `json:"display_name"`
	Schemas             []string  `json:"schemas"`
	ServiceEndpoint     string    `json:"service_endpoint"`
	StatusListEndpoints []string  `json:"status_list_endpoints"`
	StatusListPolicy    string    `json:"status_list_policy"`
	AccreditedAt        time.Time `json:"accredited_at"`
	ValidUntil          time.Time `json:"valid_until"`
}

// legacyListFile is the saved form of a legacy status list. It mirrors
// the onDisk type of verifiably-go internal/statuslist.
type legacyListFile struct {
	Size     int    `json:"size"`
	NextFree int    `json:"nextFree"`
	Bits     string `json:"bits"`
}

// IssuedLogName is the file name of the legacy issuance log.
const IssuedLogName = "issued-credentials.json"

// listPrefix starts the name of every legacy status list file.
const listPrefix = "status-list-"

// TrustFileName is the optional legacy trust registry export. The legacy
// file mode keeps no trust registry, so an operator writes this file by
// hand or exports it from PostgreSQL.
const TrustFileName = "trusted-issuers.json"

// ParseIssuedLog reads the legacy issuance log. Empty data is an empty
// log.
func ParseIssuedLog(data []byte) ([]LegacyIssued, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var out []LegacyIssued
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("%w: read the issuance log: %w", ErrInput, err)
	}
	return out, nil
}

// ParseTrustFile reads the optional legacy trust registry export.
func ParseTrustFile(data []byte) ([]LegacyTrust, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var out []LegacyTrust
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("%w: read the trust registry: %w", ErrInput, err)
	}
	return out, nil
}

// KindOfListID returns the status list standard of a legacy list id.
// An id that holds "token" names an IETF Token Status List. Every other
// id names a W3C Bitstring Status List.
func KindOfListID(id string) string {
	if strings.Contains(strings.ToLower(id), KindToken) {
		return KindToken
	}
	return KindBitstring
}

// ParseListFile reads one legacy status list file. The id names the
// list, for example "bitstring-v1".
func ParseListFile(id string, data []byte) (LegacyList, error) {
	var f legacyListFile
	if err := json.Unmarshal(data, &f); err != nil {
		return LegacyList{}, fmt.Errorf("%w: read the status list %s: %w", ErrInput, id, err)
	}
	raw, err := decodeRawBytes(f.Bits)
	if err != nil {
		return LegacyList{}, fmt.Errorf("%w: read the bits of %s: %w", ErrInput, id, err)
	}
	size := f.Size
	if size <= 0 {
		size = len(raw) * 8
	}
	return LegacyList{Kind: KindOfListID(id), ListID: id, Size: size, NextFree: f.NextFree, Bits: raw}, nil
}

// ListIDOfFile returns the list id of a legacy status list file name.
// ok is false when the name is not a status list file.
func ListIDOfFile(name string) (id string, ok bool) {
	if !strings.HasPrefix(name, listPrefix) || !strings.HasSuffix(name, ".json") {
		return "", false
	}
	id = strings.TrimSuffix(strings.TrimPrefix(name, listPrefix), ".json")
	if id == "" || strings.HasSuffix(id, "-key") || strings.HasSuffix(id, "-ld-key") {
		return "", false
	}
	return id, true
}

// ReadStateDir reads every legacy record from a state directory. It
// reads the issuance log, every status list file, and the optional
// trust registry export. A missing file is an empty result.
func ReadStateDir(dir string) (Legacy, error) {
	var out Legacy
	issued, err := readOptional(filepath.Join(dir, IssuedLogName))
	if err != nil {
		return Legacy{}, err
	}
	if out.Issued, err = ParseIssuedLog(issued); err != nil {
		return Legacy{}, err
	}
	trust, err := readOptional(filepath.Join(dir, TrustFileName))
	if err != nil {
		return Legacy{}, err
	}
	if out.Trust, err = ParseTrustFile(trust); err != nil {
		return Legacy{}, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Legacy{}, fmt.Errorf("migrate: read %s: %w", dir, err)
	}
	for _, e := range entries {
		id, ok := ListIDOfFile(e.Name())
		if e.IsDir() || !ok {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- the operator names the directory
		if err != nil {
			return Legacy{}, fmt.Errorf("migrate: read %s: %w", e.Name(), err)
		}
		list, err := ParseListFile(id, data)
		if err != nil {
			return Legacy{}, err
		}
		out.Lists = append(out.Lists, list)
	}
	sort.Slice(out.Lists, func(i, j int) bool { return out.Lists[i].ListID < out.Lists[j].ListID })
	return out, nil
}

// readOptional reads a file. A missing file returns no bytes.
func readOptional(path string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the operator names the directory
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("migrate: read %s: %w", path, err)
	}
	return data, nil
}
