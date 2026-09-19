// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// The queries read the three legacy tables of ADR-030 decision 8. The
// migrator reads only. It writes nothing into the legacy database.
const (
	issuedQuery = `SELECT id, schema_id, schema_name, std, format, issuer_dpg, owner_key,
 holder_hint, offer_uri, issued_at, revoked_at, subject_fields, status_list
 FROM issued_credentials ORDER BY seq`
	listsQuery = `SELECT list_id, kind, next_free, bits FROM status_lists ORDER BY list_id`
	trustQuery = `SELECT did, display_name, schemas, service_endpoint, status_list_endpoints,
 status_list_policy, accredited_at, valid_until FROM trusted_issuers ORDER BY did`
)

// Queryer is the part of *sql.DB the reader needs. A test injects a
// fake.
type Queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// ReadPostgres reads every legacy record from a PostgreSQL database.
// The caller opens the database with a driver of its choice, so this
// package needs no driver.
func ReadPostgres(ctx context.Context, db Queryer) (Legacy, error) {
	var out Legacy
	var err error
	if out.Issued, err = readIssued(ctx, db); err != nil {
		return Legacy{}, err
	}
	if out.Lists, err = readLists4PG(ctx, db); err != nil {
		return Legacy{}, err
	}
	if out.Trust, err = readTrust(ctx, db); err != nil {
		return Legacy{}, err
	}
	return out, nil
}

// readIssued reads the issued_credentials table in sequence order.
func readIssued(ctx context.Context, db Queryer) ([]LegacyIssued, error) {
	rows, err := db.QueryContext(ctx, issuedQuery)
	if err != nil {
		return nil, fmt.Errorf("migrate: read issued_credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []LegacyIssued
	for rows.Next() {
		var (
			c         LegacyIssued
			revoked   sql.NullTime
			subject   []byte
			statusRaw []byte
		)
		if err := rows.Scan(&c.ID, &c.SchemaID, &c.SchemaName, &c.Std, &c.Format, &c.IssuerDpg,
			&c.OwnerKey, &c.HolderHint, &c.OfferURI, &c.IssuedAt, &revoked, &subject, &statusRaw); err != nil {
			return nil, fmt.Errorf("migrate: read an issued_credentials row: %w", err)
		}
		if revoked.Valid {
			t := revoked.Time
			c.RevokedAt = &t
		}
		if len(subject) > 0 {
			if err := json.Unmarshal(subject, &c.SubjectFields); err != nil {
				return nil, fmt.Errorf("%w: subject_fields of %s: %w", ErrInput, c.ID, err)
			}
		}
		if len(statusRaw) > 0 && string(statusRaw) != "null" {
			var ref LegacyStatusRef
			if err := json.Unmarshal(statusRaw, &ref); err != nil {
				return nil, fmt.Errorf("%w: status_list of %s: %w", ErrInput, c.ID, err)
			}
			c.StatusList = &ref
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("migrate: read issued_credentials: %w", err)
	}
	return out, nil
}

// readLists4PG reads the status_lists table. The table holds no size,
// so the size is the length of the bit array.
func readLists4PG(ctx context.Context, db Queryer) ([]LegacyList, error) {
	rows, err := db.QueryContext(ctx, listsQuery)
	if err != nil {
		return nil, fmt.Errorf("migrate: read status_lists: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []LegacyList
	for rows.Next() {
		var l LegacyList
		if err := rows.Scan(&l.ListID, &l.Kind, &l.NextFree, &l.Bits); err != nil {
			return nil, fmt.Errorf("migrate: read a status_lists row: %w", err)
		}
		l.Size = len(l.Bits) * 8
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("migrate: read status_lists: %w", err)
	}
	return out, nil
}

// readTrust reads the trusted_issuers table. The verifier API key is a
// secret, so the query does not read it.
func readTrust(ctx context.Context, db Queryer) ([]LegacyTrust, error) {
	rows, err := db.QueryContext(ctx, trustQuery)
	if err != nil {
		return nil, fmt.Errorf("migrate: read trusted_issuers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []LegacyTrust
	for rows.Next() {
		var (
			t         LegacyTrust
			schemas   string
			endpoints string
			until     sql.NullTime
		)
		if err := rows.Scan(&t.DID, &t.DisplayName, &schemas, &t.ServiceEndpoint, &endpoints,
			&t.StatusListPolicy, &t.AccreditedAt, &until); err != nil {
			return nil, fmt.Errorf("migrate: read a trusted_issuers row: %w", err)
		}
		if until.Valid {
			t.ValidUntil = until.Time
		}
		t.Schemas = ParseTextArray(schemas)
		t.StatusListEndpoints = ParseTextArray(endpoints)
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("migrate: read trusted_issuers: %w", err)
	}
	return out, nil
}

// ParseTextArray reads a PostgreSQL text array literal such as
// {a,"b,c"}. A driver returns the literal, because database/sql has no
// array type. An empty array returns no values.
func ParseTextArray(s string) []string {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return nil
	}
	body := s[1 : len(s)-1]
	if body == "" {
		return nil
	}
	var (
		out     []string
		item    strings.Builder
		quoted  bool
		escaped bool
	)
	for _, r := range body {
		switch {
		case escaped:
			item.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			quoted = !quoted
		case r == ',' && !quoted:
			out = append(out, item.String())
			item.Reset()
		default:
			item.WriteRune(r)
		}
	}
	out = append(out, item.String())
	return out
}

// OpenPostgres opens a database with the driver and the DSN. The driver
// must be linked into the program. The CLI keeps this function so that
// a build can add a driver without a change to the migrator.
func OpenPostgres(driver, dsn string) (*sql.DB, error) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("migrate: open the legacy database: %w", err)
	}
	return db, nil
}
