// SPDX-License-Identifier: Apache-2.0

// Package claims writes the VCA claims store of Inji Certify (ADR-051).
//
// Certify issues what its data provider returns for the subject of an
// access token. The stack runs the Postgres data provider of the
// digital credential plugins 0.6.0 on the foreign table
// certify.vca_claims. file_fdw maps that table onto every *.csv file of
// one directory, which this package writes. The adapter opens no
// database connection (ADR-051 decision 2).
//
// Each staged subject gets one file that holds one row. The name of the
// file is the SHA-256 of the subject, so a second write replaces it. The
// writer renames a finished file into place, so the database never reads
// half a row. The sweep deletes a row when its offer has expired.
package claims

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// MaxClaims is the number of claim columns, c1 to c64 (ADR-051
// decision 4).
const MaxClaims = 64

// reserved lists the columns before the claim columns, in table order.
// vca_claims.sql of the stack declares the same order.
var reserved = []string{
	"subject", "config_id", "expires_at",
	"v_valid_from", "v_valid_until", "v_status_uri", "v_status_index",
}

// Columns is the number of columns of a row.
var Columns = len(reserved) + MaxClaims

// The template variables of the reserved columns. The data provider
// returns each column under its name, and the template of a
// configuration reads them.
const (
	// ValidFromColumn holds the start of the validity window.
	ValidFromColumn = "v_valid_from"
	// ValidUntilColumn holds the end of the validity window.
	ValidUntilColumn = "v_valid_until"
	// StatusURIColumn holds the address of the status list.
	StatusURIColumn = "v_status_uri"
	// StatusIndexColumn holds the index in the status list.
	StatusIndexColumn = "v_status_index"
)

// ColumnName returns the name of the claim column at index i, from 0:
// c1 for the first claim.
func ColumnName(i int) string { return "c" + strconv.Itoa(i+1) }

// Row is one staged subject.
type Row struct {
	// Subject is the value Certify looks the row up by: the sub of the
	// access token.
	Subject string
	// ConfigID is the credential configuration the row is for.
	ConfigID string
	// ExpiresAt is the end of the offer. The sweep deletes the row then.
	ExpiresAt time.Time
	// ValidFrom is the start of the validity window, in RFC 3339, or "".
	ValidFrom string
	// ValidUntil is the end of the validity window, in RFC 3339, or "".
	ValidUntil string
	// StatusURI is the address of the status list, or "".
	StatusURI string
	// StatusIndex is the index in the status list, or "".
	StatusIndex string
	// Claims holds the value of each claim column in column order.
	Claims []string
}

// Map returns the claims of the row by name, for the claim names of the
// columns in order.
func (r Row) Map(names []string) map[string]string {
	out := make(map[string]string, len(names))
	for i, name := range names {
		if i < len(r.Claims) {
			out[name] = r.Claims[i]
		}
	}
	return out
}

// Key returns the subject of a pre-authorized token for a staging id:
// the JSON text of the staged map {"id": id}, as Certify writes it
// (ADR-051 decision 5). A UUID holds no character that either encoder
// escapes, and the encoder keeps HTML characters as they are.
func Key(stagingID string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	// A string always encodes.
	if err := enc.Encode(map[string]string{"id": stagingID}); err != nil {
		return ""
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// Value returns the column text of one claim value: a string as it is,
// nothing for null, and the JSON text of every other value.
func Value(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Sprint(v)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// Writer writes and sweeps the rows of one directory.
type Writer struct {
	// Dir is the directory that file_fdw reads.
	Dir string
	// Now reads the clock. Nil reads the real clock.
	Now func() time.Time

	// rename moves a finished file into place. Nil uses os.Rename. A
	// test replaces it.
	rename func(from, to string) error
}

// now returns the time of the writer clock.
func (w Writer) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// fileName returns the name of the file of one subject.
func fileName(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:]) + ".csv"
}

// Put writes the row of one subject and sweeps the expired rows.
func (w Writer) Put(r Row) error {
	if len(r.Claims) > MaxClaims {
		return fmt.Errorf("claims: %d claims, the store holds %d", len(r.Claims), MaxClaims)
	}
	if _, err := w.Sweep(); err != nil {
		return err
	}
	final := filepath.Join(w.Dir, fileName(r.Subject))
	// The temporary name does not end in .csv, so the table skips it.
	tmp := filepath.Join(w.Dir, ".tmp-"+fileName(r.Subject)+"-"+strconv.FormatInt(w.now().UnixNano(), 36))
	// The Postgres process of the stack reads the file under another
	// user, so the file is readable by all.
	if err := os.WriteFile(tmp, encode(r), 0o644); err != nil { //nolint:gosec // G306: the database user reads the row
		return fmt.Errorf("claims: write the row: %w", err)
	}
	if err := os.Chmod(tmp, 0o644); err != nil { //nolint:gosec // G302: the database user reads the row
		return errors.Join(fmt.Errorf("claims: set the mode of the row: %w", err), os.Remove(tmp))
	}
	rename := w.rename
	if rename == nil {
		rename = os.Rename
	}
	if err := rename(tmp, final); err != nil {
		return errors.Join(fmt.Errorf("claims: place the row: %w", err), os.Remove(tmp))
	}
	return nil
}

// Delete removes the row of one subject. A missing row is not an
// error. The holder authorization server calls it when a code comes
// back a second time, so a stolen code issues nothing (RFC 6749
// section 4.1.2).
func (w Writer) Delete(subject string) error {
	err := os.Remove(filepath.Join(w.Dir, fileName(subject)))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("claims: delete the row: %w", err)
	}
	return nil
}

// Find returns the row of one subject.
func (w Writer) Find(subject string) (Row, bool, error) {
	raw, err := os.ReadFile(filepath.Join(w.Dir, fileName(subject))) //nolint:gosec // G304: the name is a hash
	if errors.Is(err, fs.ErrNotExist) {
		return Row{}, false, nil
	}
	if err != nil {
		return Row{}, false, fmt.Errorf("claims: read the row: %w", err)
	}
	r, err := decode(raw)
	if err != nil {
		return Row{}, false, err
	}
	return r, true, nil
}

// Sweep deletes the file of every row whose offer has expired, and of
// every file that does not hold a row. It returns the number it deleted.
func (w Writer) Sweep() (int, error) {
	entries, err := os.ReadDir(w.Dir)
	if err != nil {
		return 0, fmt.Errorf("claims: read the store: %w", err)
	}
	now := w.now()
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".csv") {
			continue
		}
		path := filepath.Join(w.Dir, e.Name())
		raw, err := os.ReadFile(path) //nolint:gosec // G304: the path is an entry of the store
		if err != nil {
			continue
		}
		r, err := decode(raw)
		if err == nil && now.Before(r.ExpiresAt) {
			continue
		}
		if err := os.Remove(path); err == nil {
			removed++
		}
	}
	return removed, nil
}

// encode returns the CSV line of a row. Every field is quoted, so an
// empty value is an empty string and not NULL for file_fdw, and every
// row carries all the columns.
func encode(r Row) []byte {
	fields := []string{
		r.Subject, r.ConfigID, r.ExpiresAt.UTC().Format(time.RFC3339),
		r.ValidFrom, r.ValidUntil, r.StatusURI, r.StatusIndex,
	}
	fields = append(fields, r.Claims...)
	for len(fields) < Columns {
		fields = append(fields, "")
	}
	var b strings.Builder
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(strings.ReplaceAll(f, `"`, `""`))
		b.WriteByte('"')
	}
	b.WriteByte('\n')
	return []byte(b.String())
}

// decode reads the row of one file.
func decode(raw []byte) (Row, error) {
	rd := csv.NewReader(bytes.NewReader(raw))
	rd.FieldsPerRecord = Columns
	fields, err := rd.Read()
	if err != nil {
		return Row{}, fmt.Errorf("claims: read the row: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, fields[2])
	if err != nil {
		return Row{}, fmt.Errorf("claims: read the end of the row: %w", err)
	}
	return Row{
		Subject: fields[0], ConfigID: fields[1], ExpiresAt: expires,
		ValidFrom: fields[3], ValidUntil: fields[4], StatusURI: fields[5], StatusIndex: fields[6],
		Claims: fields[len(reserved):],
	}, nil
}
