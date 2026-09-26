// SPDX-License-Identifier: Apache-2.0

// Package reader opens a stored source and returns its rows as a table.
// It resolves secret references at use time and passes the values to the
// source readers only (ADR-015 decision 2). The values never leave the
// call.
package reader

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/csvsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/httpsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/secrets"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/source"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/sqlsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/table"
)

// Errors the package returns.
var (
	ErrCSVRef   = errors.New("reader: the csv file reference is not a plain file name or a data URL")
	ErrNoCSVDir = errors.New("reader: the deployment has no csv directory")
	ErrField    = errors.New("reader: the source has no such field")
)

// DataPrefix starts a file reference that carries the CSV bytes inline.
const DataPrefix = "data:text/csv;base64,"

// Reader opens sources.
type Reader struct {
	// Secrets resolves secret references.
	Secrets secrets.Resolver
	// HTTP reads HTTP sources.
	HTTP httpsrc.Fetcher
	// SQL reads SQL sources.
	SQL sqlsrc.Reader
	// CSVDir is the directory of uploaded CSV files. Empty allows data
	// URLs only.
	CSVDir string
	// ReadFile reads a CSV file, for example os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// CSVMaxBytes caps a CSV file. Zero means csvsrc.DefaultMaxBytes.
	CSVMaxBytes int64
}

// Read returns the rows of src.
func (r Reader) Read(ctx context.Context, src source.Source) (table.Table, error) {
	switch src.Kind {
	case source.KindCSV:
		return r.readCSV(*src.CSV)
	case source.KindHTTP:
		return r.readHTTP(ctx, *src.HTTP)
	case source.KindSQL:
		return r.readSQL(ctx, *src.SQL)
	}
	return table.Table{}, fmt.Errorf("%w: kind %q", source.ErrInvalid, src.Kind)
}

// Match returns the rows of src whose field holds value. An SQL source
// filters in the database. A CSV or an HTTP source is read, then
// filtered here. A field that the source does not hold is ErrField.
func (r Reader) Match(ctx context.Context, src source.Source, field, value string) (table.Table, error) {
	if src.Kind == source.KindSQL {
		dsn, err := r.Secrets.Resolve(src.SQL.DSN)
		if err != nil {
			return table.Table{}, err
		}
		tb, err := r.SQL.Match(ctx, sqlsrc.Request{Driver: src.SQL.Driver, DSN: dsn, Query: src.SQL.Query, Timeout: src.SQL.Timeout}, field, value)
		if errors.Is(err, sqlsrc.ErrField) {
			return table.Table{}, fmt.Errorf("%w: %q", ErrField, field)
		}
		return tb, err
	}
	tb, err := r.Read(ctx, src)
	if err != nil {
		return table.Table{}, err
	}
	if !slices.Contains(tb.Fields, field) && !slices.Contains(table.FieldsOf(tb.Rows, nil), field) {
		return table.Table{}, fmt.Errorf("%w: %q", ErrField, field)
	}
	var rows []map[string]string
	for _, row := range tb.Rows {
		if row[field] == value {
			rows = append(rows, row)
		}
	}
	return table.Table{Fields: tb.Fields, Rows: rows, Total: int64(len(rows))}, nil
}

func (r Reader) readCSV(c source.CSV) (table.Table, error) {
	data, err := r.csvBytes(c.FileRef)
	if err != nil {
		return table.Table{}, err
	}
	return csvsrc.Parse(bytes.NewReader(data), csvsrc.Options{Delimiter: c.Delimiter, HasHeader: c.HasHeader, Encoding: c.Encoding, MaxBytes: r.CSVMaxBytes})
}

func (r Reader) csvBytes(ref string) ([]byte, error) {
	if strings.HasPrefix(ref, DataPrefix) {
		data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ref, DataPrefix))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCSVRef, err)
		}
		return data, nil
	}
	if ref == "" || ref != filepath.Base(ref) || strings.HasPrefix(ref, ".") {
		return nil, fmt.Errorf("%w: %q", ErrCSVRef, ref)
	}
	if r.CSVDir == "" || r.ReadFile == nil {
		return nil, ErrNoCSVDir
	}
	data, err := r.ReadFile(filepath.Join(r.CSVDir, ref))
	if err != nil {
		return nil, fmt.Errorf("reader: read csv %s: %w", ref, err)
	}
	return data, nil
}

func (r Reader) readHTTP(ctx context.Context, h source.HTTP) (table.Table, error) {
	req := httpsrc.Request{URL: h.URL, Method: h.Method, Headers: h.Headers, RowsPath: h.RowsPath, Timeout: h.Timeout}
	var err error
	switch {
	case !h.Bearer.IsZero():
		req.Auth.Bearer, err = r.Secrets.Resolve(h.Bearer)
	case !h.BasicPass.IsZero():
		req.Auth.BasicUser = h.BasicUser
		req.Auth.BasicPassword, err = r.Secrets.Resolve(h.BasicPass)
	case !h.MTLSCert.IsZero():
		var cert, key string
		if cert, err = r.Secrets.Resolve(h.MTLSCert); err == nil {
			key, err = r.Secrets.Resolve(h.MTLSKey)
		}
		req.Auth.CertPEM, req.Auth.KeyPEM = []byte(cert), []byte(key)
	}
	if err != nil {
		return table.Table{}, err
	}
	return r.HTTP.Fetch(ctx, req)
}

func (r Reader) readSQL(ctx context.Context, q source.SQL) (table.Table, error) {
	dsn, err := r.Secrets.Resolve(q.DSN)
	if err != nil {
		return table.Table{}, err
	}
	return r.SQL.Read(ctx, sqlsrc.Request{Driver: q.Driver, DSN: dsn, Query: q.Query, Timeout: q.Timeout})
}
