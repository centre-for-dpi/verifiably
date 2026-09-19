// SPDX-License-Identifier: Apache-2.0

// Package csvsrc reads rows from a CSV file with encoding/csv
// (ADR-015 decision 1). It caps the input size and needs UTF-8.
package csvsrc

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/table"
)

// Errors the package returns.
var (
	ErrTooLarge   = errors.New("csvsrc: the file is larger than the limit")
	ErrNotUTF8    = errors.New("csvsrc: the file is not valid UTF-8")
	ErrBadCSV     = errors.New("csvsrc: the file is not valid CSV")
	ErrBadOptions = errors.New("csvsrc: the options are not valid")
)

// DefaultMaxBytes caps a file when Options.MaxBytes is zero.
const DefaultMaxBytes = 32 << 20

// Options control the parse.
type Options struct {
	// Delimiter is the field separator. Empty means a comma.
	Delimiter string
	// HasHeader says the first row holds the field names.
	HasHeader bool
	// Encoding is the character encoding. Empty or utf-8 only.
	Encoding string
	// MaxBytes caps the input. Zero means DefaultMaxBytes.
	MaxBytes int64
}

// Validate checks the options.
func (o Options) Validate() error {
	if utf8.RuneCountInString(o.Delimiter) > 1 {
		return fmt.Errorf("%w: delimiter must be one character", ErrBadOptions)
	}
	if o.Delimiter == "\"" || o.Delimiter == "\n" || o.Delimiter == "\r" {
		return fmt.Errorf("%w: delimiter %q is not allowed", ErrBadOptions, o.Delimiter)
	}
	switch strings.ToLower(o.Encoding) {
	case "", "utf-8", "utf8":
		return nil
	}
	return fmt.Errorf("%w: encoding %q is not supported, use UTF-8", ErrBadOptions, o.Encoding)
}

// Parse reads every row of r. Without a header the fields are named
// column_1, column_2, and so on. A row with fewer values than fields
// leaves the missing fields empty.
func Parse(r io.Reader, o Options) (table.Table, error) {
	if err := o.Validate(); err != nil {
		return table.Table{}, err
	}
	maxBytes := o.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return table.Table{}, fmt.Errorf("csvsrc: read: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return table.Table{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, maxBytes)
	}
	if !utf8.Valid(data) {
		return table.Table{}, ErrNotUTF8
	}
	rd := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(data), "\xef\xbb\xbf")))
	if o.Delimiter != "" {
		rd.Comma, _ = utf8.DecodeRuneInString(o.Delimiter)
	}
	rd.FieldsPerRecord = -1
	rd.TrimLeadingSpace = true
	records, err := rd.ReadAll()
	if err != nil {
		return table.Table{}, fmt.Errorf("%w: %w", ErrBadCSV, err)
	}
	var fields []string
	if o.HasHeader && len(records) > 0 {
		fields = headerNames(records[0])
		records = records[1:]
	}
	rows := make([]map[string]string, 0, len(records))
	for _, rec := range records {
		for len(fields) < len(rec) {
			fields = append(fields, "column_"+strconv.Itoa(len(fields)+1))
		}
		row := make(map[string]string, len(fields))
		for i, name := range fields {
			if i < len(rec) {
				row[name] = rec[i]
			} else {
				row[name] = ""
			}
		}
		rows = append(rows, row)
	}
	return table.Table{Fields: fields, Rows: rows, Total: int64(len(rows))}, nil
}

// headerNames trims names and fills empty or repeated names.
func headerNames(rec []string) []string {
	out := make([]string, len(rec))
	seen := map[string]bool{}
	for i, n := range rec {
		n = strings.TrimSpace(n)
		if n == "" {
			n = "column_" + strconv.Itoa(i+1)
		}
		for base, k := n, 2; seen[n]; k++ {
			n = base + "_" + strconv.Itoa(k)
		}
		seen[n] = true
		out[i] = n
	}
	return out
}
