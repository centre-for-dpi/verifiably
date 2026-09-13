// SPDX-License-Identifier: Apache-2.0

// Package export renders issued records as CSV or as JSON lines
// (ADR-017 decision 3). The export holds the same fields as the portal
// list. It holds no personal data beyond the searchable claims the
// issuer marked.
//
// The package is pure. It returns bytes. The service splits the bytes
// into stream chunks.
package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
)

// ChunkSize is the number of bytes in one stream chunk.
const ChunkSize = 32 * 1024

// Columns are the fixed CSV columns, in order. The searchable claim
// columns follow them, sorted by name.
var Columns = []string{
	"id",
	"schema_id",
	"schema_version",
	"subject_ref",
	"format",
	"status",
	"dpg",
	"issued_at",
	"valid_from",
	"valid_until",
	"offer_id",
	"status_list_kind",
	"status_list_id",
	"status_list_index",
	"status_changed_at",
	"status_reason",
	"hash",
	"previous_hash",
	"record_hash",
}

// CSV writes rs to out as RFC 4180 CSV with a header row.
func CSV(out io.Writer, rs []record.Record) error {
	claims := record.ClaimNames(rs)
	w := csv.NewWriter(out)
	if err := w.Write(append(append([]string{}, Columns...), claims...)); err != nil {
		return fmt.Errorf("export: write the header: %w", err)
	}
	for _, r := range rs {
		row := fixed(r)
		for _, name := range claims {
			row = append(row, r.SearchableClaims[name])
		}
		if err := w.Write(row); err != nil {
			return fmt.Errorf("export: write a row: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("export: flush: %w", err)
	}
	return nil
}

// fixed returns the fixed columns of r as strings.
func fixed(r record.Record) []string {
	index := ""
	if !r.Binding.IsZero() {
		index = strconv.FormatInt(r.Binding.Index, 10)
	}
	return []string{
		r.ID,
		r.SchemaID,
		strconv.Itoa(r.SchemaVersion),
		r.SubjectRef,
		r.Format,
		string(r.Status),
		r.DPG,
		stamp(r.IssuedAt),
		stamp(r.ValidFrom),
		stamp(r.ValidUntil),
		r.OfferID,
		string(r.Binding.Kind),
		r.Binding.ListID,
		index,
		stamp(r.StatusChangedAt),
		r.StatusReason,
		r.Hash,
		r.PreviousHash,
		r.RecordHash,
	}
}

// stamp returns t in RFC 3339. A zero time returns an empty string.
func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// JSON writes rs to out as one JSON object per line.
func JSON(out io.Writer, rs []record.Record) error {
	enc := json.NewEncoder(out)
	for _, r := range rs {
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("export: encode a record: %w", err)
		}
	}
	return nil
}

// Bytes runs write over a buffer and returns the bytes it produced.
func Bytes(rs []record.Record, write func(io.Writer, []record.Record) error) ([]byte, error) {
	var buf bytes.Buffer
	if err := write(&buf, rs); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Chunks splits data into pieces of at most size bytes. Empty data
// returns one empty chunk, so the stream always has a last message.
func Chunks(data []byte, size int) [][]byte {
	if size <= 0 {
		size = ChunkSize
	}
	if len(data) == 0 {
		return [][]byte{{}}
	}
	out := make([][]byte, 0, (len(data)+size-1)/size)
	for start := 0; start < len(data); start += size {
		end := start + size
		if end > len(data) {
			end = len(data)
		}
		out = append(out, data[start:end])
	}
	return out
}
