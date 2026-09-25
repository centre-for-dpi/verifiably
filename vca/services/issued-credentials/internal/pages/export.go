// SPDX-License-Identifier: Apache-2.0

package pages

import (
	"bytes"
	"net/http"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
)

// buffer collects the chunks of an export, so a refusal still answers
// with a status before any byte leaves.
type buffer struct{ bytes.Buffer }

// Send keeps one chunk. Writing to a bytes.Buffer never fails.
func (b *buffer) Send(m *issuedv1.ExportResponse) error {
	anyval.DiscardWrite(b.Write(m.GetChunk()))
	return nil
}

// exportAs answers the rows of the search and the filters of the list as
// a file. The CSV guards every cell against a formula; the JSON lines
// keep the values (ADR-017 decision 3). The service writes the audit
// event with the staff member as the actor.
func (p *Pages) exportAs(encoding issuedv1.ExportRequest_Encoding) func(pg page) error {
	name, kind := "issued-credentials.csv", "text/csv; charset=utf-8"
	if encoding == issuedv1.ExportRequest_ENCODING_JSON {
		name, kind = "issued-credentials.jsonl", "application/x-ndjson"
	}
	return func(pg page) error {
		q := readQuery(pg.r.URL.Query())
		var out buffer
		if err := p.opts.Records.ExportTo(pg.ctx(), &issuedv1.ExportRequest{Filter: q.filter, Query: q.text, Encoding: encoding}, &out); err != nil {
			return err
		}
		h := pg.w.Header()
		h.Set("Content-Type", kind)
		h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		pg.w.WriteHeader(http.StatusOK)
		anyval.DiscardWrite(pg.w.Write(out.Bytes()))
		return nil
	}
}
