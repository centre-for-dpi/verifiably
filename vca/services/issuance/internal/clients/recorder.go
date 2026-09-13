// SPDX-License-Identifier: Apache-2.0

package clients

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// RecordPath is the endpoint of the issued credentials service that
// takes one new record.
//
// The service contract vca.issued.v1 reads and changes records. It has
// no RPC that appends one, so the issuance service sends the record as
// ProtoJSON to this endpoint. A later release of the contract can add an
// Append RPC, and only this file changes.
const RecordPath = "/issued/records"

// ErrNoRecorder reports that no issued credentials service is set.
var ErrNoRecorder = errors.New("clients: no issued credentials URL")

// LogRecorder writes the record to the service log. A deployment
// without an issued credentials service uses it.
func LogRecorder(log *slog.Logger) Recorder {
	if log == nil {
		log = slog.Default()
	}
	return recorderFunc(func(_ context.Context, r *issuedv1.IssuedRecord) (string, error) {
		log.Warn("no issued credentials service, so the record stays in the log only",
			"schema_id", r.GetSchemaId(), "hash", r.GetHash())
		return "", nil
	})
}

// recorderFunc makes a function a Recorder.
type recorderFunc func(ctx context.Context, r *issuedv1.IssuedRecord) (string, error)

func (f recorderFunc) Record(ctx context.Context, r *issuedv1.IssuedRecord) (string, error) {
	return f(ctx, r)
}

// HTTPRecorder sends the record to the issued credentials service.
type HTTPRecorder struct {
	baseURL string
	client  *http.Client
}

// NewHTTPRecorder returns a recorder that posts to the base URL.
func NewHTTPRecorder(baseURL string, client *http.Client) *HTTPRecorder {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPRecorder{baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

// Record stores one issued record and returns its id.
func (h *HTTPRecorder) Record(ctx context.Context, r *issuedv1.IssuedRecord) (string, error) {
	if h == nil || h.baseURL == "" {
		return "", ErrNoRecorder
	}
	body, err := protojson.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("clients: encode the record: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		h.baseURL+RecordPath, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("clients: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("clients: write the record: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("clients: the issued credentials service returned %d: %s",
			resp.StatusCode, string(raw))
	}
	var stored issuedv1.IssuedRecord
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := protojson.Unmarshal(raw, &stored); err != nil {
			return "", fmt.Errorf("clients: read the record answer: %w", err)
		}
	}
	return stored.GetId(), nil
}
