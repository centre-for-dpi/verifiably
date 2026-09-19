// SPDX-License-Identifier: Apache-2.0

package clients

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	issuedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1/issuedv1connect"
)

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

// Appender is the part of the issued credentials contract that the
// issuance service calls. A test passes a fake and needs no server.
type Appender interface {
	// Append records one issuance and returns its id and hash.
	Append(context.Context, *connect.Request[issuedv1.AppendRequest]) (
		*connect.Response[issuedv1.AppendResponse], error)
}

// AppendRecorder writes the record with the Append RPC of the issued
// credentials service (ADR-017 decision 1).
type AppendRecorder struct {
	client Appender
}

// NewAppendRecorder returns a recorder over an Append client.
func NewAppendRecorder(client Appender) *AppendRecorder {
	return &AppendRecorder{client: client}
}

// NewConnectRecorder returns a recorder that calls the Append RPC of
// the service at baseURL.
func NewConnectRecorder(baseURL string, client *http.Client) *AppendRecorder {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		return &AppendRecorder{}
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &AppendRecorder{client: issuedv1connect.NewIssuedServiceClient(client, baseURL)}
}

// Record stores one issued record and returns its id.
func (a *AppendRecorder) Record(ctx context.Context, r *issuedv1.IssuedRecord) (string, error) {
	if a == nil || a.client == nil {
		return "", ErrNoRecorder
	}
	resp, err := a.client.Append(ctx, connect.NewRequest(&issuedv1.AppendRequest{Record: r}))
	if err != nil {
		return "", fmt.Errorf("clients: write the record: %w", err)
	}
	return resp.Msg.GetId(), nil
}
