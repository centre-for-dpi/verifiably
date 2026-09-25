// SPDX-License-Identifier: Apache-2.0

package rpcguard_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1/datasourcev1connect"
	schemabuilderv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schemabuilder/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schemabuilder/v1/schemabuilderv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/rpcguard"
)

// builder answers PreviewCredential to anyone, refuses Import without a
// credential, and does not serve SampleData.
type builder struct {
	schemabuilderv1connect.UnimplementedSchemaBuilderServiceHandler
	importCode connect.Code
}

func (builder) PreviewCredential(context.Context, *connect.Request[schemabuilderv1.PreviewCredentialRequest]) (*connect.Response[schemabuilderv1.PreviewCredentialResponse], error) {
	return connect.NewResponse(&schemabuilderv1.PreviewCredentialResponse{}), nil
}

func (b builder) Import(context.Context, *connect.Request[schemabuilderv1.ImportRequest]) (*connect.Response[schemabuilderv1.ImportResponse], error) {
	return nil, connect.NewError(b.importCode, errors.New("no"))
}

func handler(b builder) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(schemabuilderv1connect.NewSchemaBuilderServiceHandler(b))
	return mux
}

func TestAnonymousReadsTheCodeOfEveryRPC(t *testing.T) {
	got, err := rpcguard.Anonymous(handler(builder{importCode: connect.CodeUnauthenticated}), schemabuilderv1connect.SchemaBuilderServiceName)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]connect.Code{
		"PreviewCredential": 0, "Import": connect.CodeUnauthenticated, "SampleData": connect.CodeUnimplemented,
	}
	if len(got) != len(want) {
		t.Fatalf("codes = %v", got)
	}
	for name, code := range want {
		if got[name] != code {
			t.Errorf("%s = %v, want %v", name, got[name], code)
		}
	}
}

func TestCheckNamesEveryRPCThatLetsTheCallerIn(t *testing.T) {
	h := handler(builder{importCode: connect.CodePermissionDenied})
	problems, err := rpcguard.Check(h, schemabuilderv1connect.SchemaBuilderServiceName)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "PreviewCredential answers ok") {
		t.Errorf("problems = %v", problems)
	}
	problems, err = rpcguard.Check(h, schemabuilderv1connect.SchemaBuilderServiceName, "PreviewCredential")
	if err != nil || len(problems) != 0 {
		t.Errorf("an open RPC is a problem: %v, %v", problems, err)
	}
	problems, err = rpcguard.Check(h, schemabuilderv1connect.SchemaBuilderServiceName, "PreviewCredential", "Missing")
	if err != nil || len(problems) != 1 || !strings.Contains(problems[0], "has no RPC Missing") {
		t.Errorf("an unknown open RPC passed: %v, %v", problems, err)
	}
	// An answer with a code that lets the caller past is a problem too.
	problems, err = rpcguard.Check(handler(builder{importCode: connect.CodeInvalidArgument}), schemabuilderv1connect.SchemaBuilderServiceName, "PreviewCredential")
	if err != nil || len(problems) != 2 || !strings.Contains(strings.Join(problems, "\n"), "Import answers invalid_argument") {
		t.Errorf("problems = %v, %v", problems, err)
	}
}

func TestCheckRefusesAHandlerThatServesNothing(t *testing.T) {
	problems, err := rpcguard.Check(http.NotFoundHandler(), schemabuilderv1connect.SchemaBuilderServiceName)
	if err != nil || len(problems) != 1 || !strings.Contains(problems[0], "does not serve it") {
		t.Errorf("an empty handler passed: %v, %v", problems, err)
	}
}

func TestAnonymousRefusesAWrongName(t *testing.T) {
	for _, name := range []string{"vca.nothing.v1.NoService", "vca.schemabuilder.v1.ImportRequest"} {
		if _, err := rpcguard.Check(http.NotFoundHandler(), name); !errors.Is(err, rpcguard.ErrService) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := rpcguard.Anonymous(http.NotFoundHandler(), datasourcev1connect.DataSourceServiceName); !errors.Is(err, rpcguard.ErrStreaming) {
		t.Errorf("a streaming RPC passed: %v", err)
	}
}

func TestRefused(t *testing.T) {
	for code, want := range map[connect.Code]bool{
		connect.CodeUnauthenticated: true, connect.CodePermissionDenied: true, connect.CodeUnimplemented: true,
		0: false, connect.CodeNotFound: false, connect.CodeInvalidArgument: false,
	} {
		if rpcguard.Refused(code) != want {
			t.Errorf("Refused(%v) = %v", code, !want)
		}
	}
}
