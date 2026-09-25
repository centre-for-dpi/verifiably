// SPDX-License-Identifier: Apache-2.0

// Package rpcguard calls a Connect service as a caller on the internet
// with no credential can call it. The reverse proxy publishes a Connect
// service only when every RPC of it checks the caller (ADR-047 decision
// 1). The test of each such service runs Check on the handler that the
// service mounts, so a new RPC without a check fails that test.
package rpcguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// ErrService reports a name that is not a Connect service of the
// generated code.
var ErrService = errors.New("rpcguard: no such service")

// ErrStreaming reports a streaming RPC. Check calls unary RPCs only, so
// a public service with a streaming RPC needs its own test.
var ErrStreaming = errors.New("rpcguard: a streaming RPC")

// Refused reports whether a code means that the service did nothing for
// the caller: it asked for a credential, it refused the credential, or
// it does not serve the RPC.
func Refused(c connect.Code) bool {
	switch c {
	case connect.CodeUnauthenticated, connect.CodePermissionDenied, connect.CodeUnimplemented:
		return true
	default:
		return false
	}
}

// Anonymous calls every RPC of the named service on h with an empty JSON
// message and no credential. It returns the Connect code of each answer
// by RPC name. A success gives code 0. The generated code of the service
// must be linked into the program, as it is when h serves the service.
func Anonymous(h http.Handler, service string) (map[string]connect.Code, error) {
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(service))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrService, service)
	}
	sd, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrService, service)
	}
	out := map[string]connect.Code{}
	methods := sd.Methods()
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		if m.IsStreamingClient() || m.IsStreamingServer() {
			return nil, fmt.Errorf("%w: %s/%s", ErrStreaming, service, m.Name())
		}
		out[string(m.Name())] = call(h, "/"+service+"/"+string(m.Name()))
	}
	return out, nil
}

// call sends one unary request of the Connect protocol and reads the
// code of the answer.
func call(h http.Handler, path string) connect.Code {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		return 0
	}
	var answer struct {
		Code string `json:"code"`
	}
	var code connect.Code
	if json.Unmarshal(rec.Body.Bytes(), &answer) != nil || code.UnmarshalText([]byte(answer.Code)) != nil {
		// A handler that is not Connect, such as a 404 of the mux,
		// served nothing.
		return connect.CodeUnimplemented
	}
	return code
}

// Check calls every RPC of the service on h with no credential. It
// returns one line for each RPC that the caller gets past, unless open
// names it, and one line for each name in open that the service does
// not have. An empty result means that every RPC outside open refuses
// the caller.
func Check(h http.Handler, service string, open ...string) ([]string, error) {
	codes, err := Anonymous(h, service)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	var out []string
	asked := false
	for _, code := range codes {
		asked = asked || code == connect.CodeUnauthenticated || code == connect.CodePermissionDenied
	}
	if !asked {
		// A handler that serves another service answers unimplemented to
		// every RPC, which proves nothing.
		out = append(out, fmt.Sprintf("no RPC of %s asks for a credential, so the handler does not serve it", service))
	}
	for _, name := range open {
		allowed[name] = true
		if _, ok := codes[name]; !ok {
			out = append(out, fmt.Sprintf("%s has no RPC %s", service, name))
		}
	}
	for name, code := range codes {
		if allowed[name] || Refused(code) {
			continue
		}
		answer := "ok"
		if code != 0 {
			answer = code.String()
		}
		out = append(out, fmt.Sprintf("%s/%s answers %s to a caller with no credential", service, name, answer))
	}
	sort.Strings(out)
	return out, nil
}
