// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"testing"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/verifierauth/v1/verifierauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/rpcguard"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-auth/internal/server"
)

// TestAnonymousRPCsAreRefused is ADR-047 decision 1. The reverse proxy
// publishes the VerifierAuthService and the AdminService of verifier-auth, so
// every RPC refuses a caller with no credential. The login RPCs are
// open by design, as the login pages under /auth are: ListProviders
// lists the public providers, LoginStart starts a PKCE login,
// LoginCallback needs the state of that login, and Introspect answers
// active false without a valid session token.
func TestAnonymousRPCsAreRefused(t *testing.T) {
	svc, err := server.Build(baseConfig(t), quiet)
	if err != nil {
		t.Fatal(err)
	}
	h := server.Handler(svc)
	for service, open := range map[string][]string{
		verifierauthv1connect.VerifierAuthServiceName: {"ListProviders", "LoginStart", "LoginCallback", "Introspect"},
		adminv1connect.AdminServiceName:               nil,
	} {
		problems, err := rpcguard.Check(h, service, open...)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range problems {
			t.Error(p)
		}
	}
}
