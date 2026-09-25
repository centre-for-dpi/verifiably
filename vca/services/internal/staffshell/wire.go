// SPDX-License-Identifier: Apache-2.0

package staffshell

import (
	"context"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	issuerauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1/issuerauthv1connect"
	verifierauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/verifierauth/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/verifierauth/v1/verifierauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
)

// Setup is what a service of the issuer or the verifier knows at start.
type Setup struct {
	// Role is the staff role of the pages.
	Role commonv1.Role
	// Peers are the candidate pairs, from VCA_PEERS.
	Peers []topology.Peer
	// Auth are the settings of the staff guard of the service.
	Auth staffsession.Settings
	// PublicURL is the public URL of the pair. An https URL makes the
	// cookie that clears the session Secure.
	PublicURL string
	// SignOut is the path of the sign out form of the service.
	SignOut string
	// Home is the target of the wordmark. Empty means the home of the role.
	Home string
	// Prober replaces the probe of the peers. Nil builds one when the
	// deployment names peers.
	Prober *topology.Prober
	// Client calls the auth service. Nil means a client with a 10 s timeout.
	Client connect.HTTPClient
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Wire builds the shell of a service and the handler of its sign out
// form, so every service of a role wires them the same way.
func Wire(s Setup) (*Shell, http.Handler) {
	prober := s.Prober
	if prober == nil && len(s.Peers) > 0 {
		prober = &topology.Prober{Peers: s.Peers, Now: s.Now}
	}
	var snapshot func(context.Context) topology.Snapshot
	if prober != nil {
		snapshot = prober.Snapshot
	}
	shell := New(Options{
		Role: s.Role, Peers: s.Peers, Snapshot: snapshot, JWKSURL: s.Auth.JWKSURL, Home: s.Home, SignOut: s.SignOut,
	})
	realm, _ := staffsession.RealmOf(s.Role)
	o := SignOutOptions{Cookie: realm.Cookie, After: s.Auth.LoginURL, Secure: strings.HasPrefix(s.PublicURL, "https://")}
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if auth := shell.AuthURL(); auth != "" {
		o.Logout = logout(s.Role, client, auth)
	}
	return shell, SignOut(o)
}

// logout returns the call that ends a session at the auth service of a
// role, or nil for a role with no staff auth service.
func logout(role commonv1.Role, client connect.HTTPClient, auth string) func(context.Context, string) (string, error) {
	switch role {
	case commonv1.Role_ROLE_ISSUER:
		c := issuerauthv1connect.NewIssuerAuthServiceClient(client, auth)
		return func(ctx context.Context, token string) (string, error) {
			res, err := c.Logout(ctx, connect.NewRequest(&issuerauthv1.LogoutRequest{SessionToken: token}))
			if err != nil {
				return "", err
			}
			return res.Msg.GetProviderLogoutUrl(), nil
		}
	case commonv1.Role_ROLE_VERIFIER:
		c := verifierauthv1connect.NewVerifierAuthServiceClient(client, auth)
		return func(ctx context.Context, token string) (string, error) {
			res, err := c.Logout(ctx, connect.NewRequest(&verifierauthv1.LogoutRequest{SessionToken: token}))
			if err != nil {
				return "", err
			}
			return res.Msg.GetProviderLogoutUrl(), nil
		}
	default:
		return nil
	}
}
