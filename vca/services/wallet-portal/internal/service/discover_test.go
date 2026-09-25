// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/issuers"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/ports"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// peerDocs serves the metadata of one live issuer pair at its internal
// address.
type peerDocs map[string]string

func (d peerDocs) Get(_ context.Context, url string) (fetchguard.Doc, error) {
	body, ok := d[url]
	if !ok {
		return fetchguard.Doc{}, errors.New("not found")
	}
	return fetchguard.Doc{URL: url, Body: []byte(body)}, nil
}

// crawler returns the fallback crawler over one live issuer pair whose
// metadata names the pre-authorized grant.
func crawler(t *testing.T) *issuers.Crawler {
	t.Helper()
	c, err := issuers.New(issuers.Options{
		Peers: func(context.Context) []issuers.Source {
			return []issuers.Source{{Endpoint: "http://issuer-a-registry:8084", Public: "https://a.example", Peer: true}}
		},
		Internal: peerDocs{"http://issuer-a-registry:8084/.well-known/openid-credential-issuer": `{"credential_issuer":"https://a.example",` +
			`"grant_types_supported":["urn:ietf:params:oauth:grant-type:pre-authorized_code"],` +
			`"credential_configurations_supported":{"trade":{"format":"mso_mdoc","doctype":"org.example.trade.1"}}}`},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func discover(t *testing.T, svc *service.Service) []*walletportalv1.Offering {
	t.Helper()
	resp, err := svc.ListDiscoverable(ctx(), connect.NewRequest(&walletportalv1.ListDiscoverableRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return resp.Msg.GetOfferings()
}

// TestDiscoverFallsBackToPeerMetadata checks spec HO1 with no verifier
// pair: a deployment with no catalogue, or a catalogue that does not
// answer, reads the metadata of the live issuer pairs instead.
func TestDiscoverFallsBackToPeerMetadata(t *testing.T) {
	for name, cat := range map[string]ports.Catalogue{
		"no catalogue": nil,
		"catalogue down": ports.CatalogueFunc(func(context.Context) ([]*walletportalv1.Offering, error) {
			return nil, errors.New("verifier-discovery does not resolve")
		}),
	} {
		c := crawler(t)
		svc := build(t, func(o *service.Options) { o.Catalogue, o.Fallback = cat, c })
		got := discover(t, svc)
		if len(got) != 1 || got[0].GetSchema().GetType() != "org.example.trade.1" || got[0].GetCredentialIssuer() != "https://a.example" {
			t.Fatalf("%s: offerings = %v", name, got)
		}
		if m := got[0].GetClaimMethods(); len(m) != 1 || m[0] != walletportalv1.ClaimMethod_CLAIM_METHOD_PRE_AUTHORIZED_CODE {
			t.Fatalf("%s: methods = %v", name, m)
		}
	}
}

// TestDiscoverUsesCatalogWhenPresent checks that the catalogue of the
// verifier discovery service wins when it answers. The wallet adds the
// ways to claim of each issuer, which the catalogue does not carry.
func TestDiscoverUsesCatalogWhenPresent(t *testing.T) {
	fallback := ports.CatalogueFunc(func(context.Context) ([]*walletportalv1.Offering, error) {
		t.Fatal("the fallback must not run while the catalogue answers")
		return nil, nil
	})
	asked := map[string]int{}
	svc := build(t, func(o *service.Options) {
		o.Fallback = fallback
		o.Methods = func(_ context.Context, issuer string) []walletportalv1.ClaimMethod {
			asked[issuer]++
			if issuer == "https://a.example" {
				return []walletportalv1.ClaimMethod{walletportalv1.ClaimMethod_CLAIM_METHOD_AUTHORIZATION_CODE}
			}
			return nil
		}
	})
	got := discover(t, svc)
	if len(got) != 2 || got[0].GetSchema().GetType() != "DriverLicence" {
		t.Fatalf("offerings = %v", got)
	}
	if m := got[0].GetClaimMethods(); len(m) != 1 || m[0] != walletportalv1.ClaimMethod_CLAIM_METHOD_AUTHORIZATION_CODE {
		t.Fatalf("methods = %v", m)
	}
	if len(got[1].GetClaimMethods()) != 0 || asked["https://a.example"] != 1 {
		t.Fatalf("second = %v asked = %v", got[1], asked)
	}
	// With neither a catalogue nor a fallback the page has nothing.
	none := build(t, func(o *service.Options) { o.Catalogue = nil })
	if _, err := none.ListDiscoverable(ctx(), connect.NewRequest(&walletportalv1.ListDiscoverableRequest{})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("none: %v", err)
	}
}
