// SPDX-License-Identifier: Apache-2.0

// Package peertest gives the tests of a service a peer authority and
// identities of it (ADR-075). Only tests import it.
package peertest

import (
	"crypto/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/centre-for-dpi/vc-adapters/internal/peerauth"
)

// Caller is the name of the identity that Client signs with.
const Caller = "peertest"

// Kit is the authority of one test deployment.
type Kit struct {
	t testing.TB
	a peerauth.Authority
}

// New makes the authority of a test.
func New(t testing.TB) *Kit {
	t.Helper()
	a, err := peerauth.NewAuthority(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Kit{t: t, a: a}
}

// Fixed makes an authority for the helpers of a test package that have
// no *testing.T at hand. A test file keeps it in a package variable. It
// panics when the system has no randomness.
func Fixed() *Kit {
	a, err := peerauth.NewAuthority(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Kit{a: a}
}

// fail stops the test, or panics for a Fixed kit.
func (k *Kit) fail(err error) {
	if k.t == nil {
		panic(err)
	}
	k.t.Helper()
	k.t.Fatal(err)
}

// testHosts returns the names of a test server: the loopback address
// of httptest.NewServer and the host of httptest.NewRequest. A callee
// of the kit takes a token for any of them.
func testHosts() []string { return []string{"127.0.0.1", "localhost", "example.com"} }

// Identity issues the identity of one service with the callers given.
// The service takes the tokens of its callers at the hosts of a test
// server.
func (k *Kit) Identity(service string, callers peerauth.Callers) peerauth.Settings {
	s, err := k.a.Issue(peerauth.ID{Service: service, Pair: "test"}, rand.Reader, time.Now())
	if err != nil {
		k.fail(err)
	}
	s.Callers = callers
	s.Hosts = testHosts()
	return s
}

// caller issues the identity of Caller. It is deployment scoped, as the
// vca command is, so a callee takes its token at any host.
func (k *Kit) caller() peerauth.Settings {
	s, err := k.a.Issue(peerauth.ID{Service: Caller, Deployment: true}, rand.Reader, time.Now())
	if err != nil {
		k.fail(err)
	}
	return s
}

// Open issues the identity of a service that lets Caller, and the
// services named in also, call every VCA Connect service linked into
// the test.
func (k *Kit) Open(service string, also ...string) peerauth.Settings {
	callers := peerauth.Callers{}
	who := append([]string{Caller}, also...)
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if !strings.HasPrefix(string(fd.Package()), "vca.") {
			return true
		}
		for i := 0; i < fd.Services().Len(); i++ {
			callers[string(fd.Services().Get(i).FullName())] = who
		}
		return true
	})
	return k.Identity(service, callers)
}

// Client returns a copy of c that signs every request to a VCA
// procedure path as Caller, a plain JSON post too. A nil c stands for
// http.DefaultClient.
func (k *Kit) Client(c *http.Client) *http.Client {
	out := &http.Client{}
	if c != nil {
		copied := *c
		out = &copied
	}
	base := out.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	out.Transport = signAll{base: base, id: k.caller()}
	return out
}

// Sign puts the identity headers of Caller on r, for a test that
// serves r with a handler directly.
func (k *Kit) Sign(r *http.Request) {
	h, err := k.caller().Header(r.URL.Path, r.URL.Host)
	if err != nil {
		k.fail(err)
	}
	for name, values := range h {
		r.Header[name] = values
	}
}

// signAll signs every request whose path names a VCA procedure.
type signAll struct {
	base http.RoundTripper
	id   peerauth.Settings
}

// RoundTrip implements http.RoundTripper.
func (s signAll) RoundTrip(r *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(r.URL.Path, "/vca.") {
		return s.base.RoundTrip(r)
	}
	h, err := s.id.Header(r.URL.Path, r.URL.Host)
	if err != nil {
		return nil, err
	}
	signed := r.Clone(r.Context())
	for name, values := range h {
		signed.Header[name] = values
	}
	return s.base.RoundTrip(signed)
}
