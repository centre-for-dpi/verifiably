// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
)

// TestPublishNamesTheVctOfAnSdJwtFormat: the issuer metadata of the
// registry names the vct of an SD-JWT VC as a URL under the registry.
// A verifier asks for that vct, so the registration of an SD-JWT format
// carries the same vct, and the stack signs it into the credential. A
// type that is a URL stays as it is. The other formats carry the type.
func TestPublishNamesTheVctOfAnSdJwtFormat(t *testing.T) {
	for typ, vct := range map[string]string{
		"Degree": "https://r/.well-known/vct/Degree", "https://example.org/vct/Licence": "https://example.org/vct/Licence",
	} {
		s, fb := newService(t, &fakeBackend{})
		m := schema(typ)
		m.Formats = []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_VC_SD_JWT, commonv1.Format_FORMAT_LDP_VC}
		created, err := s.Create(context.Background(), connect.NewRequest(&schemav1.CreateRequest{Schema: m}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Publish(context.Background(), connect.NewRequest(&schemav1.PublishRequest{Id: created.Msg.GetSchema().GetId()})); err != nil {
			t.Fatal(err)
		}
		for _, c := range fb.calls {
			want := vct
			if c.GetFormat() == commonv1.Format_FORMAT_LDP_VC {
				want = typ
			}
			if c.GetType() != want {
				t.Errorf("%s: %v registers the type %q, want %q", typ, c.GetFormat(), c.GetType(), want)
			}
		}
	}
}
