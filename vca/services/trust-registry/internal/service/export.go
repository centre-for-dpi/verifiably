// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"fmt"

	"connectrpc.com/connect"

	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/trustsnap"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/etsi"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
)

// ExportSnapshot signs every entry a lookup reads: the published local
// entries, then the live copy of each external registry with its
// provenance (ADR-041 decision 1). The verifier policy service keeps it
// for checks with no network.
func (s *Service) ExportSnapshot(context.Context, *connect.Request[trustv1.ExportSnapshotRequest]) (*connect.Response[trustv1.ExportSnapshotResponse], error) {
	now := s.opts.Now()
	localURL := publish.JoinURL(s.opts.BaseURL, etsi.PathJWS)
	if p, ok := s.Snapshot().Publication(publish.MethodEtsi); ok {
		localURL = p.URL
	}
	local, err := entities(entry.Published(s.opts.Store.List()))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	claims := trustsnap.Claims{
		Issuer: s.opts.Issuer.ID, IssuedAt: now.Unix(), ExpiresAt: now.Add(s.opts.ListTTL).Unix(),
		Lists: []trustsnap.List{{ListURL: localURL, SignedBy: s.opts.Ring.Active().ID, CheckedAt: now, Entities: local}},
	}
	for _, c := range s.opts.Federation.Copies() {
		list, lerr := entities(c.Snapshot.Entries)
		if lerr != nil {
			return nil, connect.NewError(connect.CodeInternal, lerr)
		}
		claims.Lists = append(claims.Lists, trustsnap.List{
			RegistryID: c.Registry.ID, RegistryName: c.Registry.Name, ListURL: c.Snapshot.ListURL,
			SignedBy: c.Snapshot.SignedBy, CheckedAt: c.Snapshot.CheckedAt, X509Chain: c.Registry.X509PEM, Entities: list,
		})
	}
	token, err := s.opts.Ring.Sign(trustsnap.Type, claims)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	n := int32(min(claims.Count(), maxCount)) // #nosec G115 -- min caps the value
	return connect.NewResponse(&trustv1.ExportSnapshotResponse{Jws: token, EntryCount: n}), nil
}

// maxCount caps a count that goes into an int32 field.
const maxCount = 1<<31 - 1

// entities converts entries to the entities of the snapshot through the
// JSON form of the ETSI list, so both stay the same.
func entities(entries []entry.Entry) ([]trustsnap.Entity, error) {
	list := make([]etsi.Entity, 0, len(entries))
	for _, e := range entries {
		list = append(list, etsi.FromEntry(e))
	}
	raw, err := json.Marshal(list)
	if err != nil {
		return nil, fmt.Errorf("service: encode entities: %w", err)
	}
	out := []trustsnap.Entity{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("service: decode entities: %w", err)
	}
	return out, nil
}
