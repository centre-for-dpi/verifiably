// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/federation"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/httpapi"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
)

// AddRegistry federates with one external registry and reads it once.
// The audit log records the change, also when it fails.
func (s *Service) AddRegistry(ctx context.Context, req *connect.Request[trustv1.AddRegistryRequest]) (res *connect.Response[trustv1.AddRegistryResponse], err error) {
	target := ""
	defer func() {
		s.opts.Audit.Record(ctx, req.Header(), ActionAddRegistry, target, req.Msg.GetRegistry().GetName(), err)
	}()
	r, err := s.opts.Federation.Add(ctx, registryFromProto(req.Msg.GetRegistry()))
	if err != nil {
		return nil, registryError(err)
	}
	target = r.ID
	return connect.NewResponse(&trustv1.AddRegistryResponse{Registry: registryProto(r)}), nil
}

// ListRegistries returns the external registries and the local lists.
func (s *Service) ListRegistries(context.Context, *connect.Request[trustv1.ListRegistriesRequest]) (*connect.Response[trustv1.ListRegistriesResponse], error) {
	resp := &trustv1.ListRegistriesResponse{JwksUrl: publish.JoinURL(s.opts.BaseURL, httpapi.JWKSPath)}
	for _, r := range s.opts.Federation.List() {
		resp.Registries = append(resp.Registries, registryProto(r))
	}
	snap := s.Snapshot()
	for _, m := range snap.Methods() {
		p, _ := snap.Publication(m)
		resp.Local = append(resp.Local, publicationProto(p))
	}
	return connect.NewResponse(resp), nil
}

// RemoveRegistry stops the federation with one registry.
func (s *Service) RemoveRegistry(ctx context.Context, req *connect.Request[trustv1.RemoveRegistryRequest]) (res *connect.Response[trustv1.RemoveRegistryResponse], err error) {
	defer func() { s.opts.Audit.Record(ctx, req.Header(), ActionRemoveRegistry, req.Msg.GetId(), "", err) }()
	found, err := s.opts.Federation.Remove(req.Msg.GetId())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if !found {
		return nil, connect.NewError(connect.CodeNotFound, federation.ErrNotFound)
	}
	return connect.NewResponse(&trustv1.RemoveRegistryResponse{}), nil
}

// SyncRegistry reads one registry now. A failed read is not an RPC
// error: the registry carries the reason in last_error.
func (s *Service) SyncRegistry(ctx context.Context, req *connect.Request[trustv1.SyncRegistryRequest]) (res *connect.Response[trustv1.SyncRegistryResponse], err error) {
	defer func() { s.opts.Audit.Record(ctx, req.Header(), ActionSyncRegistry, req.Msg.GetId(), "", err) }()
	r, err := s.opts.Federation.Sync(ctx, req.Msg.GetId())
	if err != nil {
		return nil, registryError(err)
	}
	return connect.NewResponse(&trustv1.SyncRegistryResponse{Registry: registryProto(r)}), nil
}

// registryError maps a federation error to a Connect error.
func registryError(err error) error {
	switch {
	case errors.Is(err, federation.ErrInvalid):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, federation.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewError(connect.CodeInternal, err)
}

// publicationProto converts one local publication.
func publicationProto(p publish.Publication) *trustv1.PublishResponse_Publication {
	return &trustv1.PublishResponse_Publication{
		Method:      methodProto(p.Method),
		Url:         p.URL,
		EntryCount:  toInt32(int64(p.EntryCount)),
		PublishedAt: timestamppb.New(p.PublishedAt),
		KeyId:       p.KeyID,
	}
}

// registryFromProto reads the fields an admin sets.
func registryFromProto(p *trustv1.Registry) federation.Registry {
	return federation.Registry{
		Name:    p.GetName(),
		Method:  registryMethodName(p.GetMethod()),
		URL:     p.GetUrl(),
		JWKSURL: p.GetAnchor().GetJwksUrl(),
		X509PEM: p.GetAnchor().GetX509Certificate(),
		Refresh: p.GetRefresh().AsDuration(),
	}
}

// registryProto converts a registry with its sync state.
func registryProto(r federation.Registry) *trustv1.Registry {
	p := &trustv1.Registry{
		Id: r.ID, Name: r.Name, Method: registryMethodProto(r.Method), Url: r.URL,
		Anchor:     &trustv1.Registry_Anchor{},
		Refresh:    durationpb.New(r.Refresh),
		LastError:  r.LastError,
		EntryCount: toInt32(int64(r.EntryCount)),
		SignedBy:   r.SignedBy,
	}
	if r.JWKSURL != "" {
		p.Anchor.Anchor = &trustv1.Registry_Anchor_JwksUrl{JwksUrl: r.JWKSURL}
	} else {
		p.Anchor.Anchor = &trustv1.Registry_Anchor_X509Certificate{X509Certificate: r.X509PEM}
	}
	if !r.LastSync.IsZero() {
		p.LastSync = timestamppb.New(r.LastSync)
	}
	if !r.LastRead.IsZero() {
		p.LastRead = timestamppb.New(r.LastRead)
	}
	return p
}

func registryMethodName(m trustv1.RegistryMethod) federation.Method {
	switch m {
	case trustv1.RegistryMethod_REGISTRY_METHOD_ETSI_LOTE_JSON:
		return federation.MethodEtsiLoteJSON
	case trustv1.RegistryMethod_REGISTRY_METHOD_ETSI_TSL_XML:
		return federation.MethodEtsiTslXML
	case trustv1.RegistryMethod_REGISTRY_METHOD_DEDI:
		return federation.MethodDedi
	}
	return ""
}

func registryMethodProto(m federation.Method) trustv1.RegistryMethod {
	switch m {
	case federation.MethodEtsiLoteJSON:
		return trustv1.RegistryMethod_REGISTRY_METHOD_ETSI_LOTE_JSON
	case federation.MethodEtsiTslXML:
		return trustv1.RegistryMethod_REGISTRY_METHOD_ETSI_TSL_XML
	case federation.MethodDedi:
		return trustv1.RegistryMethod_REGISTRY_METHOD_DEDI
	}
	return trustv1.RegistryMethod_REGISTRY_METHOD_UNSPECIFIED
}

// lookupMethod names the publication method of an external answer.
func lookupMethod(m federation.Method) trustv1.Method {
	if m == federation.MethodDedi {
		return trustv1.Method_METHOD_DEDI
	}
	return trustv1.Method_METHOD_ETSI
}
