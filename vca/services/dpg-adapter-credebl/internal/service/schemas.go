// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
)

// Schemas beyond the SD-JWT templates (P6-C2). An AnonCreds
// configuration writes a schema and its credential definition on the
// Indy ledger where the organisation of the adapter holds a DID. A W3C
// JSON-LD configuration writes a schema with no ledger, which the schema
// file server of the stack keeps. The capability answer lists both in
// schema_formats and the ledgers in ledgers. It lists neither format as
// an issue format: the platform issues them over DIDComm (P6-C3).

// ledgerTTL is how long the adapter keeps the ledgers of the capability
// answer before it reads the platform again.
const ledgerTTL = time.Minute

// schemaVersion is the version of every AnonCreds schema the adapter
// writes. A new version of a VCA schema is a new type on the ledger.
const schemaVersion = "1.0"

// credDefTag is the tag of every credential definition the adapter
// writes.
const credDefTag = "default"

// registerAnonCreds writes the schema and the credential definition of
// one AnonCreds configuration and returns the credential definition id.
func (s *Service) registerAnonCreds(
	ctx context.Context, cfg *backendv1.CredentialConfiguration,
) (*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error) {
	ledger := strings.TrimSpace(cfg.GetLedger())
	if ledger == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("an AnonCreds configuration names its ledger"))
	}
	attributes, err := schemaAttributes(cfg, anonCredsType)
	if err != nil {
		return nil, err
	}
	dids, err := s.client.OrgDids(ctx, s.client.OrgID())
	if err != nil {
		return nil, failed("read the DIDs of the organisation", err)
	}
	did := ""
	for _, d := range dids {
		if ns, ok := credebl.IndyNamespace(d.Did); ok && ns == ledger && did == "" {
			did = d.Did
		}
	}
	if did == "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("the organisation holds no DID on the ledger %s; add one in the platform", ledger))
	}
	// A registration again finds what the first one wrote, so the
	// ledger sees one write of each (ADR-077 decision 2).
	schemaID, err := s.findIndySchema(ctx, cfg.GetType(), ledger)
	if err != nil {
		return nil, failed("read the schemas of the organisation", err)
	}
	if schemaID == "" {
		schemaID, err = s.client.CreateIndySchema(ctx, cfg.GetType(), schemaVersion, did, attributes)
		if err != nil {
			return nil, failed("write the schema on the ledger", err)
		}
	}
	credDef, err := s.findCredDef(ctx, schemaID)
	if err != nil {
		return nil, failed("read the credential definitions of the schema", err)
	}
	if credDef == "" {
		credDef, err = s.client.CreateCredentialDefinition(ctx, schemaID, did, credDefTag)
		if err != nil {
			return nil, failed("write the credential definition on the ledger", err)
		}
	}
	return connect.NewResponse(&backendv1.RegisterCredentialConfigurationResponse{Id: credDef}), nil
}

// findIndySchema returns the ledger id of the AnonCreds schema of the
// name and of schemaVersion that the organisation wrote on the ledger,
// or the empty string.
func (s *Service) findIndySchema(ctx context.Context, name, ledger string) (string, error) {
	schemas, err := s.client.OrgSchemas(ctx, name)
	if err != nil {
		return "", err
	}
	for _, sc := range schemas {
		ns, ok := credebl.IndyNamespace(sc.IssuerID)
		if sc.Name == name && sc.Version == schemaVersion && !sc.NoLedger() && ok && ns == ledger {
			return sc.LedgerID, nil
		}
	}
	return "", nil
}

// findCredDef returns the id of the credential definition with the tag
// credDefTag of one schema, or the empty string.
func (s *Service) findCredDef(ctx context.Context, schemaID string) (string, error) {
	defs, err := s.client.SchemaCredDefs(ctx, schemaID)
	if err != nil {
		return "", err
	}
	for _, d := range defs {
		if d.Tag == credDefTag && d.ID != "" {
			return d.ID, nil
		}
	}
	return "", nil
}

// findW3CSchema returns the address of the W3C schema with no ledger of
// the name and the alias, or the empty string. A JSON-LD schema carries
// its type as the alias. The schema of a template carries none.
func (s *Service) findW3CSchema(ctx context.Context, name, alias string) (string, error) {
	schemas, err := s.client.OrgSchemas(ctx, name)
	if err != nil {
		return "", err
	}
	for _, sc := range schemas {
		if sc.Name == name && sc.Alias == alias && sc.NoLedger() {
			return sc.LedgerID, nil
		}
	}
	return "", nil
}

// registerJSONLD writes one W3C JSON-LD schema with no ledger and
// returns its address.
func (s *Service) registerJSONLD(
	ctx context.Context, cfg *backendv1.CredentialConfiguration,
) (*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error) {
	if cfg.GetLedger() != "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("a W3C JSON-LD schema goes on no ledger"))
	}
	attributes, err := schemaAttributes(cfg, w3cType)
	if err != nil {
		return nil, err
	}
	// The platform keeps a second W3C schema of the same name, so the
	// adapter looks for the first (ADR-077 decision 2).
	id, err := s.findW3CSchema(ctx, cfg.GetType(), cfg.GetType())
	if err != nil {
		return nil, failed("read the schemas of the organisation", err)
	}
	if id != "" {
		return connect.NewResponse(&backendv1.RegisterCredentialConfigurationResponse{Id: id}), nil
	}
	id, err = s.client.CreateW3CSchema(ctx, cfg.GetType(), cfg.GetType(), attributes)
	if err != nil {
		return nil, failed("store the W3C schema", err)
	}
	return connect.NewResponse(&backendv1.RegisterCredentialConfigurationResponse{Id: id}), nil
}

// anonCredsType maps a property of a JSON Schema onto a data type of an
// AnonCreds schema: string, number, boolean or datetime-local.
func anonCredsType(typ, format string) string {
	switch {
	case format == "date" || format == "date-time":
		return "datetime-local"
	case typ == "number" || typ == "integer":
		return "number"
	case typ == "boolean":
		return "boolean"
	}
	return "string"
}

// w3cType maps a property of a JSON Schema onto a data type of a W3C
// schema of the platform, which keeps integer, array and object too.
func w3cType(typ, format string) string {
	switch {
	case format == "date" || format == "date-time":
		return "datetime-local"
	case typ == "number" || typ == "integer" || typ == "boolean" || typ == "array" || typ == "object":
		return typ
	}
	return "string"
}

// schemaAttributes reads the claims of a configuration from its JSON
// Schema, in name order. A claim is required when the JSON Schema says
// so. The platform needs one required claim, so a JSON Schema with no
// required list makes every claim required.
func schemaAttributes(cfg *backendv1.CredentialConfiguration, typeOf func(typ, format string) string) ([]credebl.SchemaAttribute, error) {
	var schema struct {
		Properties map[string]struct {
			Type   string `json:"type"`
			Format string `json:"format"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal([]byte(cfg.GetJsonSchema()), &schema); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("json_schema is not valid JSON: %w", err))
	}
	if len(schema.Properties) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the JSON Schema names no property"))
	}
	required := map[string]bool{}
	for _, name := range schema.Required {
		required[name] = true
	}
	names := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		names = append(names, name)
	}
	sortNames(names)
	out := make([]credebl.SchemaAttribute, 0, len(names))
	for _, name := range names {
		p := schema.Properties[name]
		out = append(out, credebl.SchemaAttribute{
			AttributeName: name, SchemaDataType: typeOf(p.Type, p.Format), DisplayName: name,
			IsRequired: len(required) == 0 || required[name],
		})
	}
	return out, nil
}

// ledgerCache keeps the ledgers of the capability answer for ledgerTTL.
type ledgerCache struct {
	at      time.Time
	ledgers []*backendv1.Ledger
}

// schemaTargets returns the ledgers the organisation of the adapter
// holds a DID on, with the names of the platform, and the schema formats
// they allow. A platform that does not answer gives no ledger, and the
// capability answer still comes.
func (s *Service) schemaTargets(ctx context.Context) ([]*backendv1.Ledger, []commonv1.Format) {
	s.ledgerMu.Lock()
	defer s.ledgerMu.Unlock()
	if s.ledgers.at.IsZero() || s.now().Sub(s.ledgers.at) >= ledgerTTL {
		s.ledgers = ledgerCache{at: s.now(), ledgers: s.readLedgers(ctx)}
	}
	formats := []commonv1.Format{commonv1.Format_FORMAT_LDP_VC}
	if len(s.ledgers.ledgers) > 0 {
		formats = []commonv1.Format{commonv1.Format_FORMAT_ANONCREDS, commonv1.Format_FORMAT_LDP_VC}
	}
	out := make([]*backendv1.Ledger, 0, len(s.ledgers.ledgers))
	for _, l := range s.ledgers.ledgers {
		out = append(out, &backendv1.Ledger{Namespace: l.GetNamespace(), Name: l.GetName()})
	}
	return out, formats
}

// readLedgers reads the Indy ledgers of the DIDs of the organisation.
func (s *Service) readLedgers(ctx context.Context) []*backendv1.Ledger {
	dids, err := s.client.OrgDids(ctx, s.client.OrgID())
	if err != nil {
		return nil
	}
	names := map[string]string{}
	if all, lerr := s.client.Ledgers(ctx); lerr == nil {
		for _, l := range all {
			names[l.Namespace] = l.Name
		}
	}
	var out []*backendv1.Ledger
	seen := map[string]bool{}
	for _, d := range dids {
		ns, ok := credebl.IndyNamespace(d.Did)
		if !ok || seen[ns] {
			continue
		}
		seen[ns] = true
		name := names[ns]
		if name == "" {
			name = ns
		}
		out = append(out, &backendv1.Ledger{Namespace: ns, Name: name})
	}
	return out
}
