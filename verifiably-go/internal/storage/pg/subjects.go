package pg

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AllowedSubjectClaims are the standard claims mirrored into typed certify.vc_subject
// columns (which the vc_subject_person view reads). ALL provisioned claims — these and
// any others — are also stored in the claims jsonb, so dynamically-created schemas can
// read arbitrary fields. This list also keeps the typed-column SQL injection-safe
// (column identifiers come only from here).
var AllowedSubjectClaims = []string{
	"fullName", "givenName", "familyName", "gender", "dateOfBirth", "email", "phoneNumber",
}

// OpenRaw connects a pgx pool WITHOUT running verifiably's migrations. Use it for
// a foreign database (e.g. Inji Certify's inji_certify) where we only touch one
// known table and must never create verifiably's own schema.
func OpenRaw(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("pg: parse DSN: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pg: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pg: ping: %w", err)
	}
	return pool, nil
}

// SubjectStore upserts dynamic claim rows into certify.vc_subject — the source
// table the Inji auth-code Postgres data-provider reads when issuing a credential.
// Rows are keyed by the eSignet subject id (the access-token `sub`/PSU-token),
// which is exactly what the data-provider query binds as :id.
type SubjectStore struct{ pool *pgxpool.Pool }

// NewSubjectStore wraps a pool (opened with OpenRaw against the inji_certify DB).
func NewSubjectStore(pool *pgxpool.Pool) *SubjectStore { return &SubjectStore{pool: pool} }

// ProvisionSubject upserts the allow-listed claims keyed by subjectID into
// certify.vc_subject (INSERT … ON CONFLICT (individual_id) DO UPDATE). Column
// names come only from AllowedSubjectClaims and are quoted; values are bound.
func (s *SubjectStore) ProvisionSubject(ctx context.Context, subjectID string, claims map[string]string) error {
	// ALL claims go into the claims jsonb, so a dynamically-created schema's
	// extraction view (vc_subject_<key>, which reads claims->>'field') can read
	// arbitrary fields. The standard claims are also mirrored into their typed
	// columns, which the original vc_subject_person view reads.
	jsonClaims, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("pg: marshal claims: %w", err)
	}
	cols := []string{"individual_id", "claims"}
	args := []any{subjectID, jsonClaims}
	ph := []string{"$1", "$2::jsonb"}
	updates := []string{"claims = certify.vc_subject.claims || EXCLUDED.claims"}
	i := 3
	for _, col := range AllowedSubjectClaims {
		v, ok := claims[col]
		if !ok {
			continue
		}
		qc := pgx.Identifier{col}.Sanitize()
		cols = append(cols, qc)
		args = append(args, v)
		ph = append(ph, "$"+strconv.Itoa(i))
		updates = append(updates, qc+"=EXCLUDED."+qc)
		i++
	}
	q := "INSERT INTO certify.vc_subject (" + strings.Join(cols, ", ") + ") VALUES (" +
		strings.Join(ph, ", ") + ") ON CONFLICT (individual_id) DO UPDATE SET " + strings.Join(updates, ", ")
	if _, err := s.pool.Exec(ctx, q, args...); err != nil {
		return fmt.Errorf("pg: provision vc_subject: %w", err)
	}
	return nil
}

// ListCredentials returns the active credential_configs (the holder catalog) as
// {key, scope, displayName} maps — what the holder can discover and claim.
func (s *SubjectStore) ListCredentials(ctx context.Context) ([]map[string]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT credential_config_key_id, scope, display FROM certify.credential_config WHERE status = 'active' ORDER BY credential_config_key_id`)
	if err != nil {
		return nil, fmt.Errorf("pg: list credentials: %w", err)
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var key, scope string
		var display []byte
		if err := rows.Scan(&key, &scope, &display); err != nil {
			return nil, err
		}
		name := key
		var disp []map[string]any
		if json.Unmarshal(display, &disp) == nil && len(disp) > 0 {
			if n, ok := disp[0]["name"].(string); ok && n != "" {
				name = n
			}
		}
		out = append(out, map[string]string{"key": key, "scope": scope, "displayName": name})
	}
	return out, rows.Err()
}

// CredentialScope returns the eSignet scope for a credential_config key.
func (s *SubjectStore) CredentialScope(ctx context.Context, key string) (string, error) {
	var scope string
	err := s.pool.QueryRow(ctx,
		`SELECT scope FROM certify.credential_config WHERE credential_config_key_id = $1`, key).Scan(&scope)
	if err != nil {
		return "", fmt.Errorf("pg: credential scope for %q: %w", key, err)
	}
	return scope, nil
}

// CredentialClaimSpec returns what the holder needs to request a credential in its
// own format: the credential_format, the @context (ldp_vc) and the vct (sd-jwt).
func (s *SubjectStore) CredentialClaimSpec(ctx context.Context, key string) (format, vcContext, vct string, err error) {
	var ctxP, vctP *string
	err = s.pool.QueryRow(ctx,
		`SELECT credential_format, context, sd_jwt_vct FROM certify.credential_config WHERE credential_config_key_id = $1`,
		key).Scan(&format, &ctxP, &vctP)
	if err != nil {
		return "", "", "", fmt.Errorf("pg: claim spec for %q: %w", key, err)
	}
	if ctxP != nil {
		vcContext = *ctxP
	}
	if vctP != nil {
		vct = *vctP
	}
	return format, vcContext, vct, nil
}

// ApplyAuthcodeSchema creates a Flow B credential in one transaction: the
// per-schema extraction VIEW + the credential_config row. The view DDL carries
// sanitized field names (column identifiers); the credential_config values are
// parameterized.
func (s *SubjectStore) ApplyAuthcodeSchema(ctx context.Context,
	viewDDL, key, vcTemplateB64, credFormat, display, scope string, displayOrder []string,
	sdJwtVct, vcContext, credType, credsub *string, ownerKey string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg: begin: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, viewDDL); err != nil {
		return fmt.Errorf("pg: create view: %w", err)
	}
	// Format-specific columns are parameterized: ldp_vc sets context+credential_type
	// +credential_subject; vc+sd-jwt sets sd_jwt_vct (the others NULL).
	const ins = `INSERT INTO certify.credential_config (
		credential_config_key_id, config_id, status, vc_template, doctype, sd_jwt_vct,
		context, credential_type, credential_format, did_url,
		key_manager_app_id, key_manager_ref_id, signature_algo, signature_crypto_suite,
		sd_claim, display, display_order, scope,
		cryptographic_binding_methods_supported, credential_signing_alg_values_supported,
		proof_types_supported, credential_subject, mso_mdoc_claims, plugin_configurations,
		credential_status_purpose, qr_settings, qr_signature_algo, cr_dtimes, upd_dtimes
	) VALUES (
		$1, gen_random_uuid()::VARCHAR(255), 'active', $2, NULL, $3,
		$4, $5, $6, 'did:web:certify-nginx',
		'CERTIFY_VC_SIGN_ED25519', 'ED25519_SIGN', 'EdDSA', 'Ed25519Signature2020',
		NULL, $7::JSONB, $8, $9,
		ARRAY['did:jwk'], ARRAY['Ed25519Signature2020'],
		'{"jwt": {"proof_signing_alg_values_supported": ["RS256", "ES256"]}}'::JSONB,
		$10::JSONB, NULL, NULL, ARRAY['revocation'], NULL, NULL, NOW(), NULL
	) ON CONFLICT (credential_config_key_id) DO NOTHING`
	if _, err := tx.Exec(ctx, ins, key, vcTemplateB64, sdJwtVct, vcContext, credType, credFormat,
		display, displayOrder, scope, credsub); err != nil {
		return fmt.Errorf("pg: insert credential_config: %w", err)
	}
	// Record which issuer created this credential (verifiably-owned table) so the
	// issuer's "my credentials" view can be owner-scoped.
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS certify.vc_credential_owner (
		credential_config_key_id VARCHAR(255) PRIMARY KEY, owner_key TEXT NOT NULL, cr_dtimes TIMESTAMP DEFAULT NOW())`); err != nil {
		return fmt.Errorf("pg: ensure owner table: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO certify.vc_credential_owner (credential_config_key_id, owner_key) VALUES ($1, $2)
		 ON CONFLICT (credential_config_key_id) DO UPDATE SET owner_key = EXCLUDED.owner_key`,
		key, ownerKey); err != nil {
		return fmt.Errorf("pg: record owner: %w", err)
	}
	return tx.Commit(ctx)
}

// ListMyCredentials returns the active credentials created by the given owner
// (issuer), as {key, scope, displayName, format} maps -- the owner-scoped catalog.
func (s *SubjectStore) ListMyCredentials(ctx context.Context, ownerKey string) ([]map[string]string, error) {
	if _, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS certify.vc_credential_owner (
		credential_config_key_id VARCHAR(255) PRIMARY KEY, owner_key TEXT NOT NULL, cr_dtimes TIMESTAMP DEFAULT NOW())`); err != nil {
		return nil, fmt.Errorf("pg: ensure owner table: %w", err)
	}
	rows, err := s.pool.Query(ctx,
		`SELECT cc.credential_config_key_id, cc.scope, cc.display, cc.credential_format
		 FROM certify.credential_config cc
		 JOIN certify.vc_credential_owner o ON o.credential_config_key_id = cc.credential_config_key_id
		 WHERE cc.status = 'active' AND o.owner_key = $1
		 ORDER BY cc.credential_config_key_id`, ownerKey)
	if err != nil {
		return nil, fmt.Errorf("pg: list my credentials: %w", err)
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var key, scope, format string
		var display []byte
		if err := rows.Scan(&key, &scope, &display, &format); err != nil {
			return nil, err
		}
		name := key
		var disp []map[string]any
		if json.Unmarshal(display, &disp) == nil && len(disp) > 0 {
			if n, ok := disp[0]["name"].(string); ok && n != "" {
				name = n
			}
		}
		out = append(out, map[string]string{"key": key, "scope": scope, "displayName": name, "format": format})
	}
	return out, rows.Err()
}

// CredentialFields returns the claim field names for a credential (its stored
// display_order) -- used to render the per-credential provisioning form so the
// issuer is asked for exactly the fields that credential issues.
func (s *SubjectStore) CredentialFields(ctx context.Context, key string) ([]string, error) {
	var order []string
	if err := s.pool.QueryRow(ctx,
		`SELECT display_order FROM certify.credential_config WHERE credential_config_key_id=$1`,
		key).Scan(&order); err != nil {
		return nil, fmt.Errorf("pg: credential fields: %w", err)
	}
	return order, nil
}
