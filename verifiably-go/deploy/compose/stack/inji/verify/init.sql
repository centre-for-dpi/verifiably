-- Inji Verify (verify-service 0.16.0) OID4VP online-sharing schema.
-- The image ships ddl-auto=none and NO migrations, so the verify schema
-- must be created out-of-band. Canonical DDL from mosip/inji-verify
-- @ tag v0.16.0 (docker-compose/db-init/init.sql), verbatim + idempotent.
-- Mounted into inji-verify-postgres:/docker-entrypoint-initdb.d (fresh
-- volumes) and applied idempotently by deploy.sh (existing volumes).

CREATE SCHEMA IF NOT EXISTS verify;

CREATE TABLE IF NOT EXISTS verify.authorization_request_details (
    request_id character varying(40) NOT NULL,
    transaction_id character varying(40) NOT NULL,
    authorization_details text NOT NULL,
    expires_at bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS verify.presentation_definition(
    id character varying(36) NOT NULL,
    input_descriptors jsonb NOT NULL,
    name character varying(500),
    purpose character varying(500),
    vp_format text,
    submission_requirements text
);

CREATE TABLE IF NOT EXISTS verify.vc_submission(
    transaction_id character varying(40) NOT NULL,
    vc text NOT NULL
);

CREATE TABLE IF NOT EXISTS verify.vp_submission(
    request_id character varying(40) NOT NULL,
    vp_token VARCHAR NOT NULL,
    presentation_submission text NOT NULL,
    error character varying(100) NULL,
    error_description character varying(200) NULL
);