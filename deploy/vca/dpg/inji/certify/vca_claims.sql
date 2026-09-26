-- SPDX-License-Identifier: Apache-2.0
-- VCA wrote this file (ADR-051). The Postgres image runs it after
-- certify_init.sql of Inji Certify 0.14.0, on the first start of an empty
-- database.
--
-- The VCA claims store. The Inji adapter of the issuer pair writes one CSV
-- file per staged subject into the volume inji-claims, which the stack
-- file mounts read only at /vca/claims here. file_fdw reads every file of
-- the directory at each query, so a new file needs no reload. Both Certify
-- containers run the Postgres data provider with one query on this table:
-- select * from certify.vca_claims where subject = :id
--
-- The adapter quotes every field, so an empty value is an empty string.
-- The program ends with status 0 when the directory holds no file.
\c inji_certify postgres
CREATE EXTENSION IF NOT EXISTS file_fdw;
CREATE SERVER IF NOT EXISTS vca_claims_files FOREIGN DATA WRAPPER file_fdw;
CREATE FOREIGN TABLE IF NOT EXISTS certify.vca_claims (
  subject text,
  config_id text,
  expires_at text,
  v_valid_from text,
  v_valid_until text,
  v_status_uri text,
  v_status_index text,
  c1 text,
  c2 text,
  c3 text,
  c4 text,
  c5 text,
  c6 text,
  c7 text,
  c8 text,
  c9 text,
  c10 text,
  c11 text,
  c12 text,
  c13 text,
  c14 text,
  c15 text,
  c16 text,
  c17 text,
  c18 text,
  c19 text,
  c20 text,
  c21 text,
  c22 text,
  c23 text,
  c24 text,
  c25 text,
  c26 text,
  c27 text,
  c28 text,
  c29 text,
  c30 text,
  c31 text,
  c32 text,
  c33 text,
  c34 text,
  c35 text,
  c36 text,
  c37 text,
  c38 text,
  c39 text,
  c40 text,
  c41 text,
  c42 text,
  c43 text,
  c44 text,
  c45 text,
  c46 text,
  c47 text,
  c48 text,
  c49 text,
  c50 text,
  c51 text,
  c52 text,
  c53 text,
  c54 text,
  c55 text,
  c56 text,
  c57 text,
  c58 text,
  c59 text,
  c60 text,
  c61 text,
  c62 text,
  c63 text,
  c64 text
) SERVER vca_claims_files OPTIONS (
  program 'cat /vca/claims/*.csv 2>/dev/null; exit 0',
  format 'csv',
  header 'false',
  null ''
);
