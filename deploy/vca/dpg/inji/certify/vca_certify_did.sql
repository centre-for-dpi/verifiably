-- SPDX-License-Identifier: Apache-2.0
-- VCA wrote this file. The Postgres image runs it after certify_init.sql of
-- Inji Certify 0.14.0, on the first start of an empty database. The sample
-- configuration FarmerCredential of the release names the DID of a tunnel of
-- the release authors. This script names the issuer DID of the stack instead,
-- from INJI_CERTIFY_DID, which the stack file passes to the database
-- container. psql 15 reads it with \getenv.
\c inji_certify postgres
\getenv stack_did INJI_CERTIFY_DID
UPDATE certify.credential_config
   SET did_url = :'stack_did'
 WHERE credential_config_key_id = 'FarmerCredential';
