-- Paste-ready SELECTs for the "DB" bulk-issuance source.
--
-- Each query aliases the underlying citizens-db columns to the field names
-- the chosen schema expects. bulk.go coerces every column to a string
-- keyed by its name, so the column aliases here MUST match the schema's
-- FieldsSpec verbatim (case-sensitive, same camelCase as walt.id templates).
--
-- Connection strings (pick the one matching how the VC platform runs).
-- For the two "main-stack DB" cases, citizens is the real password ONLY on
-- a deployment from before CITIZENS_PG_PASSWORD existed — a fresh deploy
-- generates a random one into verifiably-go's own .env (VERIFIABLY_ROOT/.env
-- for the docker-mode default layout); read CITIZENS_PG_PASSWORD from there
-- and substitute it below. The dockerized "ministry" scenario is a separate,
-- self-contained compose stack (testdata/bulk-issuance/docker-compose.yml)
-- whose own citizens-db always uses the literal "citizens" — it never reads
-- CITIZENS_PG_PASSWORD.
--   • main-stack DB, VC platform in docker (default for the demo):
--       postgres://citizens:<CITIZENS_PG_PASSWORD>@citizens-postgres:5432/citizens
--   • main-stack DB, VC platform on bare metal (go run):
--       postgres://citizens:<CITIZENS_PG_PASSWORD>@localhost:5435/citizens
--   • dockerized "ministry" scenario, VC platform same host + docker:
--       postgres://citizens:citizens@ministry-citizens-db:5432/citizens
--   • dockerized "ministry" scenario, accessed from bare metal or remote:
--       postgres://citizens:citizens@<host>:5437/citizens
--
-- The bulk form only accepts queries starting with SELECT — enforced in
-- bulk.go queryDBRows.

-- ---------------------------------------------------------------------------
-- MortgageEligibility (walt.id catalog schema; 10 fields)
-- ---------------------------------------------------------------------------
SELECT
  CASE gender WHEN 'Male' THEN 'Mr' WHEN 'Female' THEN 'Mrs' ELSE '' END AS salutation,
  first_name                       AS "firstName",
  last_name                        AS "familyName",
  email                            AS "emailAddress",
  date_of_birth::text              AS "dateOfBirth",
  (400000 + (id * 1750) % 500000)::text  AS "purchasePrice",
  (60000  + (id * 320)  % 120000)::text  AS "totalIncome",
  (320000 + (id * 1400) % 400000)::text  AS "mortgageAmount",
  CASE (id % 4) WHEN 0 THEN 'none' WHEN 1 THEN 'vehicle' WHEN 2 THEN 'savings' ELSE 'shares' END AS "additionalCollateral",
  LPAD((id * 37)::text, 5, '0')   AS "postCodeProperty"
FROM citizens
ORDER BY id
LIMIT 10;

-- ---------------------------------------------------------------------------
-- Simple "holder"-only Mortgage (works with the one-field custom schema)
-- ---------------------------------------------------------------------------
SELECT
  first_name || ' ' || last_name AS holder
FROM citizens
ORDER BY id
LIMIT 20;

-- ---------------------------------------------------------------------------
-- VerifiableId (walt.id catalog schema; 8 fields, id dropped)
-- ---------------------------------------------------------------------------
SELECT
  first_name                 AS "firstName",
  last_name                  AS "familyName",
  date_of_birth::text        AS "dateOfBirth",
  gender                     AS gender,
  place_of_birth             AS "placeOfBirth",
  address                    AS "currentAddress",
  national_id                AS "personalIdentifier",
  first_name || ' ' || last_name AS "nameAndFamilyNameAtBirth"
FROM citizens
WHERE address IS NOT NULL
ORDER BY id
LIMIT 15;

-- ---------------------------------------------------------------------------
-- HotelReservation (walt.id catalog schema; 5 fields)
-- ---------------------------------------------------------------------------
SELECT
  first_name              AS "firstName",
  last_name               AS "familyName",
  date_of_birth::text     AS "dateOfBirth",
  place_of_birth          AS "placeOfBirth",
  'Suite ' || (100 + id % 400)::text || ', Hotel Sample' AS "currentAddress"
FROM citizens
ORDER BY id
LIMIT 10;

-- ---------------------------------------------------------------------------
-- UniversityDegree-ish (custom schema with degree, major, graduationDate —
-- swap the field aliases to whatever your custom schema calls them).
-- Only rows where the citizen actually has a degree.
-- ---------------------------------------------------------------------------
SELECT
  first_name || ' ' || last_name AS holder,
  degree_type                    AS degree,
  major                          AS major,
  graduation_date::text          AS "graduationDate",
  university                     AS issuer,
  COALESCE(gpa::text, '')        AS gpa
FROM citizens
WHERE university IS NOT NULL
ORDER BY id
LIMIT 15;

-- ---------------------------------------------------------------------------
-- Farmer ID (custom schema) — only rows where the citizen is a registered farmer
-- ---------------------------------------------------------------------------
SELECT
  first_name || ' ' || last_name AS holder,
  farm_id                        AS "farmId",
  farm_location                  AS location,
  COALESCE(farm_size_hectares::text, '') AS hectares,
  COALESCE(primary_crops, '')    AS crops,
  farm_registration_date::text   AS "registeredOn"
FROM citizens
WHERE farm_id IS NOT NULL
ORDER BY id
LIMIT 10;

-- ---------------------------------------------------------------------------
-- Inji Certify — FarmerCredentialV2 (13-field order per the running
-- instance's /v1/certify/.well-known/openid-credential-issuer).
-- Only cites citizens who are registered farmers in the seed data.
-- Column aliases MUST be quoted because camelCase identifiers in postgres
-- are folded to lowercase unless quoted.
-- ---------------------------------------------------------------------------
SELECT
  first_name || ' ' || last_name                 AS "fullName",
  COALESCE(phone, '+254000000000')               AS "mobileNumber",
  date_of_birth::text                            AS "dateOfBirth",
  gender                                         AS gender,
  CASE country_code WHEN 'KE' THEN 'Kenya' WHEN 'TT' THEN 'Trinidad & Tobago' ELSE country_code END AS state,
  place_of_birth                                 AS district,
  split_part(farm_location, ' from ', 2)         AS "villageOrTown",
  '00100'                                        AS "postalCode",
  COALESCE(farm_size_hectares::text, '1.0')      AS "landArea",
  'owned'                                        AS "landOwnershipType",
  COALESCE(split_part(primary_crops, ',', 1), 'Maize') AS "primaryCropType",
  COALESCE(split_part(primary_crops, ',', 2), 'Beans') AS "secondaryCropType",
  farm_id                                        AS "farmerID"
FROM citizens
WHERE farm_id IS NOT NULL
ORDER BY id
LIMIT 10;

-- ---------------------------------------------------------------------------
-- Error-path test: SELECT that returns zero rows (exercises the
-- "query returned 0 rows" error surface)
-- ---------------------------------------------------------------------------
SELECT first_name || ' ' || last_name AS holder
FROM citizens
WHERE country_code = 'ZZ';

-- ---------------------------------------------------------------------------
-- Error-path test: non-SELECT query (rejected with "only SELECT queries
-- allowed" — no writes reach the DB)
-- ---------------------------------------------------------------------------
-- DELETE FROM citizens WHERE id < 0;
