#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=scanner_password="$SCANNER_PASSWORD" --set=deployer_password="$DEPLOYER_PASSWORD" \
  --set=reader_password="$READER_PASSWORD" <<'SQL'
CREATE ROLE ps_scanner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'scanner_password';
CREATE ROLE ps_view_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE ps_deployer LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'deployer_password';
CREATE ROLE ps_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'reader_password';
GRANT ps_view_owner TO ps_deployer;
REVOKE ALL ON DATABASE enterprise_demo FROM PUBLIC;
GRANT CONNECT ON DATABASE enterprise_demo TO ps_scanner, ps_deployer, ps_reader;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA enterprise;
CREATE SCHEMA privacyshield_masked AUTHORIZATION ps_view_owner;
CREATE SCHEMA privacyshield_private AUTHORIZATION ps_view_owner;
CREATE SCHEMA extensions;
CREATE EXTENSION pgcrypto WITH SCHEMA extensions;
GRANT USAGE ON SCHEMA extensions TO ps_view_owner, ps_reader;
GRANT USAGE ON SCHEMA enterprise TO ps_scanner, ps_view_owner;
GRANT USAGE ON SCHEMA privacyshield_masked TO ps_reader;
ALTER ROLE ps_scanner SET default_transaction_read_only = on;
ALTER ROLE ps_scanner SET statement_timeout = '10s';
ALTER ROLE ps_deployer SET statement_timeout = '30s';
ALTER ROLE ps_reader SET statement_timeout = '10s';
\i /opt/privacyshield/demo.sql
GRANT SELECT ON ALL TABLES IN SCHEMA enterprise TO ps_scanner, ps_view_owner;
CREATE TABLE privacyshield_private.pseudonym_keys (
  domain text PRIMARY KEY,
  key_version integer NOT NULL CHECK (key_version > 0),
  key bytea NOT NULL CHECK (octet_length(key) = 32)
);
ALTER TABLE privacyshield_private.pseudonym_keys OWNER TO ps_view_owner;
INSERT INTO privacyshield_private.pseudonym_keys VALUES ('demo', 1, extensions.gen_random_bytes(32));
CREATE TABLE privacyshield_private.deployment_receipts (
  deployment_id uuid PRIMARY KEY,
  plan_hash text NOT NULL,
  deployed_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE privacyshield_private.deployment_receipts OWNER TO ps_view_owner;
SQL
