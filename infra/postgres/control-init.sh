#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  --set=migrator_password="$MIGRATOR_PASSWORD" --set=app_password="$APP_DATABASE_PASSWORD" <<'SQL'
CREATE ROLE ps_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'migrator_password';
CREATE ROLE ps_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'app_password';
CREATE DATABASE privacyshield OWNER ps_migrator;
REVOKE ALL ON DATABASE privacyshield FROM PUBLIC;
GRANT CONNECT ON DATABASE privacyshield TO ps_migrator, ps_app;
\connect privacyshield
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ps_app;
SQL
