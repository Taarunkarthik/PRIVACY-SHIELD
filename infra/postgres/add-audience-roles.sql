-- Adds the two masking-audience roles to a target database that was initialised
-- before audiences existed (see docs/masking-audiences.md). New installations
-- get them from target-init.sh and do not need this file.
--
-- Run once in the target database as a superuser. Safe to run again: an
-- existing role is left exactly as it is.
--
--   docker compose exec -T target-db psql -U postgres -d enterprise_demo -v ON_ERROR_STOP=1 < infra/postgres/add-audience-roles.sql
DO $$
DECLARE
  audience_role text;
BEGIN
  FOREACH audience_role IN ARRAY ARRAY['ps_support', 'ps_analyst'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = audience_role) THEN
      EXECUTE format(
        'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS',
        audience_role
      );
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA privacyshield_masked TO %I', audience_role);
  END LOOP;
END
$$;
