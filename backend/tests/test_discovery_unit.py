import copy

import pytest
from pydantic import ValidationError

from app.schemas.connections import (
    ConnectionCreate,
    ConnectionPatch,
    DiscoveryRequest,
    normalize_host,
)
from app.services.discovery.catalog import DiscoveryError, catalog_fingerprint, validate_target_host


@pytest.mark.parametrize("host", ["host/path", "user@host", "host:5432", "one,two", "*", "a..b"])
def test_connection_host_rejects_dsn_and_multiple_target_syntax(host):
    with pytest.raises(ValueError):
        normalize_host(host)


def test_connection_host_normalizes_case_without_expanding_allowlist():
    assert normalize_host("TARGET-DB.") == "target-db"
    assert normalize_host("::1") == "::1"
    with pytest.raises(DiscoveryError, match="not enabled"):
        validate_target_host("unregistered.example")


@pytest.mark.parametrize(
    "schemas",
    [[], ["pg_catalog"], ["information_schema"], ["privacyshield_private"], ["a\x00b"], ["a"] * 21],
)
def test_discovery_rejects_unbounded_or_private_scopes(schemas):
    with pytest.raises(ValidationError):
        DiscoveryRequest(schemas=schemas)


def test_quoted_schema_identifiers_are_data_not_sql():
    name = 'quoted schema; SELECT "x"'
    assert DiscoveryRequest(schemas=[name]).schemas == [name]


def test_credentials_remain_secret_and_partial_patch_rejects_nulls():
    fields = dict(
        name="demo",
        host="target-db",
        database_name="enterprise_demo",
        scanner_username="ps_scanner",
        scanner_password="unit-test-only",
    )
    value = ConnectionCreate(**fields)
    assert "unit-test-only" not in repr(value)
    with pytest.raises(ValidationError):
        ConnectionCreate(**fields, deployer_username="deployer")
    for patch in [{}, {"host": None}, {"scanner_password": None}, {"is_active": None}]:
        with pytest.raises(ValidationError):
            ConnectionPatch(**patch)


def test_fingerprint_ignores_statistics_and_oid_but_tracks_semantic_schema_changes():
    first = {
        "schemas": ["enterprise"],
        "tables": [
            {
                "schema": "enterprise",
                "name": "customers",
                "oid": 10,
                "row_estimate": 100,
                "rls_enabled": False,
                "columns": [{"name": "id", "ordinal": 1, "data_type": "bigint"}],
                "primary_key": ["id"],
                "foreign_keys": [],
            }
        ],
    }
    second = copy.deepcopy(first)
    second["tables"][0].update(oid=900, row_estimate=500)
    assert catalog_fingerprint(first) == catalog_fingerprint(second)
    second["tables"][0]["columns"][0]["data_type"] = "text"
    assert catalog_fingerprint(first) != catalog_fingerprint(second)
    assert first["tables"][0]["row_estimate"] == 100
