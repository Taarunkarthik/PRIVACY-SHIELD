"""The bundled synthetic datasets: shape checks that need no database.

Loading them into PostgreSQL and scanning them is covered by the hosted
integration test.
"""

import re

import pytest

from app.demo_datasets import BASIC, DEMO_DATASETS, ENTERPRISE, EXTRA_DATASETS, dataset_for
from app.demo_policies import starter_policy_rules
from app.services.discovery.catalog import DEFAULT_SCHEMAS

IDENTIFIER = re.compile(r"[a-z][a-z_]{2,30}")


def test_the_first_dataset_is_the_one_every_deployment_already_has():
    assert DEMO_DATASETS[0] is ENTERPRISE
    assert (ENTERPRISE.database, ENTERPRISE.schema) == ("enterprise_demo", "enterprise")
    assert ENTERPRISE.connection_name == "Synthetic enterprise"
    assert [item.database for item in EXTRA_DATASETS] == [
        "hospital_demo",
        "university_demo",
        "masked_demo",
        "vulnerability_demo",
        "basic_demo",
    ]
    assert {item.scenario for item in EXTRA_DATASETS} == {
        "sensitive",
        "masked",
        "vulnerable",
        "basic",
    }


def test_names_are_plain_identifiers_and_do_not_collide():
    for field in ("database", "schema", "connection_name"):
        values = [getattr(item, field) for item in DEMO_DATASETS]
        assert len(set(values)) == len(values), field
    for item in DEMO_DATASETS:
        # These are composed into statements; they must never need escaping.
        assert IDENTIFIER.fullmatch(item.database) and IDENTIFIER.fullmatch(item.schema)
        assert IDENTIFIER.fullmatch(item.probe)
        assert dataset_for(item.database) is item
    assert dataset_for("somewhere_else") is None


@pytest.mark.parametrize("dataset", DEMO_DATASETS, ids=lambda item: item.schema)
def test_a_dataset_touches_only_its_own_schema(dataset):
    text = "\n".join(dataset.statements)
    assert f"CREATE TABLE {dataset.schema}.{dataset.probe} (" in text
    others = {item.schema for item in DEMO_DATASETS} - {dataset.schema}
    for schema in (*others, "public", "privacyshield_masked", "privacyshield_private"):
        assert f"{schema}." not in text
    created = re.findall(r"CREATE TABLE (\w+)\.(\w+)", text)
    assert len(created) == 4 and {schema for schema, _ in created} == {dataset.schema}
    # Every table that is created is also filled.
    for _, table in created:
        assert f"INSERT INTO {dataset.schema}.{table}" in text
    # Nothing destructive, and nothing that reaches outside the database.
    assert not re.search(r"\b(DROP|TRUNCATE|DELETE|ALTER|GRANT|COPY|dblink)\b", text)


@pytest.mark.parametrize("dataset", DEMO_DATASETS, ids=lambda item: item.schema)
def test_email_addresses_use_only_reserved_example_domains(dataset):
    text = "\n".join(dataset.statements)
    domains = set(re.findall(r"@([a-z.]+)'", text))
    if dataset.scenario == "basic":
        assert not domains
        return
    reserved = ("example.com", "example.org", "example.net")
    assert domains
    assert all(domain.endswith(reserved) for domain in domains)


def test_discovery_finds_each_demo_schema_when_none_is_named():
    for item in DEMO_DATASETS:
        assert item.schema in DEFAULT_SCHEMAS


def test_basic_inventory_uses_non_personal_supplier_tiers():
    text = "\n".join(BASIC.statements)
    assert "suppliers(name,tier)" in text
    assert all(tier in text for tier in ("bronze", "silver", "gold", "platinum"))
    assert not any(location in text for location in ("India", "Singapore", "Japan", "Australia"))


def test_masked_demo_starter_rules_cover_columns_and_withhold_free_text():
    columns = [
        {"name": "full_name", "is_jsonb": False},
        {"name": "email", "is_jsonb": False},
        {"name": "phone", "is_jsonb": False},
        {"name": "aadhaar", "is_jsonb": False},
        {"name": "profile", "is_jsonb": True},
        {"name": "balance", "is_jsonb": False},
    ]
    rules = starter_policy_rules(columns)
    assert [rule["column_name"] for rule in rules] == [column["name"] for column in columns]
    assert [rule["action"] for rule in rules] == [
        "REDACT",
        "MASK_EMAIL",
        "MASK_PHONE",
        "MASK_ID",
        "NULLIFY",
        "KEEP",
    ]
    assert all(rule["audience"] == "reader" for rule in rules)
