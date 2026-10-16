"""Unit tests for bounded settings contracts and the custom detection hook.

These do not touch a database; storage and RBAC are covered by integration tests.
"""

import re

import pytest
from pydantic import ValidationError

from app.schemas.settings import (
    MAX_CUSTOM_PATTERNS,
    CustomPatternInput,
    SettingsPatch,
)
from app.services.scanning.detection import (
    CUSTOM_PATTERN_LIMIT,
    CUSTOM_PATTERN_SCORE,
    compile_custom_patterns,
    detect_pii,
)


def test_valid_custom_pattern_compiles_and_trims_name():
    pattern = CustomPatternInput(name="  Employee ID  ", category="PII", regex=r"\bE[0-9]{6}\b")
    assert pattern.name == "Employee ID"
    assert pattern.category == "PII"
    assert pattern.enabled is True
    assert pattern.id is None


@pytest.mark.parametrize("category", ["PII", "FINANCIAL", "HEALTH", "OTHER"])
def test_each_allowed_category_is_accepted(category):
    pattern = CustomPatternInput(name="candidate", category=category, regex=r"[0-9]{4}")
    assert pattern.category == category


@pytest.mark.parametrize("category", ["pii", "SECRET", "GOVERNMENT", ""])
def test_unknown_category_is_rejected(category):
    with pytest.raises(ValidationError):
        CustomPatternInput(name="candidate", category=category, regex=r"[0-9]{4}")


def test_invalid_regex_is_rejected_without_echoing_the_pattern():
    private_regex = "(unclosed 12345"
    with pytest.raises(ValidationError) as excinfo:
        CustomPatternInput(name="broken", category="PII", regex=private_regex)
    assert private_regex not in str(excinfo.value)


def test_catastrophic_regex_is_rejected_without_echoing_the_pattern():
    private_regex = "(a+)+"
    with pytest.raises(ValidationError) as excinfo:
        CustomPatternInput(name="dangerous", category="PII", regex=private_regex)
    assert private_regex not in str(excinfo.value)


def test_bounded_real_world_regex_is_accepted():
    regex = r"(?<![A-Za-z0-9])[2-9][0-9]{3}(?:[ -]?[0-9]{4}){2}"
    pattern = CustomPatternInput(name="Aadhaar shape", category="PII", regex=regex)
    assert pattern.regex == regex


@pytest.mark.parametrize("regex", ["", "x" * 201])
def test_regex_length_is_bounded(regex):
    with pytest.raises(ValidationError):
        CustomPatternInput(name="candidate", category="PII", regex=regex)


@pytest.mark.parametrize("name", ["", "   ", "x" * 61])
def test_pattern_name_is_bounded(name):
    with pytest.raises(ValidationError):
        CustomPatternInput(name=name, category="PII", regex=r"[0-9]{4}")


def test_extra_fields_are_forbidden():
    with pytest.raises(ValidationError):
        CustomPatternInput(name="candidate", category="PII", regex=r"[0-9]", secret="leak")


def test_patch_requires_at_least_one_field():
    with pytest.raises(ValidationError):
        SettingsPatch()
    with pytest.raises(ValidationError):
        SettingsPatch(workspace_name=None)


@pytest.mark.parametrize("retention", [0, 3651, -1])
def test_patch_retention_is_bounded(retention):
    with pytest.raises(ValidationError):
        SettingsPatch(retention_days=retention)


def test_patch_workspace_name_is_bounded_and_trimmed():
    assert SettingsPatch(workspace_name="  Team A  ").workspace_name == "Team A"
    with pytest.raises(ValidationError):
        SettingsPatch(workspace_name="   ")
    with pytest.raises(ValidationError):
        SettingsPatch(workspace_name="x" * 121)


def test_patch_caps_the_pattern_collection():
    items = [
        CustomPatternInput(name=f"p{index}", category="PII", regex=rf"[{index}]{4}")
        for index in range(MAX_CUSTOM_PATTERNS + 1)
    ]
    with pytest.raises(ValidationError):
        SettingsPatch(custom_patterns=items)
    assert len(SettingsPatch(custom_patterns=items[:MAX_CUSTOM_PATTERNS]).custom_patterns) == 20


def test_compile_custom_patterns_caps_and_namespaces_labels():
    rows = [("p", "PII", r"\bsecret\b")] + [
        (f"p{index}", "OTHER", r"\d") for index in range(CUSTOM_PATTERN_LIMIT + 5)
    ]
    compiled = compile_custom_patterns(rows)
    assert len(compiled) == CUSTOM_PATTERN_LIMIT
    assert compiled[0][0] == "CUSTOM_PII"
    assert isinstance(compiled[0][1], re.Pattern)
    assert {label for label, _ in compiled} <= {"CUSTOM_PII", "CUSTOM_OTHER"}


@pytest.mark.parametrize(
    "row",
    [
        ("p", "SECRET", r"\d"),
        ("p", "PII", "(unclosed"),
        ("p", "PII", 123),  # non-string regex
        ("only-two", "PII"),
    ],
)
def test_compile_custom_patterns_skips_invalid_rows(row):
    assert compile_custom_patterns([row]) == ()


def test_detection_without_patterns_is_unchanged():
    findings = detect_pii("synthetic.person@example.com", "email_address")
    assert "EMAIL_ADDRESS" in findings
    assert not [label for label in findings if label.startswith("CUSTOM_")]


def test_detection_with_patterns_adds_only_a_bounded_label():
    compiled = compile_custom_patterns([("Account code", "FINANCIAL", r"ACCT-[0-9]{6}")])
    findings = detect_pii("Reference ACCT-778899 recorded", "notes", patterns=compiled)
    assert findings.get("CUSTOM_FINANCIAL") == CUSTOM_PATTERN_SCORE
    assert "ACCT-778899" not in repr(findings)
    # Built-in categories are still merged alongside the operator label.
    assert detect_pii("orphan text", "notes", patterns=()) == {}


def test_non_matching_pattern_adds_nothing():
    compiled = compile_custom_patterns([("Account code", "FINANCIAL", r"ACCT-[0-9]{6}")])
    assert detect_pii("ordinary support note", "notes", patterns=compiled) == {}
