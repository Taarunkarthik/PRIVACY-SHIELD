"""Unit tests for the policy separation-of-duties check.

The helper is pure, so no database is needed.
"""

import uuid

import pytest

from app.services.policies.service import (
    PolicyFailure,
    ensure_can_approve,
    policy_version_lock_key,
)


def test_self_approval_is_allowed_when_separation_is_off():
    creator = uuid.uuid4()
    ensure_can_approve(creator, creator, require_separate=False)


def test_self_approval_is_rejected_when_separation_is_on():
    creator = uuid.uuid4()
    with pytest.raises(PolicyFailure) as exc:
        ensure_can_approve(creator, creator, require_separate=True)
    assert exc.value.code == "SEPARATE_APPROVER_REQUIRED"


def test_a_different_approver_is_allowed_when_separation_is_on():
    ensure_can_approve(uuid.uuid4(), uuid.uuid4(), require_separate=True)


def test_policy_version_lock_key_is_deterministic_and_scoped():
    connection = uuid.uuid4()
    key = policy_version_lock_key(connection, "public", "customers")
    assert key == policy_version_lock_key(connection, "public", "customers")
    assert key != policy_version_lock_key(connection, "other", "customers")
    assert key != policy_version_lock_key(connection, "public", "orders")
    assert key != policy_version_lock_key(uuid.uuid4(), "public", "customers")
    # PostgreSQL advisory locks take a signed 64-bit key.
    assert -(2**63) <= key < 2**63
