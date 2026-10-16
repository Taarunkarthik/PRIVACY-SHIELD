"""Unit tests for the policy separation-of-duties check.

The helper is pure, so no database is needed.
"""

import uuid

import pytest

from app.services.policies.service import PolicyFailure, ensure_can_approve


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
