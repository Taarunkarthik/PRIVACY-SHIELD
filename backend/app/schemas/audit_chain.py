from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


class AuditChainVerification(BaseModel):
    """Result of recomputing the audit hash chain. Hashes and counts only."""

    model_config = ConfigDict(from_attributes=True)
    status: Literal["INTACT", "BROKEN"]
    sealed: int
    pending: int
    head_index: int
    head_hash: str | None
    broken_index: int | None
    reason: Literal["HASH_MISMATCH", "LINK_MISMATCH", "INDEX_GAP", "MISSING_EVENT"] | None
    anchor_status: Literal["MATCH", "MISMATCH", "NOT_FOUND"] | None
    verified_at: datetime
