from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    connection_id: UUID
    snapshot_id: UUID
    sample_limit: int = Field(default=1000, ge=1, le=10000)


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    connection_id: UUID
    snapshot_id: UUID
    status: Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"]
    sample_limit: int
    progress: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error_code: str | None


class ScanPage(BaseModel):
    items: list[ScanResponse]
    total: int
    page: int
    page_size: int


class ScanResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    scan_job_id: UUID
    schema_name: str
    table_name: str
    column_name: str
    json_path: str
    sampled_rows: int
    matching_rows: int
    confidence: float
    category_counts: dict[str, int]
    sanitized_evidence: dict
    created_at: datetime


class ScanResultPage(BaseModel):
    items: list[ScanResultResponse]
    total: int
    page: int
    page_size: int
