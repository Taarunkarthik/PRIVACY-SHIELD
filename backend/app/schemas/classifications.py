from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ClassificationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    result_ids: list[UUID] | None = Field(default=None, min_length=1, max_length=50)

    @field_validator("result_ids")
    @classmethod
    def unique_results(cls, values: list[UUID] | None) -> list[UUID] | None:
        if values is not None and len(values) != len(set(values)):
            raise ValueError("Select each result only once")
        return values


class ClassificationSummary(BaseModel):
    """How the detectors left the whole-column results of one completed scan."""

    scan_id: UUID
    whole_columns: int
    decided: int
    uncertain: int
    not_classifiable: int
    selection_limit: int
    # Columns a request without an explicit selection would send to the model.
    will_classify: int


class ClassificationJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    scan_id: UUID = Field(validation_alias="scan_job_id")
    status: Literal["QUEUED", "RUNNING", "COMPLETED", "PARTIAL", "FAILED"]
    progress: int
    total_results: int
    completed_results: int
    failed_results: int
    model: str
    prompt_version: str
    error_code: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ClassificationJobPage(BaseModel):
    items: list[ClassificationJobResponse]
    total: int
    page: int
    page_size: int


class ClassificationResponse(BaseModel):
    id: UUID
    job_id: UUID
    scan_result_id: UUID
    scan_id: UUID
    schema_name: str
    table_name: str
    column_name: str
    json_path: str
    category: str
    risk: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    recommendation: Literal["KEEP", "REDACT", "PARTIAL", "PSEUDONYMIZE", "NULLIFY", "RESTRICT"]
    confidence: float
    reason: str
    model: str
    prompt_version: str
    requires_approval: Literal[True]
    created_at: datetime


class ClassificationPage(BaseModel):
    items: list[ClassificationResponse]
    total: int
    page: int
    page_size: int
