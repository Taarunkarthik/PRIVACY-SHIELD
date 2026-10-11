import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PolicyAction = Literal[
    "KEEP",
    "REDACT",
    "PARTIAL",
    "MASK_EMAIL",
    "MASK_PHONE",
    "MASK_ID",
    "PSEUDONYMIZE",
    "NULLIFY",
    "RESTRICT",
]
_DOMAIN_PATTERN = re.compile(r"^[a-z0-9_]{1,60}$")
PolicyStatus = Literal["DRAFT", "PENDING_APPROVAL", "APPROVED", "REJECTED", "DEPLOYED", "FAILED"]
DeploymentStatus = Literal["QUEUED", "RUNNING", "RECONCILING", "COMPLETED", "FAILED"]


class PolicyRuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    column_name: str = Field(min_length=1, max_length=63)
    action: PolicyAction
    pseudonym_domain: str | None = Field(default=None, min_length=1, max_length=60)
    classification_id: UUID | None = None

    @field_validator("column_name")
    @classmethod
    def valid_column(cls, value: str) -> str:
        if not value.strip() or "\x00" in value:
            raise ValueError("Column name must contain non-null text")
        return value

    @model_validator(mode="after")
    def valid_domain(self):
        domain = self.pseudonym_domain
        if domain is not None and not _DOMAIN_PATTERN.fullmatch(domain):
            raise ValueError("Pseudonym domain must be lowercase letters, digits, or underscores")
        return self


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    connection_id: UUID
    schema_name: str = Field(min_length=1, max_length=63)
    table_name: str = Field(min_length=1, max_length=63)
    snapshot_id: UUID
    rules: list[PolicyRuleCreate] = Field(min_length=1, max_length=200)

    @field_validator("schema_name", "table_name")
    @classmethod
    def valid_identifier(cls, value: str) -> str:
        if not value.strip() or "\x00" in value:
            raise ValueError("Identifier must contain non-null text")
        return value


class PolicyRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    policy_id: UUID
    column_name: str
    action: PolicyAction
    pseudonym_domain: str | None
    classification_id: UUID | None


class PolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    connection_id: UUID
    schema_name: str
    table_name: str
    version: int
    status: PolicyStatus
    schema_fingerprint: str
    compiled_plan_fingerprint: str | None
    created_by: UUID
    created_at: datetime
    rules: list[PolicyRuleResponse] = []


class PolicyPage(BaseModel):
    items: list[PolicyResponse]
    total: int
    page: int
    page_size: int


class PolicyPreviewColumn(BaseModel):
    name: str
    data_type: str
    action: PolicyAction
    pseudonym_domain: str | None
    source_column: str


class PolicyPreview(BaseModel):
    policy_id: UUID
    schema_name: str
    table_name: str
    view_schema: str = "privacyshield_masked"
    view_name: str
    columns: list[PolicyPreviewColumn]
    sql: str


class SampleColumn(BaseModel):
    name: str
    data_type: str
    action: PolicyAction


class PolicySamples(BaseModel):
    """Compiled expressions applied to fabricated inputs; never source rows."""

    policy_id: UUID
    status: Literal["OK", "UNAVAILABLE"]
    source: Literal["FABRICATED"] = "FABRICATED"
    columns: list[SampleColumn]
    before: list[list[str | None]] = []
    after: list[list[str | None]] = []


class AccessCheck(BaseModel):
    reader_role: str
    reader_can_read_view: bool
    reader_can_read_source: bool


class ProtectedOutput(BaseModel):
    """Rows read through the deployed view: what the approved policy exposes."""

    policy_id: UUID
    view_schema: str
    view_name: str
    source_schema: str
    source_table: str
    columns: list[SampleColumn]
    rows: list[list[str | None]]
    row_limit: int
    access: AccessCheck


class RuleSuggestion(BaseModel):
    """A starting point for one column; a person still decides every rule."""

    column_name: str
    data_type: str
    # DETECTOR: pattern evidence from the scan. AI: advisory classification of a
    # column the detectors did not flag. NO_FINDINGS: scanned, nothing found.
    # NOT_SCANNED: no usable evidence, so no action is suggested.
    source: Literal["DETECTOR", "AI", "NO_FINDINGS", "NOT_SCANNED"]
    action: PolicyAction | None = None
    category: str | None = None
    confidence: float | None = None
    sampled_rows: int = 0
    matching_rows: int = 0
    classification_id: UUID | None = None
    ai_recommendation: str | None = None
    ai_risk: str | None = None


class PolicySuggestions(BaseModel):
    connection_id: UUID
    schema_name: str
    table_name: str
    scan_id: UUID | None
    scanned_at: datetime | None
    columns: list[RuleSuggestion]


class DeployRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idempotency_key: UUID | None = None


class DeploymentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    policy_id: UUID
    requested_by: UUID
    idempotency_key: UUID
    status: DeploymentStatus
    target_receipt: dict | None
    finished_at: datetime | None
    error_code: str | None
    created_at: datetime


class DeploymentPage(BaseModel):
    items: list[DeploymentResponse]
    total: int
    page: int
    page_size: int


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    actor_id: UUID | None
    event_type: str
    subject_type: str
    subject_id: UUID | None
    correlation_id: UUID
    details: dict
    created_at: datetime


class AuditEventPage(BaseModel):
    items: list[AuditEventResponse]
    total: int
    page: int
    page_size: int
