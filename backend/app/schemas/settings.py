"""Bounded, non-secret operator settings and custom detection pattern contracts."""

import re
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PatternCategory = Literal["PII", "FINANCIAL", "HEALTH", "OTHER"]
MAX_CUSTOM_PATTERNS = 20
MAX_PATTERN_NAME = 60
MAX_PATTERN_REGEX = 200


class CustomPatternInput(BaseModel):
    """One operator regex. An optional id updates an existing pattern in place."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    id: UUID | None = None
    name: str = Field(min_length=1, max_length=MAX_PATTERN_NAME)
    category: PatternCategory
    regex: str = Field(min_length=1, max_length=MAX_PATTERN_REGEX)
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or "\x00" in cleaned:
            raise ValueError("Pattern name must contain non-null text")
        return cleaned

    @field_validator("regex")
    @classmethod
    def compilable_regex(cls, value: str) -> str:
        if not value or "\x00" in value:
            raise ValueError("Pattern regex must contain non-null text")
        try:
            re.compile(value)
        except re.error:
            # Never echo the offending pattern back to the caller.
            raise ValueError("Pattern regex does not compile") from None
        return value


class CustomPatternResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    category: PatternCategory
    regex: str
    enabled: bool


class SettingsResponse(BaseModel):
    workspace_name: str
    retention_days: int
    custom_patterns: list[CustomPatternResponse]


class SettingsPatch(BaseModel):
    """Bounded partial update; supplied fields replace the current value entirely."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    workspace_name: str | None = Field(default=None, min_length=1, max_length=120)
    retention_days: int | None = Field(default=None, ge=1, le=3650)
    custom_patterns: list[CustomPatternInput] | None = Field(
        default=None, max_length=MAX_CUSTOM_PATTERNS
    )

    @field_validator("workspace_name")
    @classmethod
    def valid_workspace_name(cls, value: str | None) -> str | None:
        if value is None:
            return value
        cleaned = value.strip()
        if not cleaned or "\x00" in cleaned:
            raise ValueError("Workspace name must contain non-null text")
        return cleaned

    @model_validator(mode="after")
    def at_least_one_bounded_field(self):
        if not self.model_fields_set:
            raise ValueError("Supply at least one settings field")
        for field in self.model_fields_set:
            if getattr(self, field) is None:
                raise ValueError("Settings fields cannot be cleared")
        return self
