import ipaddress
import re
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

SSLMode = Literal["disable", "require", "verify-ca", "verify-full"]
Identifier = Annotated[str, Field(min_length=1, max_length=63)]
Password = Annotated[SecretStr, Field(min_length=1, max_length=4096)]
RESERVED_SCHEMAS = {
    "information_schema",
    "privacyshield_private",
    "privacyshield_masked",
    "extensions",
}


def normalize_host(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", value):
            raise ValueError("Expected a single hostname or IP address") from None
        if any(
            not label or label.startswith("-") or label.endswith("-") or len(label) > 63
            for label in value.split(".")
        ):
            raise ValueError("Expected a single hostname or IP address") from None
        return value


class ConnectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=5432, ge=1, le=65535)
    database_name: Identifier
    ssl_mode: SSLMode = "require"
    scanner_username: Identifier
    scanner_password: Password
    deployer_username: Identifier | None = None
    deployer_password: Password | None = None

    _host = field_validator("host")(normalize_host)

    @field_validator("name", "database_name", "scanner_username", "deployer_username")
    @classmethod
    def valid_text(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or "\x00" in value):
            raise ValueError("Value must contain non-null text")
        return value

    @model_validator(mode="after")
    def paired_credentials(self):
        if (self.deployer_username is None) != (self.deployer_password is None):
            raise ValueError("Supply both deployment username and password")
        return self


class ConnectionPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    name: str | None = Field(default=None, min_length=1, max_length=120)
    host: str | None = Field(default=None, min_length=1, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    database_name: Identifier | None = None
    ssl_mode: SSLMode | None = None
    scanner_username: Identifier | None = None
    scanner_password: Password | None = None
    deployer_username: Identifier | None = None
    deployer_password: Password | None = None
    is_active: bool | None = None

    @field_validator("host")
    @classmethod
    def host_value(cls, value: str | None) -> str | None:
        return normalize_host(value) if value is not None else None

    @field_validator("name", "database_name", "scanner_username", "deployer_username")
    @classmethod
    def valid_text(cls, value: str | None) -> str | None:
        return ConnectionCreate.valid_text(value)

    @model_validator(mode="after")
    def not_empty_or_null_required(self):
        if not self.model_fields_set:
            raise ValueError("Supply at least one field")
        for field in self.model_fields_set - {"deployer_username", "deployer_password"}:
            if getattr(self, field) is None:
                raise ValueError("Required fields cannot be cleared")
        return self


class ConnectionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    host: str
    port: int
    database_name: str
    ssl_mode: SSLMode
    scanner_username: str
    deployer_username: str | None
    is_active: bool
    created_at: datetime


class ConnectionPage(BaseModel):
    items: list[ConnectionResponse]
    total: int
    page: int
    page_size: int


class DiscoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schemas: list[Identifier] | None = Field(default=None, min_length=1, max_length=20)

    @field_validator("schemas")
    @classmethod
    def user_schemas(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        if any(
            not value.strip()
            or "\x00" in value
            or len(value.encode("utf-8")) > 63
            or value.lower().startswith("pg_")
            or value.lower() in RESERVED_SCHEMAS
            for value in values
        ):
            raise ValueError("Only explicit non-system source schemas are supported")
        return sorted(set(values))


class ColumnInfo(BaseModel):
    name: str
    data_type: str
    udt_name: str
    nullable: bool
    ordinal: int
    is_primary_key: bool
    is_jsonb: bool


class ForeignKeyInfo(BaseModel):
    name: str
    columns: list[str]
    referenced_schema: str
    referenced_table: str
    referenced_columns: list[str]


class TableInfo(BaseModel):
    schema_name: str = Field(alias="schema")
    name: str
    oid: int
    row_estimate: int = Field(
        ge=-1, description="Estimated rows; -1 means statistics are unavailable"
    )
    rls_enabled: bool
    columns: list[ColumnInfo]
    primary_key: list[str]
    foreign_keys: list[ForeignKeyInfo]


class Catalog(BaseModel):
    schemas: list[str]
    tables: list[TableInfo]


class SnapshotResponse(BaseModel):
    snapshot_id: UUID
    discovered_at: datetime
    fingerprint: str
    catalog: Catalog


class ConnectionTestResponse(BaseModel):
    status: Literal["ok"] = "ok"
    schemas: list[str]
    table_count: int
