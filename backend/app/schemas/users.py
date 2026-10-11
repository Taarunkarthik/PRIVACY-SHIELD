"""Account management contracts. A password is accepted, never returned."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, field_validator

Role = Literal["ADMIN", "ANALYST", "AUDITOR"]
# The bounds app.core.security.hash_password enforces.
Password = SecretStr


def _hashable(value: SecretStr) -> SecretStr:
    try:
        value.get_secret_value().encode("utf-8")
    except UnicodeEncodeError:
        # Fixed text only: the value itself must never reach an error message.
        raise ValueError("Passwords must be valid text") from None
    return value


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    email: EmailStr = Field(max_length=254)
    role: Role
    password: Password = Field(min_length=12, max_length=128)

    @field_validator("email", mode="after")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.lower()

    @field_validator("password")
    @classmethod
    def hashable_password(cls, value: SecretStr) -> SecretStr:
        return _hashable(value)


class UserPatch(BaseModel):
    """Any one or more of: a new role, activation state, or a new password."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    role: Role | None = None
    is_active: bool | None = None
    password: Password | None = Field(default=None, min_length=12, max_length=128)

    @field_validator("password")
    @classmethod
    def hashable_password(cls, value: SecretStr | None) -> SecretStr | None:
        return value if value is None else _hashable(value)


class UserItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    role: Role
    is_active: bool
    created_at: datetime


class UserPage(BaseModel):
    items: list[UserItem]
    total: int
    page: int
    page_size: int
