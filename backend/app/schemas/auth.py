from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, SecretStr, field_validator


class LoginRequest(BaseModel):
    email: EmailStr
    password: SecretStr = Field(min_length=1, max_length=128)

    @field_validator("email", mode="after")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.lower()


class UserResponse(BaseModel):
    id: UUID
    email: str
    role: str
    csrf_token: str
