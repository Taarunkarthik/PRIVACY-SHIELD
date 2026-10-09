from functools import lru_cache

from cryptography.fernet import Fernet
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=None, case_sensitive=False, extra="ignore", hide_input_in_errors=True
    )

    database_url: SecretStr
    migration_database_url: SecretStr | None = None
    redis_url: SecretStr = SecretStr("redis://redis:6379/0")
    celery_queue: str = Field(default="privacyshield", pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    ollama_base_url: str = "http://ollama:11434"
    ollama_model: str = Field(default="qwen2.5:1.5b", min_length=1, max_length=120)
    credential_encryption_key: SecretStr
    allowed_origins: list[str] = Field(default_factory=lambda: ["http://localhost:8080"])
    target_allowed_hosts: list[str] = Field(default_factory=lambda: ["target-db"])
    cookie_secure: bool = False
    session_hours: int = Field(default=8, ge=1, le=24)
    login_attempt_limit: int = Field(default=10, ge=1, le=100)
    login_window_seconds: int = Field(default=300, ge=30, le=3600)

    @field_validator("database_url", "migration_database_url")
    @classmethod
    def postgres_only(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            try:
                if make_url(value.get_secret_value()).drivername != "postgresql+psycopg":
                    raise ValueError
            except Exception as exc:
                raise ValueError("A postgresql+psycopg URL is required") from exc
        return value

    @field_validator("credential_encryption_key")
    @classmethod
    def valid_fernet_key(cls, value: SecretStr) -> SecretStr:
        try:
            Fernet(value.get_secret_value().encode("ascii"))
        except (ValueError, UnicodeError) as exc:
            raise ValueError("A valid Fernet encryption key is required") from exc
        return value

    @field_validator("allowed_origins")
    @classmethod
    def explicit_origins(cls, values: list[str]) -> list[str]:
        if not values or any(
            origin == "*" or not origin.startswith(("http://", "https://")) or origin.endswith("/")
            for origin in values
        ):
            raise ValueError("Specify explicit HTTP(S) origins without trailing slashes")
        return values

    @field_validator("target_allowed_hosts")
    @classmethod
    def exact_target_hosts(cls, values: list[str]) -> list[str]:
        from app.schemas.connections import normalize_host

        if not values:
            raise ValueError("At least one explicit target host is required")
        return sorted({normalize_host(value) for value in values})


@lru_cache
def get_settings() -> Settings:
    return Settings()
