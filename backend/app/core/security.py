import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet

from app.core.config import get_settings

SESSION_COOKIE = "ps_session"
CSRF_COOKIE = "ps_csrf"
password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
# Perform a real Argon2 check for unknown accounts as well as known accounts.
_dummy_hash = password_hasher.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    if not 12 <= len(password) <= 128:
        raise ValueError("Passwords must contain 12 to 128 characters")
    return password_hasher.hash(password)


def verify_password(password: str, encoded: str | None) -> bool:
    try:
        matched = password_hasher.verify(encoded or _dummy_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return bool(encoded and matched)


def session_token() -> str:
    return secrets.token_urlsafe(48)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def csrf_token(token: str) -> str:
    key = get_settings().credential_encryption_key.get_secret_value().encode("ascii")
    return hmac.new(key, b"privacyshield:csrf:v1:" + token.encode(), hashlib.sha256).hexdigest()


def encrypt_credential(value: str) -> str:
    key = get_settings().credential_encryption_key.get_secret_value().encode("ascii")
    return Fernet(key).encrypt(value.encode()).decode("ascii")


def decrypt_credential(value: str) -> str:
    key = get_settings().credential_encryption_key.get_secret_value().encode("ascii")
    return Fernet(key).decrypt(value.encode("ascii")).decode()
