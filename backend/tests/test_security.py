import pytest
from cryptography.fernet import InvalidToken

from app.core.security import (
    csrf_token,
    decrypt_credential,
    encrypt_credential,
    hash_password,
    session_token,
    token_hash,
    verify_password,
)


def test_password_hash_is_salted_and_rejects_wrong_password():
    password = "test-only sufficient password"
    first = hash_password(password)
    second = hash_password(password)
    assert first != second
    assert password not in first
    assert verify_password(password, first)
    assert not verify_password("incorrect password", first)
    assert not verify_password(password, None)
    assert not verify_password(password, "corrupted")


@pytest.mark.parametrize("password", ["short", "x" * 129])
def test_bootstrap_password_length(password):
    with pytest.raises(ValueError):
        hash_password(password)


def test_sessions_have_independent_csrf_tokens():
    first, second = session_token(), session_token()
    assert first != second
    assert first not in token_hash(first)
    assert csrf_token(first) != csrf_token(second)
    assert csrf_token(first) == csrf_token(first)


def test_credentials_are_authenticated_ciphertext():
    original = "synthetic test credential"
    encrypted = encrypt_credential(original)
    assert original not in encrypted
    assert encrypt_credential(original) != encrypted
    assert decrypt_credential(encrypted) == original
    tampered = encrypted[:-8] + "ABCDEFGH"
    with pytest.raises(InvalidToken):
        decrypt_credential(tampered)
