import os

from cryptography.fernet import Fernet

# Unit tests only need valid configuration; they never substitute a different database engine.
# Existing integration environment variables always take precedence.
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://ps_app@localhost/privacyshield_test")
os.environ.setdefault("CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("COOKIE_SECURE", "false")
