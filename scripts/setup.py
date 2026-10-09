"""Create local-only secrets without overwriting existing configuration."""
from __future__ import annotations

import base64
from pathlib import Path
import secrets

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    destination = ROOT / ".env"
    if destination.exists():
        print("Existing .env preserved. Review .env.example for new settings.")
        return
    names = (
        "CONTROL_POSTGRES_PASSWORD", "MIGRATOR_PASSWORD", "APP_DATABASE_PASSWORD",
        "TARGET_POSTGRES_PASSWORD", "SCANNER_PASSWORD", "DEPLOYER_PASSWORD", "READER_PASSWORD",
    )
    values = {name: secrets.token_hex(24) for name in names}
    values["CREDENTIAL_ENCRYPTION_KEY"] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    values.update(FRONTEND_PORT="8080", COOKIE_SECURE="false",
                  ALLOWED_ORIGINS='["http://localhost:8080"]',
                  TARGET_ALLOWED_HOSTS='["target-db"]', OLLAMA_MODEL="qwen2.5:1.5b")
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write("# Local generated secrets. Never commit this file.\n")
        stream.writelines(f"{key}={value}\n" for key, value in values.items())
    destination.chmod(0o600)
    print("Created ignored .env with unique credentials; no secrets printed.")
    print("Next: docker compose up -d --build")


if __name__ == "__main__":
    main()
