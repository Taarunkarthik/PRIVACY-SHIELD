"""Provision the optional local synthetic demo databases for Docker Compose."""

import logging
import os
import sys

from sqlalchemy.engine import URL

from app.demo_datasets import EXTRA_DATASETS
from app.render_bootstrap import provision_extra_datasets


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    required = (
        "TARGET_POSTGRES_PASSWORD",
        "SCANNER_PASSWORD",
        "DEPLOYER_PASSWORD",
        "READER_PASSWORD",
    )
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        logging.error("Demo provisioning is missing required Compose settings")
        return 1
    target_admin = URL.create(
        "postgresql",
        username="postgres",
        password=os.environ["TARGET_POSTGRES_PASSWORD"],
        host=os.environ.get("TARGET_DB_HOST", "target-db"),
        port=int(os.environ.get("TARGET_DB_PORT", "5432")),
        database="enterprise_demo",
    ).render_as_string(hide_password=False)
    ready = provision_extra_datasets(
        target_admin,
        os.environ["SCANNER_PASSWORD"],
        os.environ["DEPLOYER_PASSWORD"],
        os.environ["READER_PASSWORD"],
    )
    expected = {dataset.database for dataset in EXTRA_DATASETS}
    missing_datasets = sorted(expected - set(ready))
    if missing_datasets:
        logging.error("Demo provisioning did not finish all configured databases")
        return 1
    logging.info("All synthetic demo databases are ready")
    return 0


if __name__ == "__main__":
    sys.exit(main())
