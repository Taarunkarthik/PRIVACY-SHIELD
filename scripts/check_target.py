"""Run inside the backend image. Assert actual target-login boundaries."""
import os

import psycopg


def denied(connection: psycopg.Connection, statement: str) -> None:
    try:
        connection.execute(statement)
    except (psycopg.errors.InsufficientPrivilege, psycopg.errors.ReadOnlySqlTransaction):
        connection.rollback()
    else:
        connection.rollback()
        raise AssertionError("An operation expected to be denied was allowed")


def main() -> None:
    settings = dict(host="target-db", dbname="enterprise_demo", connect_timeout=5)
    with psycopg.connect(**settings, user="ps_scanner", password=os.environ["SCANNER_PASSWORD"]) as conn:
        assert conn.execute("SELECT count(*) FROM enterprise.customers").fetchone()[0] == 100
        conn.rollback()
        conn.autocommit = True
        conn.execute("SET default_transaction_read_only = off")
        conn.autocommit = False
        denied(conn, "UPDATE enterprise.customers SET full_name = full_name WHERE false")
        denied(conn, "SELECT key FROM privacyshield_private.pseudonym_keys")
    with psycopg.connect(**settings, user="ps_reader", password=os.environ["READER_PASSWORD"]) as conn:
        denied(conn, "SELECT email FROM enterprise.customers LIMIT 1")
        denied(conn, "SELECT key FROM privacyshield_private.pseudonym_keys")
        denied(conn, "SET ROLE ps_view_owner")
    print("PASS: real scanner can read synthetic rows but cannot write or read keys")
    print("PASS: real reader cannot access source data, keys, or assume owner role")


if __name__ == "__main__":
    main()
