# Connection management and schema discovery

**Phase 2 status: complete local gate passed; remote delivery pending.** Backend, frontend, browser, Docker/HTTP, demo, and proxy-recovery checks passed. [The verification record](verification-phase2.md) lists the counts and remaining commit/push/CI checks. Discovery inventories metadata; it does not sample customer values or claim PII findings.

## Local target setup

The bundled target runs as the `target-db` Compose service. For an authorized connection use host `target-db`, port `5432`, database `enterprise_demo`, and scanner username `ps_scanner`. The local synthetic service uses `ssl_mode: disable`; configure verified TLS for remote deployments. Obtain the scanner password from the private generated configuration and enter it only into the local connection form or a protected request file. Do not publish the `.env` contents or put credentials in command-line arguments.

The scanner has `SELECT` on the `enterprise` fixture tables and cannot modify them, read private pseudonym keys, or become the view-owner role. Use the scanner credential for discovery; a superuser or deployment credential is not an acceptable shortcut. Deployer credentials are optional in this phase and must be supplied as a username/password pair when registered.

The backend's `TARGET_ALLOWED_HOSTS` configuration controls permitted target hosts. Local Compose permits `target-db`; CI permits only `127.0.0.1` for its isolated service. Changing this allowlist is a server configuration action, not a way for an ordinary browser user to open arbitrary network access.

## API contract

All paths below use the `/api/v1` prefix and require an authenticated session. Administrators register, update, and test connections; administrators and analysts can discover schemas; all authenticated roles can read the connection inventory and saved schemas. Unsafe requests require the session's `X-CSRF-Token`; plaintext passwords are accepted only as write-only input, encrypted before storage, and omitted from responses and audit records.

| Endpoint | Intended behavior |
| --- | --- |
| `GET /connections` | Paginated inventory; `page` defaults to 1 and `page_size` to 20, with maximum 100; response contains `items`, `total`, `page`, and `page_size` |
| `POST /connections` | Register `name`, `host`, `port`, `database_name`, `ssl_mode`, scanner username/password, and optional deployer username/password pair |
| `PATCH /connections/{id}` | Change supplied connection settings or `is_active`; omitted password fields preserve existing ciphertext |
| `POST /connections/{id}/test` | Read-only connection/privilege check; optional `schemas` list; return status, schemas, and accessible table count |
| `POST /connections/{id}/discover` | Synchronously inventory selected schemas and save an immutable snapshot; return snapshot identifier, discovery timestamp, fingerprint, and catalog |
| `GET /connections/{id}/schema` | Return the latest saved snapshot, or `404` when discovery has not run |

Connection SSL choices are `disable`, `require`, `verify-ca`, and `verify-full`. The local demo's schema selection is `enterprise`. Existing inactive connections retain their historical metadata. Target failures must use sanitized errors without reflecting passwords, DSNs, or source values.

Discovery defaults to the accessible demo schemas (`enterprise`, `hospital`, `university`) and `public` when no list is supplied. Explicit lists must be nonempty and contain at most 20 source schemas; system and privacy-infrastructure schemas are rejected. The implementation limits a discovery to 500 tables, 10,000 columns, and 5,000 primary/foreign-key constraints, with a 10-second statement timeout and a read-only repeatable-read transaction. Exceeding the scope limits returns a clear error instead of silently truncating the snapshot. Fingerprints exclude volatile row estimates and object identifiers, while preserving the semantic schema structure.

## Demonstration and acceptance

The protected-file demo helper follows the same API workflow and avoids putting scanner credentials in shell history:

```powershell
python scripts/register_demo.py --email admin@example.com --password-file .secrets/admin-password.txt
```

It reads generated scanner settings from ignored `.env`, registers the connection named `Synthetic enterprise`, checks the scanner, discovers `enterprise`, and asserts four fixture tables, JSONB, and the composite foreign key. It prints only the connection identifier and count summary. Supply the password file for an already bootstrapped administrator; the helper is not a substitute for creating an account. The helper passed against the actual rebuilt Phase 2 HTTP service; remaining delivery gates are listed in [the verification record](verification-phase2.md).

1. Sign in as an administrator and register the synthetic target with its dedicated scanner credential.
2. Test the connection and discover the `enterprise` schema.
3. Open Schema Explorer and verify customers, accounts, transactions, and support records; column types; JSONB; primary and foreign keys; and the composite relationship from support records to transactions.
4. Confirm overview totals come from the saved metadata, and that a repeat discovery creates a new immutable snapshot rather than rewriting history.
5. Confirm unauthorized roles cannot register or change credentials, source writes are denied, and plaintext secrets are absent from API responses, logs, and audit records.

Catalog statistics are database estimates and metadata, not sampled PII detections. The scanner must respect existing RLS and bound database statement duration. Unknown schema/table identifiers must not be concatenated into executable SQL.

## CI target

The Phase 2 backend job adds a physically separate PostgreSQL 16 service on loopback port `5433`. It copies `infra/postgres/demo.sql` and runs the repository's `target-init.sh` rather than maintaining a second fixture implementation. Random scanner, deployer, reader, and bootstrap credentials are generated during the job and masked in logs.

After provisioning, the target switches TCP authentication from temporary bootstrap trust to SCRAM and verifies that an incorrect scanner password fails while the generated password can read the 100 synthetic customer rows. The control-plane service remains separate on port `5432`. Neither database contains customer data.

Integration configuration includes `TEST_TARGET_HOST`, `TEST_TARGET_PORT`, `TEST_TARGET_SCANNER_PASSWORD`, `TEST_TARGET_DEPLOYER_PASSWORD`, and `TEST_TARGET_SUPERUSER_PASSWORD`. The superuser credential belongs only to the disposable test service for negative permission cases; application discovery must reject privileged credentials. The CI workflow update is configuration awaiting verification, not evidence that Phase 2 tests have already passed.

The action versions were updated against publisher releases: [checkout 7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1), [setup-python 7.0.0](https://github.com/actions/setup-python/releases/tag/v7.0.0), [setup-node 7.1.0](https://github.com/actions/setup-node/releases/tag/v7.1.0), and [setup-uv 10.2.0](https://github.com/astral-sh/setup-uv/releases/tag/v10.2.0). CI pins the uv executable to `0.11.3` to match the backend image.
