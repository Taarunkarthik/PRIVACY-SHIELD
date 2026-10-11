# Accounts and roles

Everyone who signs in to PrivacyShield has one of three roles. The role is
checked by the server on every request; what the interface shows or hides only
follows from it.

| Role | May do |
| --- | --- |
| Administrator | Everything: connections, scans, classification, policies, approving and deploying, settings, reading rows through a deployed view, verifying the audit log, and managing accounts |
| Analyst | Run scans and classification, write and submit policies. Cannot approve, deploy, or see protected output |
| Auditor | Read-only: review scans, policies, deployments and the audit log, and verify its integrity |

These are accounts for the PrivacyShield workspace. The people who read masked
data are not among them: they connect to the target database with a database
role such as `ps_reader` and query the masked views
([masking-audiences.md](masking-audiences.md)).

## How accounts are made

There is no self-service sign-up.

- **The first administrator** is created outside the interface: with
  `python -m app.cli create-admin` under Docker Compose, or from `ADMIN_EMAIL`
  and `ADMIN_PASSWORD` at startup on a hosted deployment.
- **Every other account** is created by an administrator on the **Users** page
  (Manage → Users), which is shown to administrators only.

On that page an administrator can:

- add an account with an email address, a role and an initial password (12 to
  128 characters). The password is stored only as an Argon2 hash and is never
  shown again, so it has to be passed on privately;
- change an account's role. It applies from that person's next request;
- deactivate an account, which signs it out at once, and reactivate it later;
- set a new password for an account, which ends that account's sessions. An
  administrator changing their own password keeps the session they are using.

## Rules that prevent a lock-out

- An administrator cannot change their own role or deactivate their own
  account (`409 OWN_ACCESS`).
- An administrator whose access is taken away while one of their own requests
  is still running gets `403` for it: creating an account and changing one
  both take the lock described next and read the acting account again.
- A sign-in that is still checking the password when an administrator
  deactivates that account or resets its password is refused, so it cannot
  leave a session behind.
- The last active administrator cannot be demoted or deactivated
  (`409 LAST_ADMIN`). One request can never do this, because the person acting
  stays an administrator. Two administrators demoting each other at the same
  moment could, so account changes are serialised with a transaction-level
  advisory lock and the acting account is read again under it; the request
  that arrives second is refused with `403`.

## API

All three are for administrators only: `403` for any other signed-in role, `401`
without a session.

- `GET /api/v1/users?page=&page_size=`: accounts in the order they were added.
  Each has `id`, `email`, `role`, `is_active` and `created_at`. No password or
  hash is ever returned.
- `POST /api/v1/users` with `email`, `role` and `password`: `201` with the
  account, `409 EMAIL_IN_USE` if the address is taken (compared in lower case),
  `422` for an invalid address, role or password length. A `422` does not echo
  what was sent.
- `PATCH /api/v1/users/{id}` with any of `role`, `is_active`, `password`:
  `200` with the account; `404 USER_NOT_FOUND`; `409` as above; `422` when
  nothing is given.

## Audit

Each change is written to the audit log in the same transaction, with the
administrator as actor and the account as subject:

- `USER_CREATED_AS_ADMIN`, `USER_CREATED_AS_ANALYST`, `USER_CREATED_AS_AUDITOR`
- `USER_ROLE_SET_ADMIN`, `USER_ROLE_SET_ANALYST`, `USER_ROLE_SET_AUDITOR`
- `USER_DEACTIVATED`, `USER_REACTIVATED`, `USER_PASSWORD_RESET`

Audit events carry no details, so nothing about a password can reach the log.
For the same reason the role is part of the event type: creating or promoting
an administrator is distinguishable from creating an auditor. The events are
sealed into the audit hash chain like every other event.

## Limits

- Accounts cannot be deleted, only deactivated: audit events refer to them.
- An email address cannot be changed. Create a new account and deactivate the
  old one.
- There is no password recovery by email and no second factor. An
  administrator sets a new password.
- A person cannot change their own password unless they are an administrator.
- An administrator sets a new password for their own account without being
  asked for the current one. Someone with a stolen administrator session could
  do the same, as they could create another administrator.
- In the interface a role is changed in a dialog with an explicit Save.
