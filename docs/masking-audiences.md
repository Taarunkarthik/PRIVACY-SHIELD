# Masking audiences

One masking policy can show the same table to different database roles masked
to different degrees. Support staff can see part of a phone number, analysts can
see a stable pseudonym they can join on, and the general reader sees the
strictest version. This document describes that model. The rest of the policy
lifecycle is unchanged and is described in [masking.md](masking.md).

## Model

There are three audiences. The set is fixed.

| Audience | Target role | Kind of role | Intended use |
| --- | --- | --- | --- |
| `reader` | `ps_reader` | Login role, as before | The general, strictest view |
| `support` | `ps_support` | `NOLOGIN` group role | Partial values (`MASK_PHONE`, `MASK_EMAIL`) |
| `analyst` | `ps_analyst` | `NOLOGIN` group role | Stable pseudonyms to join on (`PSEUDONYMIZE`) |

Every policy rule belongs to one audience. A rule written without an audience
belongs to `reader`, so a policy written before audiences existed is a
reader-only policy and behaves exactly as it did. A column can have one rule per
audience; two rules for the same column and audience are rejected.

Audiences do not inherit from each other. Each audience's view is built from
that audience's rules alone:

- The **reader** always gets a view, as before. A column with no reader rule is
  `NULL` in it. A policy with rules for other audiences only still creates the
  reader view, with every column `NULL`.
- **Another audience gets a view only if the policy has at least one rule for
  it.** Within that view, a column with no rule for that audience is `NULL`.
- An audience with no rule in the policy gets **no view at all**, and so no
  access to the table. That is stricter than a view of `NULL`s.

So a support rule never changes what the reader sees, and the support view shows
only the columns that have a support rule, even if the reader keeps others.

The control-plane table `policy_rules` records this in an `audience` column
(`text`, `NOT NULL`, default `'reader'`, limited to the three values by a check
constraint). The unique key is `(policy_id, column_name, audience)`. Migration
`0007_policy_audiences` adds it and marks every existing rule `reader`. Its
downgrade refuses to run while any rule belongs to another audience, because
dropping those rules would leave approvals and deployed views describing
something else.

## View naming

All views live in schema `privacyshield_masked` and are owned by `ps_view_owner`.

| Audience | View name | Table prefix kept |
| --- | --- | --- |
| `reader` | `<table>_<digest>` | first 50 characters |
| `support` | `<table>_<digest>_support` | first 42 characters |
| `analyst` | `<table>_<digest>_analyst` | first 42 characters |

`<digest>` is the first 12 hex digits of the SHA-256 of the schema name, a NUL
byte, and the table name. It is the same for all three views of a table. For
`enterprise.customers`:

```text
privacyshield_masked.customers_20f808f337c9            reader
privacyshield_masked.customers_20f808f337c9_support    support
privacyshield_masked.customers_20f808f337c9_analyst    analyst
```

The reader name and its SQL are exactly what they were before audiences. Every
name is at most 63 bytes. A reader view name always ends in an underscore and
twelve hex digits. A name ending in `_support` or `_analyst` never has that
shape, so an audience view can never take the name of a reader view, of this
table or of any other. A table that is itself called `customers_support` gets
the reader view `customers_support_<digest>`, which is a different name again.

## What each audience can and cannot see

For a policy on `enterprise.customers` with these rules:

| Column | `reader` | `support` | `analyst` |
| --- | --- | --- | --- |
| `id` | `KEEP` | `KEEP` | `KEEP` |
| `email` | `MASK_EMAIL` | `MASK_EMAIL` | `PSEUDONYMIZE` (domain `demo`) |
| `phone` | `NULLIFY` | `MASK_PHONE` | no rule |

each role reads this for customer 7:

| Role | `email` | `phone` | every other column |
| --- | --- | --- | --- |
| `ps_reader` | `c***@example.com` | `NULL` | `NULL` |
| `ps_support` | `c***@example.com` | `+** ***** *0007` | `NULL` |
| `ps_analyst` | 64 hex digits, the same on every read | `NULL` | `NULL` |

No audience role can read:

- the source table, or any column of it;
- another audience's view of the table;
- the pseudonym keys in `privacyshield_private`.

A member of several audience roles sees the union of what those roles see.
Membership is the operator's decision and is not checked by PrivacyShield.

## Fingerprint

The plan fingerprint (`plan_hash`) covers every audience's decisions: each
audience's role, view name and ordered column decisions. Changing, adding or
removing a rule of any audience changes it, and so needs a new policy version
and a new approval.

A policy with reader rules only compiles to the same SQL and the same
fingerprint as before audiences existed. The section for other audiences is
added to the fingerprinted content only when another audience has a view. A
policy approved by an earlier release therefore still matches its approval and
still deploys.

## Deployment

Deployment is still one target transaction with one idempotent receipt. Inside
it, after the receipt check:

1. **Roles.** Every audience the policy has a view for must have its role in the
   target database. If one is missing, the deployment fails with
   `AUDIENCE_ROLE_MISSING` before anything is changed. A reader-only policy
   needs only `ps_reader`, so it deploys to a database that has never had the
   other roles.
2. **Views.** In the fixed order reader, support, analyst:
   - an audience with a view has it created or replaced. If a column's type
     changes, the view is dropped and recreated in the same transaction, as
     before;
   - an audience without a view in this version has the view an earlier version
     gave it dropped. A more permissive view never outlives the policy that
     created it. The drop is not cascaded. If something else was built on that
     view, the deployment fails with `AUDIENCE_VIEW_IN_USE` and nothing changes.
3. **Grants.** Each view is granted `SELECT` to its own audience role. Any
   privilege another audience role holds on it directly is revoked.
4. **Verification, before commit.** For every audience role that exists in the
   target:
   - it can read its own view, if the policy gives it one;
   - it cannot read the source table: no table privilege and no column
     privilege;
   - it cannot read any other audience's view of this table.

   The check asks PostgreSQL for the role's effective privileges, so it also
   catches access that comes through role membership or `PUBLIC`. It covers an
   audience without a view too: that role must read nothing. A failure rolls
   back every view and fails with `ACCESS_VERIFICATION_FAILED`.
5. **Receipt.** The target receipt row is written in the same transaction. The
   control-plane receipt (`target_receipt` on the deployment) records
   `audiences`, the audiences that have a view after this deployment, and
   `audience_views`, the view name of each. An audience not listed has no view.

Deployment error codes added for audiences:

| Code | Meaning |
| --- | --- |
| `AUDIENCE_ROLE_MISSING` | The policy has a view for an audience whose role does not exist in the target. Create the role (below) and deploy the same approved version again. |
| `AUDIENCE_VIEW_IN_USE` | A view to be dropped has dependent objects. Remove them and deploy again. |

Both leave the policy `FAILED`. Deploying again retries the same approved
version, provided its fingerprint is unchanged.

## API

Every earlier request and response still works without the new fields.

- `POST /api/v1/policies`: each rule takes an optional `audience` (`reader`,
  `support` or `analyst`; default `reader`). Rule responses include `audience`.
  A repeated column and audience pair returns `422 DUPLICATE_RULE`. At most 200
  rules are accepted per audience.
- `GET /api/v1/policies/{id}/preview?audience=`: the compiled view of that
  audience. The response adds `audience`, `role` (the target role that reads the
  view) and `audiences` (every audience this policy has a view for).
- `GET /api/v1/policies/{id}/preview/samples?audience=`: that audience's
  expressions over fabricated values. The response adds `audience`.
- `GET /api/v1/policies/{id}/protected-output?audience=`: rows through that
  audience's deployed view, and the access facts of that audience's role. The
  response adds `audience`. The fields of `access` keep their names:
  `reader_role` holds the role of the audience asked for, such as `ps_support`.
  Administrators only, as before.

`audience` defaults to `reader` everywhere. Asking for an audience the policy
has no view for returns `404 AUDIENCE_NOT_IN_POLICY`. A value outside the three
returns `422`.

`GET /api/v1/policies/suggestions` is unchanged and suggests reader rules.
Dashboard coverage is unchanged in meaning: a column counts as protected when
the deployed policy does not `KEEP` it for the reader, whatever other audiences
see.

## Role setup

New installations get both roles from `infra/postgres/target-init.sh`, and
hosted deployments from the startup bootstrap. They are created
`NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, without a password,
with `USAGE` on schema `privacyshield_masked` and nothing else.

A target database initialised before audiences existed does not have them. Run
this once in that database, as a superuser or as a role that may create roles
and grant on the schema. It is safe to run again.

```sql
DO $$
DECLARE
  audience_role text;
BEGIN
  FOREACH audience_role IN ARRAY ARRAY['ps_support', 'ps_analyst'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = audience_role) THEN
      EXECUTE format(
        'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS',
        audience_role
      );
    END IF;
    EXECUTE format('GRANT USAGE ON SCHEMA privacyshield_masked TO %I', audience_role);
  END LOOP;
END
$$;
```

The same statement is in `infra/postgres/add-audience-roles.sql`. For the bundled
Docker Compose target, from the repository root:

```text
docker compose exec -T target-db psql -U postgres -d enterprise_demo -v ON_ERROR_STOP=1 < infra/postgres/add-audience-roles.sql
```

Until the roles exist, a policy with rules for support or analysts fails to
deploy with `AUDIENCE_ROLE_MISSING` and changes nothing; deploy the same
approved version again afterwards. Reader-only policies do not need the roles.

Then give the role to the people who should have that view:

```sql
GRANT ps_support TO alice;
GRANT ps_analyst TO bob;
```

The audience roles carry no `CONNECT` privilege, so each user needs their own
right to connect to the database. The bundled target revokes `CONNECT` from
`PUBLIC`; there, also run `GRANT CONNECT ON DATABASE enterprise_demo TO alice`.

`ps_reader` also has `USAGE` on schema `extensions`. The audience roles do not,
because reading a pseudonymized view does not need it: PostgreSQL resolves the
`extensions.hmac` call when the view is created, not when it is read. The
integration tests read pseudonyms as `ps_analyst` without that grant.

## Limits

- **Three fixed audiences.** Audiences and their roles are constants in the
  code. A fourth audience, or a different role name, needs a code change and a
  migration of the check constraint.
- **Group roles the operator grants.** `ps_support` and `ps_analyst` cannot log
  in. PrivacyShield does not create users, grant the roles, or check who holds
  them. A user who is a member of two audience roles reads both views.
- **Membership between audience roles fails deployment.** If `ps_reader` is
  granted to `ps_support`, say, support staff could read the reader view, so
  every deployment to that database fails with `ACCESS_VERIFICATION_FAILED`
  until the membership is removed.
- **Pseudonyms are shared across audiences.** `PSEUDONYMIZE` gives the same
  token for the same value to every audience that uses the same key domain. An
  analyst and a reader who both pseudonymize `email` with domain `demo` can
  match their rows on the token. Use different domains to prevent that.
- **Views can be joined on what they keep.** Someone who holds two audience
  roles, or two people who share output, can combine views through any column
  both keep, such as `id`. Per-audience masking limits what each role reads; it
  does not stop readers from pooling what they are each allowed to see.
- **Hand-made grants on audience views are not kept.** A privilege given
  directly to another audience role is revoked by the next deployment, and a
  recreated view keeps only its own audience's grant.
- **Taking an audience's view away needs a deployment.** It takes a new policy
  version without rules for that audience, approved and deployed. Until then
  the earlier version's view stays, as that version was approved.
- **Existing role attributes are not changed.** The setup snippet and the hosted
  bootstrap create a missing role and never alter an existing one. A role of the
  same name with wider attributes is caught only by the deployment verification.
- **Role-level settings do not apply to members.** `ps_reader` has a 10 second
  statement timeout set on the role. A setting on a `NOLOGIN` group role would
  not reach the users who hold it, so none is set; set limits on the users.
- **The protected-output audit event does not record the audience.** Each call
  is still audited as `PROTECTED_OUTPUT_VIEWED` for the policy.
- The limitations in [masking.md](masking.md#limitations) apply to every
  audience view.
