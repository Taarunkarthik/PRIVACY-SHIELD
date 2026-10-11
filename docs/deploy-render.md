# Deploying PrivacyShield on Render (free plan)

This page gets the hosted site working with **one free web service and one free
Postgres database**. Nothing here needs a terminal: every step is a click or a
copy-and-paste in the Render dashboard.

It is written for the existing web service named **PRIVACY-SHIELD**, which today
shows the sign-in page but answers every `/api` request with `502`. That happens
because only the frontend was deployed; the API, the job worker and Redis were
separate services that need paid plans. After this change the one web service
does all of it.

| What runs | Where |
| --- | --- |
| Sign-in page and dashboard (React) | the web service |
| API | the same web service |
| Scans, classification and deployment jobs | the same web service, in the background |
| PrivacyShield's own data (users, scans, policies, audit log) | the free Postgres, database `privacyshield` |
| The synthetic "enterprise" data that gets scanned and masked | the same Postgres, a second database `enterprise_demo` |

> **Status.** Everything the service does at startup was run against a real
> PostgreSQL server with the same kind of restricted admin user Render provides,
> and the whole product was then used over HTTP. The Docker image itself is built
> and started by a GitHub Actions job, because it could not be built on the
> machine where this was written. It has **not** yet been deployed to a live
> Render account. See [the verification record](verification-render.md).

## Limits of the free plan, stated plainly

- **The site sleeps.** After 15 minutes with no visitors Render stops the
  service. The next visit wakes it, and that first page takes about a minute,
  sometimes closer to two. Later pages are normal.
- **The database is deleted 30 days after you create it.** Render removes free
  databases after 30 days. All users, scans and policies go with it. See
  [After 30 days](#after-30-days) for the five-minute renewal.
- **AI classification is not available.** It needs an Ollama server, and the
  free setup has none. Detection of personal data, masking policies, approval,
  deployment of masked views, the dashboard and the audit log do not use AI and
  all work. A classification job started without Ollama ends as failed with the
  code `OLLAMA_UNAVAILABLE`; the findings stay available for manual review.
- **Scans are slow.** A free instance gets a small share of one CPU. A scan of
  the demo database that takes about 20 seconds on a laptop can take a few
  minutes here. It will finish; the limit is 10 minutes.
- **One job at a time.** Jobs queue up and run in order.
- **Sign-in attempts are counted for everyone together.** More than 10 attempts
  in 5 minutes makes the site answer "Try again later" for up to 5 minutes.

## Before you start

The new code has to be on GitHub, on the branch the service deploys:
`dev/privacyshield`. If you are not sure, ask whoever merged it.

Decide two things and keep them somewhere safe:

- **The administrator email**, for example your own address.
- **The administrator password**, 12 to 128 characters. You will type this on
  the sign-in page.

## Step 1: find the web service's region

1. Open the [Render dashboard](https://dashboard.render.com) and click the
   service **PRIVACY-SHIELD**.
2. Near the top of the page, next to the service name, Render shows the region
   (for example *Singapore* or *Oregon*). Write it down.

The database in the next step **must be in the same region**. A database in a
different region cannot be reached by its internal address.

## Step 2: create the free database

1. In the dashboard click **New** (top right), then **Postgres**.
2. Fill in the form:
   - **Name**: `privacyshield-db`
   - **Database**: `privacyshield` (anything except `enterprise_demo`)
   - **User**: leave empty
   - **Region**: the region from Step 1
   - **PostgreSQL Version**: `16` (the version this was tested with; if 16 is
     not offered, choose the lowest version offered)
   - **Plan** or **Instance Type**: **Free**
3. Click **Create Database** and wait until its status says **Available**.
   This takes a minute or two.

Render allows one free database per workspace. If the button is greyed out, you
already have one: either use it (Step 3) or delete it first.

## Step 3: copy the database's internal address

1. Click the new database, `privacyshield-db`.
2. Find **Internal Database URL** (on the *Info* page under *Connections*, or
   behind the **Connect** button on the *Internal* tab).
3. Click the copy icon beside it. It starts with `postgresql://`.

Use the *Internal* one, not the *External* one. Treat it like a password: it
contains one.

## Step 4: set the environment variables on the web service

1. Go back to **PRIVACY-SHIELD** and click **Environment** in the left menu.
2. Add these four variables (**Add Environment Variable**, or **Edit** then
   **Add**):

   | Key | Value |
   | --- | --- |
   | `CONTROL_ADMIN_URL` | paste the Internal Database URL from Step 3 |
   | `APP_SECRET` | a long random value, see below |
   | `ADMIN_EMAIL` | the administrator email you chose |
   | `ADMIN_PASSWORD` | the administrator password you chose |

3. **Delete `API_BASE_URL`** if it is in the list (click the bin icon on its
   row). It belonged to the old setup and is not used any more. Also delete
   `JOB_RUNNER`, `STATIC_DIR`, `DATABASE_URL` and `REDIS_URL` if any of them is
   there; the service sets what it needs itself.
4. Click **Save Changes**. If Render asks how to save, any choice is fine; the
   deploy in Step 6 is what matters.

**Making `APP_SECRET` without a terminal.** It must be at least 32 characters
and should be random. Any one of these is fine:

- If the value box offers a **Generate** button, click it.
- Or use the password generator in your password manager or browser, set it to
  40 characters or more, and paste the result.
- Or type 40 or more letters and digits at random. It never has to be typed
  again or remembered.

Set it once and **do not change it afterwards**. The database passwords and the
key that protects stored connection passwords are worked out from it. Changing
it signs everybody out, and stored connection passwords other than the demo
connection's can no longer be read.

## Step 5: check the service settings

Still on **PRIVACY-SHIELD**, click **Settings** and check:

| Setting | Value |
| --- | --- |
| Branch | `dev/privacyshield` |
| Dockerfile Path | `./Dockerfile` |
| Docker Build Context Directory | `.` (or empty) |
| Docker Command | **empty** |
| Health Check Path | `/api/v1/health/ready` |
| Instance Type | Free |

To change the health check: scroll to **Health Checks**, click **Edit**, type
`/api/v1/health/ready`, and save.

## Step 6: deploy

1. At the top of the service page click **Manual Deploy**, then **Deploy latest
   commit**.
2. Click **Logs**. The build takes several minutes the first time. When the
   service starts you should see these lines, in this order:

   ```text
   INFO Bootstrap: creating database enterprise_demo
   INFO Bootstrap: creating the synthetic demo tables
   INFO Bootstrap complete.
   INFO Administrator created
   INFO Demo connection registered: enterprise_demo on ...
   INFO Serving frontend from /app/static, jobs run in-process, listening on 0.0.0.0:10000
   ```

3. The deploy is finished when the service's status is **Live**.

If the log stops at a line beginning `ERROR`, that line says what to fix; find
it in [Troubleshooting](#troubleshooting).

## Step 7: sign in and try it

1. Open the service's address (shown under its name, ending in
   `.onrender.com`).
2. Sign in with the administrator email and password from Step 4.
3. Open **Connections**. A connection called **Synthetic enterprise** is
   already there. Nothing has to be typed in.
4. Click **Discover**, then start a **Scan**. Wait for it to finish (a few
   minutes on the free plan), then look at the findings, create a masking
   policy, approve it and deploy it.

Once you have signed in you may delete the `ADMIN_PASSWORD` variable from the
service. The account already exists and the variable is only read to create it.

## After 30 days

Render deletes the free database 30 days after it was created. To carry on:

1. Delete the expired database in the dashboard if it is still listed.
2. Do Step 2 and Step 3 again to create a new one and copy its Internal
   Database URL.
3. On **PRIVACY-SHIELD** > **Environment**, replace the value of
   `CONTROL_ADMIN_URL` with the new URL. Put `ADMIN_PASSWORD` back if you
   deleted it. Leave `APP_SECRET` as it is.
4. **Manual Deploy** > **Deploy latest commit**.

The site starts empty again: the administrator and the demo connection are
created afresh, and earlier scans and policies are gone.

## Troubleshooting

Open **PRIVACY-SHIELD** > **Logs** and look for the line in the middle column.

| What you see | Line to look for in Logs | What to do |
| --- | --- | --- |
| The sign-in page loads but every action fails with **502** on `/api` | There is **no** line `Serving frontend from /app/static, jobs run in-process` | The old frontend-only image is still running, or the new deploy failed. Check **Events** for a failed deploy, redo Step 5 (Dockerfile Path `./Dockerfile`, Docker Command empty), delete `API_BASE_URL` (Step 4), then deploy again (Step 6). |
| A **502** or a blank page for about a minute, then it works | `Bootstrap complete.` appears shortly afterwards | The site was asleep and is waking up. This is the free plan; wait a minute and reload. |
| The deploy fails | `ERROR Startup stopped: CONTROL_ADMIN_URL is not set` | Do Step 3 and Step 4. |
| The deploy fails | `ERROR Startup stopped: APP_SECRET is not set` or `Bootstrap failed: APP_SECRET is ... characters long` | Set `APP_SECRET` to a random value of at least 32 characters (Step 4). |
| The deploy fails | `Bootstrap failed: Cannot connect to database ...` | The URL is wrong, the database is in a different region from the service, or the free database has expired. Copy the **Internal** Database URL again (Step 3); if the regions differ, create the database again in the service's region (Step 2). |
| The deploy fails | `Bootstrap failed: Role ps_... exists but this database user may not manage it` | The database was set up earlier by a different database user. Delete it, create a new one (Step 2) and update `CONTROL_ADMIN_URL`. |
| The deploy fails | `Setup failed: ADMIN_PASSWORD was rejected: Passwords must contain 12 to 128 characters` | Choose a password of 12 to 128 characters and deploy again. |
| **Sign-in rejected**: "Invalid email or password" | `Administrator already exists; its password was left unchanged` | The account keeps the password it was first created with; changing `ADMIN_PASSWORD` later does not change it. Use the original password. If it is lost, set `ADMIN_EMAIL` to a different address with a new `ADMIN_PASSWORD` and deploy: a second administrator is created. |
| **Sign-in rejected**: "Invalid email or password", first deploy | `ADMIN_EMAIL and ADMIN_PASSWORD are not set; no account created` | Add both variables (Step 4) and deploy again. |
| **Sign-in rejected**: "Origin is not allowed" | none | Open the site at its `.onrender.com` address, not through another address or an embedded frame. If you use your own domain, add a variable `FRONTEND_ORIGIN` with that address, for example `https://privacy.example.org`, and deploy. |
| **Sign-in rejected**: "Try again later" | none | More than 10 sign-in attempts in 5 minutes. Wait 5 minutes. |
| **"Target host is not enabled by the operator"** when adding or testing a connection | `Demo connection registered: enterprise_demo on <host>` shows the one host that is allowed | The site only connects to databases on its allow-list, and on this setup that is the demo database. Use the **Synthetic enterprise** connection. To allow another database host, add a variable `TARGET_ALLOWED_HOSTS` with that host name and deploy; the demo host stays allowed. |
| **A scan stays "Queued"** | Within a couple of seconds there should be `Job started: scan <id>`. At startup there should be `Jobs run in-process: one worker thread ...` | If the startup line is missing, a `JOB_RUNNER` variable is overriding the image: delete it and deploy. If another job is running, yours starts when it ends. If the service restarted, queued jobs are picked up again within about 45 seconds of the restart. |
| **A scan stays "Running"** for minutes | `Job started: scan <id>` with no `Job ended` yet | Normal on the free plan's small CPU share; wait. A scan that runs for 10 minutes is stopped and shown as failed with `SCAN_TIMEOUT`. If the site went to sleep or restarted in the middle, the scan is run again automatically after the restart (up to 3 attempts in all). |
| A scan or connection test fails with "Stored credentials could not be decrypted" | `Demo connection: stored credentials could not be read with the current key` | `APP_SECRET` was changed. The demo connection is repaired automatically at the next start. Put the old `APP_SECRET` back if you still have it. |
| Classification fails with `OLLAMA_UNAVAILABLE` | `AI classification is off: OLLAMA_BASE_URL is not set` | Expected on the free setup. See the limits above. |
| Everything is gone, or the deploy fails after about a month | `Bootstrap failed: Cannot connect to database ...` | The free database expired. See [After 30 days](#after-30-days). |

## Environment variables

Set by you:

| Variable | Needed | Meaning |
| --- | --- | --- |
| `CONTROL_ADMIN_URL` | yes | The database's Internal Database URL. Used only while starting, to create the restricted database roles. |
| `APP_SECRET` | yes | One random value, at least 32 characters. Never change it. |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | for the first sign-in | The administrator created at startup if that email has no account. |
| `OLLAMA_BASE_URL`, `OLLAMA_MODEL` | no | The address of an Ollama server and the model name, if you have one. Enables AI classification. |
| `FRONTEND_ORIGIN` | no | Only for a custom domain, if sign-in reports "Origin is not allowed". |
| `TARGET_ALLOWED_HOSTS` | no | Extra database hosts the site may connect to, separated by commas. |

Set by Render or by the image; do not add them: `PORT`, `RENDER_EXTERNAL_URL`,
`JOB_RUNNER`, `STATIC_DIR`. Not used at all: `API_BASE_URL`, `REDIS_URL`.

## For engineers

### How one service does everything

The repository-root `Dockerfile` builds the frontend, then an image based on the
backend with the built files in `/app/static`. Its command is
`backend/scripts/render/start-all.sh`:

1. `python -m app.render_bootstrap` connects as the admin user in
   `CONTROL_ADMIN_URL`, derives every secret from `APP_SECRET`, creates the
   roles `ps_migrator`, `ps_app`, `ps_scanner`, `ps_deployer`, `ps_view_owner`
   and `ps_reader`, creates the `enterprise_demo` database with its synthetic
   tables, hands the control database to `ps_migrator`, and applies migrations.
   It is idempotent.
2. `python -m app.render_seed` creates the administrator and registers the
   "Synthetic enterprise" connection through the application's own models and
   credential encryption.
3. The provisioning credentials are removed from the environment and `uvicorn`
   starts on `0.0.0.0:$PORT` with `JOB_RUNNER=inline` and
   `STATIC_DIR=/app/static`. The server process holds only the `ps_app`
   database URL and the encryption key.

With `STATIC_DIR` set the API also serves the frontend, with the same security
headers nginx sends in the Compose deployment (`backend/app/frontend.py`).

### Jobs without Celery or Redis

With `JOB_RUNNER=inline` (`backend/app/workers/inline.py`) the API process runs
jobs itself. PostgreSQL is the queue: a job is a committed row before anything
else happens, exactly as with Celery.

| Celery deployment | Inline mode |
| --- | --- |
| Redis delivers the job identifier to a worker | The request hands the identifier to one worker thread in the same process; the job starts immediately |
| Celery beat calls the `dispatch_*` functions every 15 seconds | A supervisor thread calls the same functions every 15 seconds, and once right after startup |
| One worker process (`--concurrency=1`) | One worker thread: one job at a time, one copy of the detection model in memory |
| Soft time limit: `SoftTimeLimitExceeded` is raised in the task (scan 600 s, classification 900 s, deployment 120 s) | The same exception is raised in the worker thread at the same limits. The job code that already turns it into `SCAN_TIMEOUT` / `CLASSIFICATION_TIMEOUT` is unchanged |
| Hard time limit: the worker process is killed (660 s, 1050 s, 150 s) | A thread cannot be killed, so the **process exits** with status 70. The platform restarts the service, the job's advisory lock is released with its connection, and the sweep runs the row again as a new attempt (3 attempts in all) |
| Worker killed mid-job: row stays `RUNNING`, re-dispatched after 30 s | The same rule, applied by the sweep after the service restarts |

Two things bound a job besides those limits. Every database statement has a
timeout (10 s for the control plane and the scanner, 30 s for the deployer) and
every connection attempt has one (5 s), as before. And the soft limit is
delivered between Python instructions: it interrupts detection and other Python
work at once, but a call blocked inside the database driver is only interrupted
when the call returns, which the statement timeouts guarantee. A call blocked
on a dead network connection is what the hard limit is for.

On a clean stop (`SIGTERM`, as on every redeploy and when the free instance goes
to sleep) the runner stops accepting work and waits up to 20 seconds for the
running job. A job that does not finish in that time stays `RUNNING` and is
recovered after the next start.

`GET /api/v1/health/ready` in this mode reports
`{"database": "ok", "redis": "not_used", "jobs": "ok"}`; `jobs` is `unavailable`
if the job threads are not alive, which makes the platform restart the service.

### Security properties of this layout

The role model is the one in [architecture.md](architecture.md). What is
different from Compose is that both databases are in one PostgreSQL instance:

- `CONNECT` is revoked from `PUBLIC` on both databases. The scanner, deployer
  and reader roles cannot open the control database, and the application and
  migration roles cannot open the demo database.
- The admin user in `CONTROL_ADMIN_URL` is a member of `ps_migrator` and
  `ps_view_owner`. PostgreSQL 16 requires that before a non-superuser can give
  those roles ownership of the database, schemas and tables. The admin user is
  used only by the two startup steps.
- If the admin user cannot transfer ownership of the control database (it would
  need `CREATEDB`), migrations run as the admin user instead of `ps_migrator`.
  The application still connects as `ps_app`, so it still cannot change the
  schema or update or delete audit rows. What is lost in that case is only the
  separate migration credential. On a server like Render's, where the admin user
  has `CREATEDB` and `CREATEROLE`, the transfer succeeds and nothing is lost.
- The demo data is synthetic. Do not point `TARGET_ALLOWED_HOSTS` at a database
  you are not authorised to inspect.

### Memory

Measured on the development machine with the real frontend build and the
production dependency set, `ps -o rss=` of the server process:

| State | Resident memory |
| --- | --- |
| Started, idle | about 98 MB |
| After real scans of the demo database (Presidio and the spaCy model loaded) | about 231 MB |
| The same, during 8 simultaneous sign-in attempts | 354 MB at its highest |

Password hashing uses 64 MB per computation. It is limited to two at a time
(`backend/app/core/security.py`); without that limit the same 8 attempts were
measured at 736 MB, more than a free instance has.

### Using the Blueprint instead of the dashboard

`render.yaml` describes the same setup: **New** > **Blueprint**, pick the
repository and the `dev/privacyshield` branch, and enter `ADMIN_EMAIL` and
`ADMIN_PASSWORD` when asked. Render generates `APP_SECRET` and wires
`CONTROL_ADMIN_URL` to the database. The service in the file is named
`PRIVACY-SHIELD`; Render's documentation says a Blueprint applies itself to an
existing service of the same name rather than creating a second one. The file
asks for the `singapore` region. A service's region cannot be changed, so if
the existing service is elsewhere, use the dashboard steps above instead.

### Checking a deployment from a terminal

```shell
ADMIN_PASSWORD='...' python scripts/check_hosted.py \
    --base-url https://<name>.onrender.com --email you@example.com --scan
```

It checks the frontend, security headers, readiness, sign-in, the demo
connection and, with `--scan`, a real scan. It uses only the Python standard
library and never prints the password.

### The paid, multi-service layout

`render.paid.yaml` is the earlier Blueprint: separate API, Celery worker and
nginx services, Key Value (Redis) and two Postgres instances. It needs paid
plans (Render has no free workers and one free Postgres per workspace) and has
not been deployed. It uses `backend/Dockerfile`, `frontend/Dockerfile`,
`start-api.sh` and `start-worker.sh`, with `JOB_RUNNER` left at its default,
`celery`.

## Local alternative

The same application still runs locally with `docker compose up -d --build --wait`;
see the [README](../README.md) and [operations runbook](operations.md). Compose
does not use the root `Dockerfile`, `JOB_RUNNER=inline` or `STATIC_DIR`.
