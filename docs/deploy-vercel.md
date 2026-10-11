# Deploying PrivacyShield on Vercel

> **Status: deployed once and working, on a beta platform feature.** On
> 11 October 2026 this was deployed at
> [privacy-shield-gamma.vercel.app](https://privacy-shield-gamma.vercel.app)
> with a Neon database from the Vercel Marketplace. The site answered its
> readiness check with the database and the job runner both `ok`, and the
> project owner signed in, ran a scan to completion, deployed a masking policy
> and verified the audit chain as intact. That is one deployment used by one
> person for a few minutes: see [what was checked](#what-was-checked-and-what-was-not)
> for what it does and does not show. Vercel's container runtime is in beta.

Vercel can run a container image as a function (the "Container Runtime", in
beta on all plans). It detects `Dockerfile.vercel` in the repository root,
builds it, and routes every request to the container. PrivacyShield runs there
as one container that serves the frontend, the API and the background jobs,
with a Postgres database added from the Vercel Marketplace (Neon).

## What is different from a normal server

These follow from how Vercel runs containers:

- **The container is stopped after 5 minutes without requests** (30 seconds for
  preview deployments). The next visit starts a new one, which first checks
  the database and migrations. Expect that first page to take 10 seconds or
  more.
- **Jobs run in the background of that container.** A scan, a classification or
  a deployment is started by a request and finishes after the request has
  returned. Vercel describes containers as meant for request handling, not
  background work. While the page is open it polls for progress, which counts
  as traffic and keeps the container up, so a scan should finish. If the
  container is stopped mid-job, the job row stays in the database and is run
  again when the next container starts. In the first deployment a scan and a
  policy deployment both completed with the page open. What happens to a job
  when the page is closed, or under repeated use, has not been tried.
- **Use the production deployment.** Preview deployments stop after 30 seconds
  idle, which is shorter than a scan.
- **AI classification is not available** (no Ollama server), as on Render.
- **The database is on the public internet**, protected by TLS and passwords.
  The scanned "enterprise_demo" data is synthetic.

## Steps

All in the Vercel dashboard. The code must already be on the repository's
default branch, `dev/privacyshield`.

1. **Import the repository.** *Add New…* → *Project* → import
   `PRIVACY-SHIELD`. Root Directory: leave it as `./`.

   Vercel reads the repository layout and proposes **Services** with three
   entries: `backend` (FastAPI), `frontend` (Vite) and `privacy-shield`
   (Container). Do not accept that. PrivacyShield is the one container; the
   proposed split would send `/api` to a bare FastAPI function with no
   database setup and no job runner. Change **Application Preset** away from
   *Services* so that only the root container is deployed (*Container*, or
   *Other* if that is what the list offers). No `vercel.json` is needed.

   Add the variables from step 3 on this screen if it lets you, then deploy.
   This first deploy builds the image but cannot start, because a database can
   only be attached once the project exists.
2. **Add the database.** In the project open **Storage** → *Create Database* →
   **Neon** (Postgres) → plan **Free** → region **Washington, D.C. (iad1)**,
   which is where Vercel runs functions by default. A database in another
   region makes every start slow. Connect it to this project for the
   Production environment. The connect form requires a **Custom Prefix** for
   the variables it adds; any value works (`DATABASE` gives the usual names).
   Leave "Create database branch for deployment" unticked.
3. **Add four variables.** *Settings* → *Environment Variables*, for
   Production:

   | Name | Value |
   | --- | --- |
   | `PORT` | `10000` |
   | `APP_SECRET` | 40 or more random characters. Set once, never change |
   | `ADMIN_EMAIL` | the address you will sign in with |
   | `ADMIN_PASSWORD` | 12 to 128 characters |

   Nothing else is needed: the start script finds the database from the
   variables the Neon integration adds, whatever prefix they were given when
   the database was connected. If it cannot, add `CONTROL_ADMIN_URL` yourself:
   in the Neon console click **Connect**, switch **Connection pooling** off,
   and copy the connection string (its host has no `-pooler` in it).

   **Do not import a local `.env` file.** Two of its values are wrong for a
   hosted site: `ALLOWED_ORIGINS` (it names `http://localhost:8080`, which
   stops the project's own address being allowed automatically) and
   `COOKIE_SECURE=false` (it removes the Secure flag from the session cookie).
   Delete both if they are there. The other values from that file are either
   ignored or used in place of the ones derived from `APP_SECRET`.
4. **Deploy.** *Deployments* → the latest one → *Redeploy*. The build takes
   several minutes the first time.
5. **Open the production address** (`<project>.vercel.app`) and sign in. A
   connection called **Synthetic enterprise** is already there.

## Reading the logs

Open the deployment → **Logs**. A good start prints, in order:

```text
INFO Bootstrap: creating database enterprise_demo
INFO Bootstrap complete.
INFO Administrator created
INFO Demo connection registered: enterprise_demo on ...
INFO Serving frontend from /app/static, jobs run in-process, listening on 0.0.0.0:10000
```

| What you see | Likely cause | What to do |
| --- | --- | --- |
| `ERROR Startup stopped: no database is connected` | The Neon database is not connected to this project and environment | Storage → the database → Connect Project, then redeploy |
| `ERROR Startup stopped: only a pooled database URL was found` | The integration did not provide a direct connection string | Add `CONTROL_ADMIN_URL` with the database's direct (unpooled) connection string from the Neon console |
| `Bootstrap failed: ...` followed by a permission error | The database user may not do something the bootstrap needs. It worked on the Neon database of the first deployment | The line names the statement |
| `WARNING PORT is not set` and then a permission error | The server tried port 80 as a non-root user | Add `PORT=10000` and redeploy |
| Every page is a `502` or `504` | The container did not start listening in time, or on the wrong port | Check `PORT`, then look for the last `INFO` line to see how far startup got |
| Sign-in answers `Origin is not allowed` | You are on a custom domain | Add `FRONTEND_ORIGIN` with that `https://` address |
| A scan stays `Queued` or `Running` for minutes | The container's background work is being paused or stopped | Keep the page open and wait for the next container start to pick the job up again. If it keeps happening, use Render for jobs |

## What was checked, and what was not

Checked here, on PostgreSQL 16 with a restricted (non-superuser) admin:

- the start wrapper picks the direct database URL (also when the integration's
  variables carry a custom prefix), refuses a pooled one, removes every other
  variable that holds a Postgres URL or the database owner's password before
  the server starts, allows the project's own `*.vercel.app` addresses for the
  origin check, and falls back to `/tmp` for a home directory;
- started through the wrapper, the server comes up, serves the frontend, signs
  an administrator in from both Vercel addresses, and refuses another origin;
- `Dockerfile.vercel` has exactly the build steps of `Dockerfile`.

Seen on Vercel, 11 October 2026, on the deployment named at the top (built from
`dev/privacyshield` at `89a5663`):

- Vercel built `Dockerfile.vercel` and the container started;
- from outside, `GET /api/v1/health/ready` returned
  `{"status":"ok","checks":{"database":"ok","redis":"not_used","jobs":"ok"}}`.
  That requires the bootstrap to have created the roles and the second
  database on Neon and the migrations to have run;
- reported by the project owner, not observed independently: signing in, a
  scan reaching Completed, a masking policy deployed, and the audit chain
  verified as Intact.

Not checked:

- anything beyond that one short session: repeated use, several people at
  once, a job running when the page is closed or when the container is
  stopped after five idle minutes;
- how long a cold start takes there;
- which PostgreSQL version and region that Neon database has (this build is
  otherwise tested on 16 only);
- the automatic discovery of the database variables on Vercel. That
  deployment was built before the start script learned to read prefixed
  variable names, and was set up by giving `CONTROL_ADMIN_URL` by hand (those
  were the steps followed; the project's settings were not inspected). The
  discovery is covered by the tests above only;
- whether background jobs keep running between requests.
