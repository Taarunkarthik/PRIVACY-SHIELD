# Deploying PrivacyShield on Vercel (experimental)

> **Status: experimental and unverified.** Nothing on this page has been run on
> Vercel. The image is the one used for the single-service deployment
> ([deploy-render.md](deploy-render.md)), with a small start wrapper for
> Vercel's environment. The wrapper is tested against a real PostgreSQL server;
> Vercel's container runtime, its lifecycle and a Neon database are not part of
> any test here. Treat the first deploy as the test. The supported hosted route
> is still [Render](deploy-render.md).

Vercel can run a container image as a function (the "Container Runtime", in
beta on all plans). It detects `Dockerfile.vercel` in the repository root,
builds it, and routes every request to the container. PrivacyShield runs there
as one container that serves the frontend, the API and the background jobs,
with a Postgres database added from the Vercel Marketplace (Neon).

## What is different from a normal server

These follow from how Vercel runs containers, and they are why this route is
experimental:

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
  again when the next container starts. **Whether jobs complete reliably on
  Vercel is the main thing a first deploy has to show.**
- **Use the production deployment.** Preview deployments stop after 30 seconds
  idle, which is shorter than a scan.
- **AI classification is not available** (no Ollama server), as on Render.
- **The database is on the public internet**, protected by TLS and passwords.
  The scanned "enterprise_demo" data is synthetic.

## Steps

All in the Vercel dashboard. The code must already be on the repository's
default branch, `dev/privacyshield`.

1. **Import the repository.** *Add New…* → *Project* → import
   `PRIVACY-SHIELD`. Framework Preset: **Other**. Root Directory: leave as it
   is. Do not deploy yet if the page lets you add variables first; otherwise
   let the first deploy fail and continue.
2. **Add the database.** In the project open **Storage** → *Create Database* →
   **Neon** (Postgres) → plan **Free** → region **Washington, D.C. (iad1)**,
   which is where Vercel runs functions by default. A database in another
   region makes every start slow. Connect it to this project for the
   Production environment.
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
| `Bootstrap failed: ...` followed by a permission error | Neon does not allow a statement the bootstrap needs. This is one of the untested parts | Send the line; it names the statement |
| `WARNING PORT is not set` and then a permission error | The server tried port 80 as a non-root user | Add `PORT=10000` and redeploy |
| Every page is a `502` or `504` | The container did not start listening in time, or on the wrong port | Check `PORT`, then look for the last `INFO` line to see how far startup got |
| Sign-in answers `Origin is not allowed` | You are on a custom domain | Add `FRONTEND_ORIGIN` with that `https://` address |
| A scan stays `Queued` or `Running` for minutes | The container's background work is being paused or stopped | This is the known risk above. Use Render for jobs |

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

Not checked:

- building or running the image on Vercel;
- Neon: whether its database owner may do everything the bootstrap does
  (create the roles and the second database, change owners, set role
  options), whether the direct endpoint accepts the connection options the
  application sends, and its PostgreSQL version (this build was tested on 16
  only);
- how long a cold start takes there, and whether it is within what Vercel
  allows;
- whether background jobs keep running between requests.
