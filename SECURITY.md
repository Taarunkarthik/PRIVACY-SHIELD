# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities through GitHub's private security
advisory on this repository (**Security** tab → **Report a vulnerability**).
Do not open a public issue for a security problem.

Reports are acknowledged on a best-effort basis, as this is a small academic
project.

## Supported versions

PrivacyShield is in active academic/hackathon development on the default
branch. Only the latest revision of the default branch is supported; there are
no maintained release branches or back-ported fixes.

## Scope and known limitations

- The architecture and trust boundaries are described in
  [`docs/architecture.md`](docs/architecture.md). Security notes and limitations
  are listed in the README's
  [Security notes and limitations](README.md#security-notes-and-limitations)
  section.
- The bundled target database contains **synthetic data only**. It is not real
  customer data and must not be treated as a production dataset.
- AI recommendations are **advisory**. The model sees metadata and sanitized
  evidence, never raw rows, and cannot execute SQL.
- The default configuration is a **local demonstration**, not a certified
  production deployment. Before exposing the stack beyond localhost, terminate
  TLS, enable secure cookies and set explicit allowed origins.

## Secrets

Never commit `.env`, connection credentials, or the `.secrets/` directory. The
repository's `.gitignore` already excludes them; keep it that way and use
`.env.example` for placeholders only.
