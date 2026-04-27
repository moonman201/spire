# SPIRE — Replit Environment

SPIRE (Sanitization, Prediction, Intelligence, Readiness Engine) is a
contested-logistics operating system originally built for USMC pilots. This
file documents how the project is wired to run inside Replit.

## Stack

- **Backend** — FastAPI (Python 3.12) under `backend/`. Generates a synthetic
  canonical dataset at boot using the `dataset/` engine. Serves the REST API
  under `/api/*`. Listens on `127.0.0.1:8000` in the Replit dev environment.
- **Frontend** — React 19 + Vite 8 + TypeScript under `frontend/`. Tailwind 4,
  MapLibre, Recharts, Zustand, React Router. Vite dev server listens on
  `0.0.0.0:5000` and proxies `/api/*` to the backend.

## Workflows

- **Backend** — `python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000`
  (console output). Dataset generation takes ~30–60 seconds on cold start.
- **Frontend** — `cd frontend && npm run dev` (webview, port 5000).

## Replit-specific changes vs upstream

- `frontend/vite.config.ts` — bound to `0.0.0.0:5000`, `allowedHosts: true`
  so the Replit iframe proxy can reach it, and the dev proxy targets
  `http://localhost:8000` instead of the upstream `:8700` (port 8700 isn't
  in Replit's allowed dev port set).
- `backend/main.py` — CORS widened (`allow_origin_regex=".*"`,
  `allow_credentials=False`) so the proxied iframe origin works. The
  upstream still ships locked-down origins for the air-gap deploy.

The upstream Docker / Fly path (`Dockerfile`, `Dockerfile.web`,
`docker-compose.yml`, `fly.toml`, `deploy/`) is left alone — those still
target the original `:8700` backend / `:8080` nginx layout.

## Deployment

Replit deployment serves the built React bundle from FastAPI on port 5000.
See `frontend/dist/` (built on deploy) and the static-mount block in
`backend/main.py`.

## RBAC / session auth

- `backend/auth.py` — stdlib HMAC-SHA256 session bearer (8h TTL). Known roles:
  `maintenance_chief`, `g4`, `mef_commander`, `data_custodian`,
  `security_manager`.
- **Demo-mode boundary.** Backend refuses to boot if `SPIRE_SESSION_SECRET`
  is missing **unless** `SPIRE_DEMO_MODE=1` is set (then it generates an
  ephemeral per-process secret). The Replit Backend workflow sets both env
  vars so the persona-dropdown demo keeps working.
- **Open mint endpoint gated.** `POST /api/auth/session {"role": "..."}`
  works only in demo mode; outside, it returns
  `503 {"error": "DemoModeRequired"}`. Production deployments must front-end
  it with a CAC/Keycloak adapter.
- **Production deployment checklist** (do NOT skip — the demo defaults are
  intentionally insecure for the workshop walkthrough):
  1. **Unset `SPIRE_DEMO_MODE`** in the deployment env (any value other than
     `1` works, but unsetting is cleanest). This re-closes the open mint
     endpoint and the missing-secret refuse-to-boot guard.
  2. **Set `SPIRE_SESSION_SECRET`** to a high-entropy value via Replit
     Secrets (≥32 random bytes; `python -c "import secrets;
     print(secrets.token_urlsafe(48))"`). Do NOT reuse the dev secret
     baked into `.replit` — it's intentionally fixed for predictable
     demos and must never reach production.
  3. **Set `SPIRE_DB_PASSPHRASE`** so the at-rest Fernet layer is keyed by
     a real secret instead of the empty-string default.
  4. **Front the mint endpoint with the CAC/Keycloak adapter** before
     real users hit it — the open mint is the IdP shim; once a real IdP
     issues bearers carrying `{role, unit, billet, attested_by}`, the
     mint route can be removed entirely.
  5. **Add perimeter rate-limiting** (per-IP token bucket, mTLS, or move
     `/api/auth/session` behind the IdP) — there is no in-process
     rate-limit on mint today and the redteam suite explicitly notes this.
  These steps are also captured in the deployment runbook in PR #28.
- **Structured Principal envelope.** Bearer payload carries
  `{role, unit, billet, attested_by, attested_at, iat, exp, sid, jti}`.
  FastAPI deps: `current_principal` (full Principal dataclass),
  `current_role` (legacy shim), `current_role_optional`.
  `GET /api/auth/whoami` echoes the principal.
- **Token revocation kill-switch.** `revoked_sessions` table
  (`backend/persistence.py`) + `verify()` checks revocation on every
  request and surfaces `TokenRevoked`. `POST /api/auth/revoke` (security
  manager only) writes locally and `routes/system.py` mirrors the event
  onto the air-gap sync queue as a `session.revoke` op.
- **Audit-chain retention.** Soft-redaction via
  `persistence.prune_audit(days)` preserves the SHA-256 spine; the
  `audit_log.redacted` flag tells `verify_chain()` to chain through the
  stored `self_hash`. Operator helper: `python scripts/audit_prune.py
  --days 90 [--dry-run]`. The prune itself is recorded as `audit_pruned`.
- `backend/scoping.py` — per-module role allowlists
  (`PULSE_VIEW_ROLES`, `SENTRY_VIEW_ROLES`, `BASTION_VIEW_ROLES`,
  `COALITION_RELEASE_ROLES`, `AUDIT_READ_ROLES`, `REVOKE_ROLES`) and
  unit-scope filters. Sensitive routes call `require_role(...)` and pass
  the bearer-resolved actor into `audit_log(...)` so payload `actor_role`
  claims are ignored.
- Frontend (`frontend/src/api.ts`) attaches `Authorization: Bearer <token>`
  to every request, surfaces a `DemoModeRequired` error if mint returns
  503, and re-mints on 401 / `setRole`.
- Regression: `python scripts/rbac_regression.py` — 48 cases (issues #3-#10
  + 5 hardening cases for revoke, structured principal, whoami,
  air-gap-queue propagation).
- Adversarial: `python scripts/rbac_redteam.py` — 30 attacks covering
  replay-after-revoke, malformed-bearer shapes, signature-strip, payload
  byte-flip escalation, manually-aged token, signed unknown-role,
  persona-swap race, brute-force-mint visibility, open-mint refusal in
  non-demo subprocess, and missing-secret refuses-to-boot subprocess.
  All attacks repelled.
