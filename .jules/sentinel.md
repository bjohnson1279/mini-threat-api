## 2024-05-24 - Strict Secret Configuration Enforcement
**Vulnerability:** A hardcoded default `JWT_SECRET_KEY` in `app/config.py` allowed the app to start with an insecure, known secret if the environment variable was missing.
**Learning:** Using dynamic defaults (like `secrets.token_urlsafe()`) in Pydantic `BaseSettings` breaks multi-worker deployments by generating a unique secret per worker.
**Prevention:** Strictly omit defaults for module-level secrets in `BaseSettings` so the application predictably fails if the environment variable is not provided, ensuring security configurations are explicit.

## 2024-05-18 - Hardcoded JWT Secret Fallback Removed
**Vulnerability:** A hardcoded `JWT_SECRET_KEY` fallback was present in `app/config.py` which allowed attackers reading the codebase to forge access tokens if the env variable wasn't set.
**Learning:** Initial attempt to replace the fallback with a dynamically generated string (`secrets.token_urlsafe(32)`) led to bugs in multi-worker environments since each worker generated a different secret at module load.
**Prevention:** Remove the default value entirely for sensitive keys in Pydantic models. This ensures the app fails securely (crashing on startup) instead of falling back to insecure or inconsistent behavior.

## 2024-05-24 - Remove Hardcoded Secret
**Vulnerability:** A hardcoded `JWT_SECRET_KEY` was found in `app/config.py` as a fallback value for an environment variable.
**Learning:** Hardcoded secrets in application code can be easily exposed via version control and can break multi-worker deployments (e.g., Gunicorn/Uvicorn) if dynamic defaults like `secrets.token_urlsafe()` are used.
**Prevention:** Always omit default values for sensitive configuration options in Pydantic BaseSettings to enforce configuration via environment variables, ensuring secrets are managed securely and explicitly.

## 2023-10-27 - [Plaintext Passwords in Mock Database]
**Vulnerability:** Found plaintext passwords hardcoded in MOCK_USERS_DB dictionary (`app/auth.py`), verified using naive string comparison (`!=`) in `app/main.py`.
**Learning:** Hardcoded credentials are a critical security flaw. Additionally, the standard `passlib` is broken on modern python (3.12) with bcrypt>=4.0 due to unmaintained codebase calling non-existent `__about__`.
**Prevention:** Always use one-way hashing algorithms like bcrypt for passwords. Prefer using the raw `bcrypt` library directly over the broken `passlib` on Python 3.12+ environments.

## 2024-05-15 - User Enumeration Timing Attack Mitigation
**Vulnerability:** The `/auth/token` endpoint immediately returned a 401 if a user wasn't found in the database, without performing any password hashing. This noticeable timing difference can be used by an attacker to enumerate valid usernames (timing attack).
**Learning:** Short-circuit evaluation (`not user or not verify_password(...)`) is efficient but creates a side channel when verification involves expensive operations like bcrypt hashing.
**Prevention:** Always perform a dummy hash verification (using a valid, static dummy hash, e.g., `b"$2b$12$..."` for bcrypt) when a user is not found to ensure consistent response times regardless of whether the user exists or not.

## Prevention Directives for Automated Refactoring
- **Never Overwrite Complete Files**: Always use range-scoped replacement chunks for edits to `schema.prisma`, `index.ts`, `public/index.php`, `db/schema.rb`, or DDL SQL scripts.
- **Do Not Remove Core Declarations**: Do not delete existing route registrations or database DDL tables.
- **Environment Isolation Compatibility**: When replacing fallback secrets, preserve test environment execution via `!getenv('APP_ENV')` or `getenv('APP_ENV') === 'testing'`.
- **No Scratch Files**: Never stage or commit `test_*.ts`, `test_*.js`, `test.cjs`, `fix_*.php`, or `test.js` files to git.
- **No Unresolved Conflict Markers**: Never stage or commit files containing Git merge conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`, `|||||||`). Always resolve conflicts cleanly before committing.

## Completeness & Verification Directives
- **Explicit Parameter & Contract Validation**: When creating or modifying API endpoints (Express, Fastify, Rails, Laravel), always implement explicit parameter and request body validation schemas (e.g. `z.string().uuid()`) to prevent unhandled 404/500 fallthroughs.
- **Database Indexing for Queries**: When addressing query bottlenecks or adding query lookup filters, always implement native database index migrations rather than loading collections into memory and performing array filtering (`.filter()`, `.select`).
- **Co-Occurring Dependency Auditing**: When bumping any dependency version, verify that other transitive dependencies do not carry high/critical security advisories (e.g. run `bundler-audit`, `npm audit`). Never introduce a version bump that breaks underlying framework APIs.
- **Self-Verification Before Commit**: Always run syntax checks (`bash -n` for shell scripts, `tsc --noEmit` for TypeScript, linter checks) and targeted test runners locally before opening or updating a PR.

## Hallucinatory Task & Empty PR Directives
- **Zero-Diff Task Termination**: If the requested optimization, refactor, or fix is ALREADY natively present in the target branch, DO NOT create an empty pull request or commit an acknowledgment PR. Exit the task cleanly without opening a PR.
- **Stale Suggestion Guard**: Always verify the current code on `main`/`master` before planning changes. If no actionable diff is required, cancel task execution immediately.

## 2024-05-24 - Authorization Bypass in Threat Intel Ingestion
**Vulnerability:** The `POST /iocs` endpoint only validated that a user was authenticated (via `get_current_user`), but failed to enforce Role-Based Access Control (RBAC). Any authenticated user, including read-only users or guests, could ingest new threat intelligence indicators into the database.
**Learning:** In FastAPI, depending on an authentication function ensures identity but not authorization. A dedicated authorizer dependency (like `require_role`) is necessary for endpoints that modify state or sensitive data.
**Prevention:** Always verify endpoint dependencies for write operations. Use `Depends(require_role("role_name"))` instead of `Depends(get_current_user)` when restricting access based on privileges. Ensure unit tests validate that lower-privileged users receive a 403 Forbidden response for administrative actions.
