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

## 2024-05-24 - Missing Authorization on State-Modifying Endpoint
**Vulnerability:** The `POST /iocs` endpoint used `get_current_user`, which validates identity (authentication) but not permissions (authorization). Any valid user, including a guest, could ingest threat indicators.
**Learning:** Authentication dependencies like `Depends(get_current_user)` only prove *who* the user is, not *what* they are allowed to do. State-modifying endpoints must explicitly check roles.
**Prevention:** Always enforce Role-Based Access Control (RBAC) (e.g., using `require_role`) on endpoints that create, modify, or delete sensitive data or modify state, to prevent authorization bypass.

## 2024-09-15 - bcrypt DoS via Maximum Password Length
**Vulnerability:** The `/auth/token` endpoint passed raw user passwords directly to `bcrypt.checkpw()`. If a password exceeded 72 bytes, the `bcrypt` library threw a `ValueError`, resulting in a 500 Internal Server Error (Denial of Service).
**Learning:** The Python `bcrypt` library enforces a strict 72-byte limit on passwords. Unhandled, this allows attackers to trivially crash or exhaust server resources by submitting overly long passwords.
**Prevention:** Always check password length before passing to `bcrypt.checkpw()`. For passwords > 72 bytes, handle them gracefully (e.g., truncate and force an authentication failure) to prevent exceptions while maintaining constant-time execution to avoid timing attacks.

## 2024-05-24 - Missing Input Length Limits
**Vulnerability:** The `IOCBase` schema in `app/schemas.py` lacked `max_length` constraints on string fields like `indicator_value`, `threat_type`, and `description`, which have strict length limits in the database (e.g. `String(255)`). An attacker could send massive payloads, bypassing application-level validation and causing the underlying database driver (like PostgreSQL) to throw fatal `DataError` exceptions, leading to unhandled 500 Internal Server Errors and potential Denial of Service.
**Learning:** Pydantic validation must match or be stricter than database schema limits to ensure that invalid payloads are cleanly rejected at the application edge (returning 422 Unprocessable Entity) before consuming database resources or causing crashes.
**Prevention:** Always define `max_length` constraints on string fields in Pydantic schemas corresponding to the maximum column lengths defined in SQLAlchemy models.

## 2024-05-24 - Authorization Bypass Token Generation for Disabled Accounts
**Vulnerability:** The `/auth/token` endpoint verified user passwords and generated valid JWT access tokens for accounts marked as `"disabled": True` in `MOCK_USERS_DB`. Although the application correctly rejected usage of tokens by disabled users in protected routes via `get_current_user`, issuing a token is an unnecessary security risk and should be prevented at the authentication stage.
**Learning:** Checking the account status only when using a token leaves a gap where disabled accounts can still authenticate and receive tokens. A defense-in-depth strategy requires preventing token issuance for disabled accounts in the first place, treating them similarly to non-existent accounts to mitigate timing attacks.
**Prevention:** Always verify account status (e.g., `disabled`) during the authentication phase before issuing tokens. Check `not user_dict.get("disabled", False)` along with checking if the user exists. Handle disabled accounts seamlessly with non-existent accounts using dummy hashes for consistent response times.

## 2024-10-24 - SQL LIKE Wildcard Injection and Missing Input Length Limits
**Vulnerability:** The `/iocs` endpoint lacked input length limits on query parameters (e.g., `search`) and failed to escape SQL wildcards (`%`, `_`) in SQLAlchemy `.ilike()` filters. This allowed Denial of Service (DoS) attacks via overly long payloads causing DB driver errors, or via excessively complex wildcard queries causing database resource exhaustion.
**Learning:** Query parameters that feed directly into expensive database operations (like full-text search or `LIKE` queries) must be strictly bounded in length and sanitized to prevent attackers from intentionally crafting expensive queries that degrade database performance or cause crashes.
**Prevention:** Always enforce `max_length` bounds on FastAPI Query parameters that correspond to database text fields. Always escape wildcards (`%`, `_`, `\`) in user input before passing them to SQL `LIKE` or `.ilike()` operators to prevent injection, using the `escape="\\"` parameter in SQLAlchemy.

## 2024-10-24 - Rate Limiting on Login Endpoint
**Vulnerability:** The `/auth/token` endpoint was vulnerable to brute-force credential stuffing and DoS attacks due to a lack of rate limiting. An attacker could rapidly guess passwords or exhaust server resources because it is a CPU-bound endpoint checking bcrypt hashes.
**Learning:** Endpoints that perform computationally expensive tasks (like bcrypt validation) or authentication must always be rate-limited, as they amplify the effect of unauthenticated DoS traffic and allow for rapid brute-forcing.
**Prevention:** Implement IP-based or user-based rate limiting on sensitive routes. For simple applications without Redis, a lightweight in-memory dictionary bounded by time (and optimally cleaned up) can provide effective basic protection against brute force and DoS.

## 2026-09-21 - [Security Headers for API Defense]
**Vulnerability:** The FastAPI application was missing standard security HTTP headers (like `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`), leaving it potentially vulnerable to MIME-sniffing, clickjacking (on browser-rendered parts like Swagger UI), and lacking forced HTTPS enforcement for consumers.
**Learning:** Even for pure APIs, setting security headers provides defense-in-depth, especially when hosting auto-generated API documentation UIs (like Swagger/ReDoc) that are rendered in web browsers.
**Prevention:** Always implement a global middleware to enforce standard security headers on all HTTP responses, ensuring browsers enforce strict security policies regardless of the endpoint accessed.

## 2024-10-24 - Integer Overflow DoS
**Vulnerability:** The `GET /iocs/{ioc_id}` endpoint lacked input validation on the `ioc_id` path parameter. Large positive or negative integers would be passed directly to the database driver, potentially resulting in an `OverflowError` or unhandled database exception (DoS).
**Learning:** Frameworks like FastAPI do not automatically cap unbound integer parameters to match 32-bit/64-bit limits of the database drivers, enabling attackers to cause internal server errors via out-of-bounds input.
**Prevention:** Always bound path integers by enforcing schema constraints (e.g., using `Path(..., ge=1, le=2147483647)` for typical 32-bit ID fields) to protect the application and database from unbounded inputs.

## 2024-10-24 - Integer Overflow DoS on Query Parameters
**Vulnerability:** The `GET /iocs` endpoint lacked input validation on the `offset` query parameter. Large positive integers would be passed directly to the database driver for pagination, potentially resulting in an `OverflowError` or unhandled database exception (DoS).
**Learning:** Frameworks like FastAPI do not automatically cap unbound integer parameters to match 32-bit/64-bit limits of the database drivers. This applies to both path parameters and query parameters like `offset`, enabling attackers to cause internal server errors via out-of-bounds input.
**Prevention:** Always bound all integer parameters (both path and query) by enforcing schema constraints (e.g., using `Query(..., ge=0, le=2147483647)` for typical 32-bit offset/limit fields) to protect the application and database from unbounded inputs.

## Assertiveness, Decisive PR Execution & Comparative Recommendations
- **Proactive & Decisive PR Submission**: Do NOT repeatedly pause to ask permission to open a pull request (e.g., avoid "Would you like me to open a PR for this?", "Can I submit the PR?", "Should I go ahead and create the PR?"). When an optimization, fix, or feature satisfies requirements, passes local test runners/linters, and preserves architectural invariants, proceed decisively to create and submit the Pull Request with a clear, structured summary and rationale.
- **Explicit Recommendations on Options**: When presenting multiple implementation strategies or architecture options (e.g., Option A vs. Option B), NEVER leave the choice open-ended or passive. Always make an explicit, reasoned recommendation (prefixed with `(Recommended)`) based on **overall technical effectiveness**:
  1. *Algorithmic & Complexity Gains*: Time and space complexity impact (O(N*M) -> O(N+M), reduction of nested scans).
  2. *Resource Overhead*: Heap allocations, memory pressure, and GC pause reduction.
  3. *Domain & Architecture Invariants*: Strict backward compatibility, contract stability, and prevention of regression risks.
  4. *Security & Reliability*: Input validation, cryptographic safety, and concurrency safety.
- **Lead with Recommended Path**: State clearly why the recommended solution delivers the highest net value and immediately execute or propose it as the primary course of action rather than asking open-ended questions.

## Scope Verification, Minimal Churn & CI Protection Directives
- **Scope Verification Before Variable Binding**: When adding interactive states or accessibility attributes (e.g. `disabled={loading}`, `aria-busy={loading}`, `isSubmitting`), NEVER assume a variable identifier exists. Always inspect component props, local state hooks (`useState`), or declaration scope first. If not defined, declare the state hook or reuse an existing scope variable. Never introduce TS2304 / TS2552 ("Cannot find name") compile errors.
- **Surgical Edits Only (No Whole-File Formatting)**: Never run whole-file code formatters (Prettier, Black, Pint, rustfmt) across unmodified lines. Changes must be strictly range-scoped and limited to the minimal AST block needed. Avoid noisy quote/whitespace churn that masks real logic changes and causes merge conflicts. Verify with `git diff -w` that non-functional churn is zero.
- **Zero Scratch File Commits**: Never stage or commit ad-hoc verification, patch, or debug scripts (`test.cjs`, `fix_*.cjs`, `fix_*.php`, `patch_*.py`, `patch_*.sh`, `scratch_*`). Execute checks via the project's native test commands (`npm test`, `pytest`, `phpunit`, etc.) and delete temporary scripts before creating git commits.
- **Never Weaken CI Workflows**: Do not modify `.github/workflows/**` to bypass failures (e.g. adding `|| true`, setting `continue-on-error: true`, or commenting out assertions). Always resolve the defect in the source code or test fixture.
- **Explicit Parameter & Variable Types**: In TypeScript files, avoid implicit `any` by always providing explicit types on functions, parameters, and arrow callbacks (e.g. `(id: string) => ...`). Verify zero type errors with `tsc --noEmit` before committing.

## 2026-09-29 - Non-Destructive Security Patching & CI Protection
**Learning:** Security patches must never weaken CI workflow files (`.github/workflows/**`) by appending `|| true` or `continue-on-error: true` to suppress test/build failures. Furthermore, when adding defensive type assertions or input validators in TypeScript, omitting explicit types can introduce `TS7006: Parameter implicitly has an 'any' type`.
**Action:** Never modify CI workflow definitions to bypass test failures; resolve the underlying issue in source code or test fixtures. Always provide explicit types on newly introduced parameters and helper functions. Ensure zero scratch scripts (`fix_*.php`, `test_*.js`) are committed.

## 2024-10-25 - Rate Limiter Memory Exhaustion DoS
**Vulnerability:** The basic IP-based rate limiter added to `/auth/token` stored IP attempts indefinitely without a capacity limit. An attacker could spoof thousands of IP addresses to bypass standard restrictions and fill the `LOGIN_ATTEMPTS` dictionary, causing Memory Exhaustion DoS (Denial of Service).
**Learning:** In-memory stores used for security tracking (like rate limiters) must always be bounded in capacity. Without a hard cap, an attacker can exhaust server memory.
**Prevention:** Always implement a cap on dictionary sizes for IP tracking. When exceeding limits (e.g. 10000), gracefully clear the dictionary or implement an LRU cache to prevent unbounded growth.
