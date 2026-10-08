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

## 2024-10-24 - Memory Exhaustion DoS in Rate Limiting
**Vulnerability:** The `/auth/token` endpoint's rate limiting implementation stored login attempts in a global dictionary (`LOGIN_ATTEMPTS`) but lacked a safe cleanup mechanism or a maximum capacity limit. Under a massive burst of requests from unique IP addresses, this unbounded growth could lead to memory exhaustion and a Denial of Service.
**Learning:** In-memory tracking structures, such as rate limiting dictionaries, must be constrained by capacity and periodically cleaned up. Iterating over the entire structure on every request (O(N) operation) would cause CPU exhaustion under load.
**Prevention:** Implement throttled cleanup routines (e.g., executing O(N) cleanups periodically rather than on every request) to safely remove expired entries using `.pop()`. Ensure tracking objects have an enforced global size limit, returning a `429 Too Many Requests` error immediately if the limit is exceeded by new requests during massive bursts.
## 2024-10-24 - Malformed Data Injection via Missing Pydantic Model Validation
**Vulnerability:** The `IOCBase` Pydantic schema accepted string values for `indicator_value` without validating them against the specified `indicator_type`. This meant an attacker or buggy client could submit malformed data (e.g., `indicator_type: "ipv4"`, `indicator_value: "Not an IP address"`), leading to data corruption and potential crashes or exploitation in downstream security systems that expect strictly formatted IP addresses or hashes.
**Learning:** Pydantic's basic type checking (e.g., validating a string is a string) is insufficient for security-critical polymorphic data structures where the format of one field depends on the value of another field.
**Prevention:** Always implement a `@model_validator` in Pydantic schemas handling polymorphic data to enforce strict cross-field validation, ensuring that string values correctly match the strict formats (like IP addresses, hashes, URLs) dictated by their associated type declarations before they hit the database.

## 2024-10-24 - Thread-Safety Crash in Concurrent Iteration
**Vulnerability:** The `/auth/token` endpoint's rate limiting cleanup loop iterated over dictionary keys (`for ip in list(LOGIN_ATTEMPTS.keys()):`) while operating in a concurrent threadpool (`def` endpoint). If another concurrent request modified the `LOGIN_ATTEMPTS` dictionary size (e.g., added a new IP) at the exact moment the iterator was processing, Python threw an unhandled `RuntimeError: dictionary changed size during iteration`. This would crash the request and, under high load, could lead to a Denial of Service.
**Learning:** In highly concurrent environments like FastAPI's synchronous threadpool, iterating over shared global dictionaries is not thread-safe. Standard dictionary iterations or list comprehensions over keys can crash if the underlying dictionary size mutates concurrently.
**Prevention:** Always wrap loops that iterate over dynamically changing, globally shared dictionaries in a `try...except RuntimeError` block to safely catch and ignore the size change exception, ensuring the request completes successfully and allowing subsequent cleanup cycles to handle any missed entries.

## 2024-10-24 - Race Condition and Data Corruption in Threaded Dictionary Cleanup
**Vulnerability:** The `/auth/token` endpoint's rate limiting implementation operated on a globally shared dictionary (`LOGIN_ATTEMPTS`) from within a synchronous threadpool (`def` endpoint) without any synchronization primitives. When multiple concurrent requests attempted to read, iterate, and mutate (e.g., via `.pop()` or assignment) the dictionary simultaneously, it resulted in race conditions. In addition to potential `RuntimeError: dictionary changed size during iteration` crashes, this lack of thread-safety meant that valid login attempts could be overwritten or improperly deleted by interleaving threads, leading to inconsistent rate-limiting enforcement.
**Learning:** In a multi-threaded environment (such as FastAPI's synchronous threadpool for `def` functions), any operations that read and mutate globally shared state (like Python dictionaries) must be strictly synchronized. Standard Python dictionary operations are not inherently thread-safe against complex read-modify-write cycles or concurrent iteration/mutation.
**Prevention:** Always use explicit synchronization primitives, such as `threading.Lock`, when accessing and modifying shared mutable state in a threaded context. Ensure the lock is acquired (e.g., using `with lock:`) around the critical sections where the state is iterated over, read, or modified to maintain data consistency and prevent race conditions or crashes.

## 2024-10-24 - Python Regex Newline Injection Vulnerability
**Vulnerability:** The SHA256 validation regex in `app/schemas.py` used the `$` anchor (`r"^[A-Fa-f0-9]{64}$"`). In Python's `re.match`, the `$` anchor allows an optional trailing newline (`\n`) at the end of the string. This could be exploited for data corruption or injection attacks in downstream systems.
**Learning:** Python's `re` module behavior for the `$` anchor differs from strictly asserting the absolute end of the string. It permits a trailing newline, which is a common pitfall when validating strict data formats.
**Prevention:** When writing security-focused regular expressions in Python (e.g., for Pydantic input validation) that must enforce absolute string boundaries, always use `\Z` instead of `$` to prevent trailing newline injections.
## 2024-10-24 - JWT Permanent Token Forgery
**Vulnerability:** The `/auth/token` endpoint's token decoding via `python-jose`'s `jwt.decode()` did not enforce the presence of required claims like `exp` (expiration) and `sub` (subject). An attacker could forge a token omitting these claims, leading to permanent token forgery.
**Learning:** `python-jose` does not strictly enforce the presence of claims by default during decoding.
**Prevention:** Always explicitly pass `options={"require_exp": True, "require_sub": True}` to `jwt.decode()` to prevent missing claim vulnerabilities.
