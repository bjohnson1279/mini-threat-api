## 2024-03-24 - SQLAlchemy Index Creation on Existing Tables
**Learning:** `Base.metadata.create_all()` in SQLAlchemy does not add missing indices to tables that already exist. If Alembic (or another migration tool) is not in use, you must use raw SQL (like `CREATE INDEX IF NOT EXISTS`) in the app lifecycle/startup to ensure the index is deployed to existing databases.
**Action:** Next time adding an index to an ORM model without a migration system, ensure there is a mechanism to apply that index to existing tables, such as running raw SQL during the application's lifespan setup.

## 2024-03-24 - FastAPI Threadpool Overhead for Non-blocking Endpoints
**Learning:** In FastAPI, endpoints declared with standard `def` instead of `async def` are run in an external threadpool to prevent blocking the async event loop. For non-blocking endpoints that do not perform synchronous I/O operations (like `health_check` or endpoints simply returning a JWT token payload from dependencies), running them in a threadpool adds significant context-switching overhead. My benchmarks showed that switching these non-blocking endpoints to `async def` nearly halved the response time for these routes by avoiding the threadpool completely.
**However, this optimization must NEVER be applied to endpoints performing CPU-bound operations (like password hashing in login endpoints).** Making a CPU-bound endpoint `async def` will run the expensive operation directly on the main event loop, blocking it entirely and causing a massive performance degradation and potential DoS vulnerability for all other users.
**Action:** Always check if a FastAPI endpoint actually performs blocking I/O (like a synchronous `db.query()`) or CPU-bound tasks (like password hashing). If it's purely CPU-bound or blocking I/O, keep it as `def`. If it purely returns data from memory/dependencies, declare it as `async def` to maximize throughput.

## 2026-09-07 - FastAPI Async vs Sync Endpoints
**Learning:** In FastAPI, endpoints defined with standard `def` are run in an external threadpool (via `anyio`) to prevent blocking the main event loop. For non-blocking endpoints, this introduces unnecessary thread context-switching overhead.
**Action:** Declare endpoints that perform no blocking I/O (like simple health checks or those returning decoded JWT claims) as `async def` so they run directly on the event loop. Keep endpoints with blocking I/O (like synchronous SQLAlchemy calls) as synchronous `def` to avoid freezing the event loop.

## 2026-09-09 - Optimize SQLAlchemy Existence Checks
**Learning:** For SQLAlchemy/PostgreSQL database operations, using `db.query(Model).count() == 0` for simple existence checks causes an inefficient O(N) scan across the table.
**Action:** Prefer `db.query(Model.id).first() is not None` (or `is None`) for an O(1) existence check, especially in application startup or seeding loops, to dramatically improve performance on large tables.

## 2026-10-25 - Optimize SQLAlchemy Primary Key Lookups
**Learning:** For SQLAlchemy primary key lookups, using `db.query(Model).filter(Model.id == id).first()` adds overhead because it must compile a filter expression. Furthermore, it will always execute a query against the database.
**Action:** Always prefer `db.get(Model, id)` for primary key lookups. It avoids compiling the filter expression and can return instantly from the Session's Identity Map without a database roundtrip if the object was already loaded.

## 2024-05-15 - FastAPI GZipMiddleware Optimization
**Learning:** For endpoints returning large, repetitive JSON payloads like Threat Intel IOC lists, the uncompressed data can become a network bottleneck.
**Action:** Apply `GZipMiddleware` to compress API responses. This significantly reduces network bandwidth and transit time for clients parsing large datasets. Because the FastAPI `TestClient` (via `httpx`) natively handles gzip, this optimization can often be added safely without breaking existing client expectations.

## 2024-05-24 - Avoid Threadpool Overhead in FastAPI Dependencies
**Learning:** Synchronous dependency functions (`def`) in FastAPI are executed in a threadpool to prevent blocking the event loop. This causes unnecessary context switching and thread contention for simple, non-blocking operations like string comparisons (e.g., in `role_checker`).
**Action:** Always use `async def` for non-blocking dependency functions to run them directly in the event loop, avoiding threadpool overhead and improving performance.

## 2024-06-25 - Skip Redundant SQLAlchemy Filters for Default Values
**Learning:** Adding filters like `Indicator.confidence_score >= min_confidence` where `min_confidence` defaults to `0` (and the column is strictly `>= 0`) forces the database to evaluate an unnecessary condition (`WHERE confidence_score >= 0`). This can add a slight overhead when processing default queries without user-provided filters.
**Action:** When a filter is functionally a no-op due to boundary conditions and default parameter values, conditionally omit it from the SQLAlchemy query builder (`if min_confidence > 0: query = query.filter(...)`) to ensure the generated SQL remains as optimal as possible for the default/unfiltered path.

## 2026-10-31 - Redundant Primary Key Indexes in SQLAlchemy
**Learning:** `primary_key=True` on a SQLAlchemy Column automatically ensures a unique index is created at the database level (in Postgres, SQLite, MySQL, etc). Explicitly adding `index=True` on the same primary key column creates a second, completely redundant B-tree index. This forces the database to maintain two identical indexes for the same column, wasting storage and unnecessarily degrading the performance of `INSERT`, `UPDATE`, and `DELETE` operations.
**Action:** Never use `index=True` on a column that is already marked as `primary_key=True`. Remove redundant explicit indexes on primary keys to improve write performance and reduce database size.

## 2024-08-16 - Redundant Indexes on Low-Cardinality and Composite Prefix Columns
**Learning:** Adding `index=True` to low-cardinality boolean columns (like `is_active`) or columns that already serve as the leftmost prefix of a composite index (like `indicator_type` in `ix_indicators_type_confidence`) creates redundant, standalone indexes. These indexes waste database storage and unnecessarily degrade write (INSERT/UPDATE/DELETE) performance without providing any query performance benefit.
**Action:** Never add `index=True` to columns that have low cardinality (e.g. boolean fields that aren't exclusively queried) or columns that are already the leftmost prefix of a composite index. Always remove these redundant indexes to optimize write operations and save storage.

## 2024-11-20 - Full Pagination for Large Data Sets
**Learning:** Returning large datasets without full pagination (using both `limit` and `offset`) can lead to memory exhaustion on the server, excessive data transfer bandwidth, and slow response times.
**Action:** When designing endpoints that return lists or large datasets, always implement full pagination by providing both `limit` and `offset` query parameters. This prevents the entire dataset from being loaded into memory and ensures scalable performance.

## Prevention Directives for Automated Refactoring
- **Never Overwrite Complete Files**: Always use range-scoped replacement chunks (`StartLine`/`EndLine`) for edits to `schema.prisma`, `index.ts`, `public/index.php`, or DDL SQL scripts.
- **Do Not Remove Core Declarations**: Do not delete existing route registrations or database DDL tables.
- **Environment Isolation Compatibility**: When replacing fallback secrets, preserve test environment execution via `!getenv('APP_ENV')` or `getenv('APP_ENV') === 'testing'`.
- **No Scratch Files**: Never stage or commit `test_*.ts`, `test_*.js`, `test.cjs`, `fix_*.php`, or `test.js` files to git.
- **No Unresolved Conflict Markers**: Never stage or commit files containing Git merge conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`, `|||||||`). Always resolve conflicts cleanly before committing.
- **Never Overwrite Complete Files**: Always use range-scoped replacement chunks for edits to `schema.prisma`, `index.ts`, `public/index.php`, `db/schema.rb`, or DDL SQL scripts.

## Hallucinatory Task & Empty PR Directives
- **Zero-Diff Task Termination**: If the requested optimization, refactor, or fix is ALREADY natively present in the target branch, DO NOT create an empty pull request or commit an acknowledgment PR. Exit the task cleanly without opening a PR.
- **Stale Suggestion Guard**: Always verify the current code on `main`/`master` before planning changes. If no actionable diff is required, cancel task execution immediately.
- **No Journal-Only PRs**: Never open a pull request that only contains updates to .jules/*.md files without corresponding functional code changes and tests.

## Completeness & Verification Directives
- **Explicit Parameter & Contract Validation**: When creating or modifying API endpoints (Express, Fastify, Rails, Laravel), always implement explicit parameter and request body validation schemas (e.g. `z.string().uuid()`) to prevent unhandled 404/500 fallthroughs.
- **Database Indexing for Queries**: When addressing query bottlenecks or adding query lookup filters, always implement native database index migrations rather than loading collections into memory and performing array filtering (`.filter()`, `.select`).
- **Co-Occurring Dependency Auditing**: When bumping any dependency version, verify that other transitive dependencies do not carry high/critical security advisories (e.g. run `bundler-audit`, `npm audit`). Never introduce a version bump that breaks underlying framework APIs.
- **Self-Verification Before Commit**: Always run syntax checks (`bash -n` for shell scripts, `tsc --noEmit` for TypeScript, linter checks) and targeted test runners locally before opening or updating a PR.

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

## 2026-09-29 - Surgical Optimization Edits and No Scratch Script Commits
**Learning:** Running whole-file formatters or regenerating entire components while performing performance optimizations introduces massive whitespace/formatting diffs (1,000+ lines), masking the real optimization, invalidating git blame, and causing painful merge conflicts with concurrent PRs. Additionally, committing scratch benchmark or patch scripts (`patch_*.py`, `test.cjs`) pollutes production repositories and triggers CI guardrail failures.
**Action:** Restrict all algorithmic and performance optimizations to strictly scoped replacement chunks. Diff size must reflect only the functional optimization. Always clean up temporary benchmark or patch scripts with `git rm -f` before committing.

## 2024-03-24 - Prevent Memory Exhaustion in Rate Limiters
**Learning:** In-memory trackers (like `LOGIN_ATTEMPTS`) grow unbounded if expired entries are never removed, leading to a Memory Exhaustion DoS vulnerability.
**Action:** Always implement a cleanup mechanism (e.g., periodically removing expired entries when the dictionary size exceeds a threshold) to ensure bounded memory usage in in-memory tracking structures.
