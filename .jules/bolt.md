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

## Prevention Directives for Automated Refactoring
- **Never Overwrite Complete Files**: Always use range-scoped replacement chunks (`StartLine`/`EndLine`) for edits to `schema.prisma`, `index.ts`, `public/index.php`, or DDL SQL scripts.
- **Do Not Remove Core Declarations**: Do not delete existing route registrations or database DDL tables.
- **Environment Isolation Compatibility**: When replacing fallback secrets, preserve test environment execution via `!getenv('APP_ENV')` or `getenv('APP_ENV') === 'testing'`.
- **No Scratch Files**: Never stage or commit `test_*.ts`, `test_*.js`, `test.cjs`, `fix_*.php`, or `test.js` files to git.
- **No Unresolved Conflict Markers**: Never stage or commit files containing Git merge conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`, `|||||||`). Always resolve conflicts cleanly before committing.

## Hallucinatory Task & Empty PR Directives
- **Zero-Diff Task Termination**: If the requested optimization, refactor, or fix is ALREADY natively present in the target branch, DO NOT create an empty pull request or commit an acknowledgment PR. Exit the task cleanly without opening a PR.
- **Stale Suggestion Guard**: Always verify the current code on `main`/`master` before planning changes. If no actionable diff is required, cancel task execution immediately.

## 2026-10-25 - Optimize SQLAlchemy Primary Key Lookups
**Learning:** For SQLAlchemy primary key lookups, using `db.query(Model).filter(Model.id == id).first()` adds overhead because it must compile a filter expression. Furthermore, it will always execute a query against the database.
**Action:** Always prefer `db.get(Model, id)` for primary key lookups. It avoids compiling the filter expression and can return instantly from the Session's Identity Map without a database roundtrip if the object was already loaded.

## 2024-05-15 - FastAPI GZipMiddleware Optimization
**Learning:** For endpoints returning large, repetitive JSON payloads like Threat Intel IOC lists, the uncompressed data can become a network bottleneck.
**Action:** Apply `GZipMiddleware` to compress API responses. This significantly reduces network bandwidth and transit time for clients parsing large datasets. Because the FastAPI `TestClient` (via `httpx`) natively handles gzip, this optimization can often be added safely without breaking existing client expectations.
