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
