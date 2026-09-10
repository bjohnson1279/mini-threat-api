## 2024-05-24 - Remove Hardcoded Secret
**Vulnerability:** A hardcoded `JWT_SECRET_KEY` was found in `app/config.py` as a fallback value for an environment variable.
**Learning:** Hardcoded secrets in application code can be easily exposed via version control and can break multi-worker deployments (e.g., Gunicorn/Uvicorn) if dynamic defaults like `secrets.token_urlsafe()` are used.
**Prevention:** Always omit default values for sensitive configuration options in Pydantic BaseSettings to enforce configuration via environment variables, ensuring secrets are managed securely and explicitly.
## 2023-10-27 - [Plaintext Passwords in Mock Database]
**Vulnerability:** Found plaintext passwords hardcoded in MOCK_USERS_DB dictionary (`app/auth.py`), verified using naive string comparison (`!=`) in `app/main.py`.
**Learning:** Hardcoded credentials are a critical security flaw. Additionally, the standard `passlib` is broken on modern python (3.12) with bcrypt>=4.0 due to unmaintained codebase calling non-existent `__about__`.
**Prevention:** Always use one-way hashing algorithms like bcrypt for passwords. Prefer using the raw `bcrypt` library directly over the broken `passlib` on Python 3.12+ environments.
