## 2024-05-24 - Strict Secret Configuration Enforcement
**Vulnerability:** A hardcoded default `JWT_SECRET_KEY` in `app/config.py` allowed the app to start with an insecure, known secret if the environment variable was missing.
**Learning:** Using dynamic defaults (like `secrets.token_urlsafe()`) in Pydantic `BaseSettings` breaks multi-worker deployments by generating a unique secret per worker.
**Prevention:** Strictly omit defaults for module-level secrets in `BaseSettings` so the application predictably fails if the environment variable is not provided, ensuring security configurations are explicit.
