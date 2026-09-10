## 2024-05-18 - Hardcoded JWT Secret Fallback Removed
**Vulnerability:** A hardcoded `JWT_SECRET_KEY` fallback was present in `app/config.py` which allowed attackers reading the codebase to forge access tokens if the env variable wasn't set.
**Learning:** Initial attempt to replace the fallback with a dynamically generated string (`secrets.token_urlsafe(32)`) led to bugs in multi-worker environments since each worker generated a different secret at module load.
**Prevention:** Remove the default value entirely for sensitive keys in Pydantic models. This ensures the app fails securely (crashing on startup) instead of falling back to insecure or inconsistent behavior.
