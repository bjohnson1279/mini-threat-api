import os
import pytest

# 🛡️ Sentinel / Env Fallback Harmonizer: Provide test defaults for Pydantic Settings
os.environ.setdefault("JWT_SECRET_KEY", "mock_local_test_jwt_secret_key_1234567890abcdef")
os.environ.setdefault("DATABASE_URL", "sqlite:///./threat_intel_test.db")
os.environ.setdefault("JWT_ALGORITHM", "HS256")
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "60")
