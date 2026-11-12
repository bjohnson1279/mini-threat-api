"""
Authentication and authorization module for Mini Threat-Intel API.
Handles JWT creation, cryptographic token verification, user dependency injection,
and role-based access control (RBAC) guard factories.
"""

from datetime import datetime, timedelta, timezone
import uuid
import time
from typing import Optional
from functools import lru_cache
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import logging
from jose import JWTError, jwt
from app.config import settings
from app.schemas import TokenData, User

logger = logging.getLogger("audit")

# OAuth2 scheme requiring Bearer token in the 'Authorization' header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# Mock user database for authentication demo
MOCK_USERS_DB = {
    "analyst": {
        "username": "analyst",
        # bcrypt hash of 'password123'
        "password": "$2b$12$v1B3NFjxLnulAxo8hmmE8.wX7DP7pExSaVPCDr74ERGYQm3lkjqc6",
        "role": "threat_analyst",
        "disabled": False
    },
    "admin": {
        "username": "admin",
        # bcrypt hash of 'adminpassword123'
        "password": "$2b$12$Sat01mrSqG5qVzQZpjfhtOlQ90fZ8EqxNbVdW4z4V3vxHnX1SOdVu",
        "role": "admin",
        "disabled": False
    },
    "guest": {
        "username": "guest",
        # bcrypt hash of 'password123'
        "password": "$2b$12$v1B3NFjxLnulAxo8hmmE8.wX7DP7pExSaVPCDr74ERGYQm3lkjqc6",
        "role": "guest",
        "disabled": False
    }
}

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Encodes a signed JWT with expiration timestamp and custom claims."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))

    # Include standard JWT claims (iat, nbf, jti) for security tracking
    to_encode.update({
        "exp": expire,
        "iat": now,
        "nbf": now,
        "jti": str(uuid.uuid4())
    })
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

# ⚡ Bolt Optimization: Cache JWT verification to avoid redundant expensive crypto operations
# on every request. We disable internal expiration verification (verify_exp=False) so we can
# cache the decoded payload and manually enforce expiration against current time.
@lru_cache(maxsize=1024)
def _decode_jwt_cached(token: str, secret_key: str, algorithm: str) -> dict:
    return jwt.decode(
        token,
        secret_key,
        algorithms=[algorithm],
        options={"require_exp": True, "require_sub": True, "verify_exp": False}
    )

def decode_access_token(token: str) -> TokenData:
    """Decodes and verifies a JWT token's signature and expiration."""
    try:
        # Require 'exp' and 'sub' claims to prevent perpetual non-expiring tokens
        payload = _decode_jwt_cached(
            token,
            settings.JWT_SECRET_KEY,
            settings.JWT_ALGORITHM
        )

        # ⚡ Bolt Optimization: Manually enforce expiration to prevent caching expired token states
        exp = payload.get("exp")
        now = time.time()
        if exp is not None and now > exp:
            raise JWTError("Token expired")

        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload: missing subject (sub)",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return TokenData(username=username, role=role)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials or token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    Custom Authorizer / Dependency Injection.
    
    Analogy:
    - Express.js: Passport / custom JWT middleware attaching `req.user = decoded`
    - NestJS: @UseGuards(AuthGuard('jwt'))
    - FastAPI: `Depends(get_current_user)` injects the validated User directly into route arguments!
    """
    token_data = decode_access_token(token)
    user_dict = MOCK_USERS_DB.get(token_data.username)
    if user_dict is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user_dict.get("disabled", False):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return User(**user_dict)

def require_role(required_role: str):
    """Role-based access control (RBAC) dependency factory."""
    # Non-blocking async dependency runs on event loop avoiding threadpool overhead
    async def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role != required_role and current_user.role != "admin":
            # Sanitize username against CRLF injection and emit RBAC audit log
            safe_username = current_user.username.replace('\n', '\\n').replace('\r', '\\r')
            logger.warning(f"Audit: Unauthorized access attempt by user '{safe_username}' (role: {current_user.role}) requiring role '{required_role}'")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Requires '{required_role}' role.",
            )
        return current_user
    return role_checker
