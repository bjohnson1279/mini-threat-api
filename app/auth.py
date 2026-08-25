from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from app.config import settings
from app.schemas import TokenData, User

# OAuth2PasswordBearer tells FastAPI that the client should send the token
# in the 'Authorization: Bearer <token>' header, and documents this in Swagger UI.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# Mock user database for the interview demo
MOCK_USERS_DB = {
    "analyst": {
        "username": "analyst",
        "password": "password123",  # For demo purposes
        "role": "threat_analyst",
        "disabled": False
    },
    "admin": {
        "username": "admin",
        "password": "adminpassword123",
        "role": "admin",
        "disabled": False
    }
}

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Encodes a signed JWT with expiration timestamp and custom claims."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> TokenData:
    """Decodes and verifies a JWT token's signature and expiration."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
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
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role != required_role and current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Requires '{required_role}' role.",
            )
        return current_user
    return role_checker
