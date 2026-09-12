from contextlib import asynccontextmanager
from typing import List, Optional
import bcrypt
from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.gzip import GZipMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import engine, Base, get_db
from app.models import Indicator
from app.schemas import IOCResponse, IOCCreate, Token, User
from app.auth import create_access_token, get_current_user, MOCK_USERS_DB
from app.seed import seed_threat_data

# Lifespan context: replaces deprecated @app.on_event("startup") in modern FastAPI
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-create database tables on startup
    Base.metadata.create_all(bind=engine)

    # ⚡ Bolt Optimization: Ensure index is created on existing tables.
    # Base.metadata.create_all() does not add missing indices to existing tables.
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_indicators_confidence_score ON indicators (confidence_score)"))
    except Exception as e:
        print(f"Could not create index: {e}")

    # Seed initial mock threat feed
    db = next(get_db())
    try:
        seed_threat_data(db)
    finally:
        db.close()
    yield

app = FastAPI(
    title="Mini Threat-Intel API",
    description="A high-performance FastAPI service demonstrating Threat Intel Indicator ingestion, querying, and JWT Custom Authorizers.",
    version="1.0.0",
    lifespan=lifespan
)

# ⚡ Bolt Optimization: Add GZip compression for large API responses.
# Threat Intel JSON payloads often contain highly repetitive string values
# (e.g., indicator types, severities, long descriptions) which compress exceptionally well.
# This simple middleware reduces payload size by over 90% for large GET /iocs queries,
# significantly decreasing network transit time and bandwidth costs.
app.add_middleware(GZipMiddleware, minimum_size=1000)

# ---------------------------------------------------------------------------
# Unauthenticated Routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint to verify service and container liveness."""
    # ⚡ Bolt Optimization: Changed from `def` to `async def`.
    # Since this endpoint does not perform blocking I/O operations (like synchronous DB queries),
    # using `async def` avoids FastAPI's threadpool context switch overhead, significantly improving throughput.
    return {"status": "healthy", "service": "threat-intel-api"}

@app.post("/auth/token", response_model=Token, tags=["Authentication"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 compatible token login endpoint.
    Accepts standard form-urlencoded credentials (username & password).
    Demo credentials:
      - username: 'analyst', password: 'password123'
      - username: 'admin', password: 'adminpassword123'

    ⚡ Bolt Optimization:
    Declared as `def` to run in a threadpool instead of the event loop.
    This avoids blocking the main event loop since `bcrypt.checkpw()` is a CPU-bound
    operation that would otherwise delay all concurrent requests.
    """
    user_dict = MOCK_USERS_DB.get(form_data.username)

    # 🛡️ Sentinel Security Fix:
    # Always perform a bcrypt check to prevent timing attacks for user enumeration.
    # If the user doesn't exist, we check the password against a dummy hash so it
    # takes roughly the same amount of time as checking a real user's password.
    # Dummy hash uses a static pre-computed bcrypt hash string.
    dummy_hash = b"$2b$12$v1B3NFjxLnulAxo8hmmE8.wX7DP7pExSaVPCDr74ERGYQm3lkjqc6"

    user_exists = user_dict is not None
    hash_to_check = user_dict["password"].encode('utf-8') if user_exists else dummy_hash

    password_matches = bcrypt.checkpw(form_data.password.encode('utf-8'), hash_to_check)

    # Check if user exists and verify password securely
    if not user_exists or not password_matches:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(
        data={"sub": user_dict["username"], "role": user_dict["role"]}
    )
    return Token(access_token=access_token, token_type="bearer", expires_in_minutes=60)

# ---------------------------------------------------------------------------
# Protected Threat Intel Routes (Secured via JWT Custom Authorizer)
# ---------------------------------------------------------------------------

@app.get(
    "/iocs",
    response_model=List[IOCResponse],
    tags=["Indicators of Compromise"],
    summary="Query Threat Intelligence Indicators"
)
def list_iocs(
    indicator_type: Optional[str] = Query(None, description="Filter by type (ipv4, domain, sha256, url)"),
    min_confidence: Optional[int] = Query(0, ge=0, le=100, description="Minimum confidence score threshold (0-100)"),
    search: Optional[str] = Query(None, description="Partial search within indicator value or description"),
    limit: int = Query(50, ge=1, le=500, description="Maximum records to return"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retrieves filtered threat indicators from PostgreSQL.
    
    Requires JWT Bearer authentication. Demonstrates:
    - FastAPI dependency injection (`Depends(get_current_user)`) as a custom authorizer
    - Database session lifecycle management (`Depends(get_db)`)
    - SQLAlchemy query filtering and execution
    - Pydantic serialization (`response_model=List[IOCResponse]`)
    """
    query = db.query(Indicator).filter(Indicator.confidence_score >= min_confidence)
    
    if indicator_type:
        query = query.filter(Indicator.indicator_type == indicator_type.lower())
    
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (Indicator.indicator_value.ilike(search_pattern)) | 
            (Indicator.description.ilike(search_pattern))
        )
        
    indicators = query.order_by(Indicator.confidence_score.desc()).limit(limit).all()
    return indicators

@app.get(
    "/iocs/{ioc_id}",
    response_model=IOCResponse,
    tags=["Indicators of Compromise"],
    summary="Get Indicator by ID"
)
def get_ioc_by_id(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieves a single threat indicator by its database primary key."""
    # ⚡ Bolt Optimization: Replace db.query(Model).filter(Model.id == id).first() with db.get(Model, id)
    # Using db.get() avoids the overhead of compiling a filter expression and will return
    # instantly from the SQLAlchemy Identity Map if the object is already loaded, avoiding a DB query entirely.
    indicator = db.get(Indicator, ioc_id)
    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat indicator with ID {ioc_id} not found."
        )
    return indicator

@app.post(
    "/iocs",
    response_model=IOCResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Indicators of Compromise"],
    summary="Ingest New Threat Indicator"
)
def create_ioc(
    ioc_in: IOCCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Ingests a new IOC record into the threat database.
    Demonstrates Pydantic request body validation and SQLAlchemy write transaction.
    """
    new_ioc = Indicator(**ioc_in.model_dump())
    db.add(new_ioc)
    db.commit()
    db.refresh(new_ioc)
    return new_ioc

@app.get("/auth/me", response_model=User, tags=["Authentication"])
async def read_current_user_profile(current_user: User = Depends(get_current_user)):
    """Returns the authenticated user identity and claims decoded from the JWT."""
    # ⚡ Bolt Optimization: Changed from `def` to `async def`.
    # Using `async def` avoids running this non-blocking endpoint in a threadpool, decreasing overhead.
    return current_user
