from contextlib import asynccontextmanager
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Query, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

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

# ---------------------------------------------------------------------------
# Unauthenticated Routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["System"])
def health_check():
    """Health check endpoint to verify service and container liveness."""
    return {"status": "healthy", "service": "threat-intel-api"}

@app.post("/auth/token", response_model=Token, tags=["Authentication"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 compatible token login endpoint.
    Accepts standard form-urlencoded credentials (username & password).
    Demo credentials:
      - username: 'analyst', password: 'password123'
      - username: 'admin', password: 'adminpassword123'
    """
    user_dict = MOCK_USERS_DB.get(form_data.username)
    if not user_dict or user_dict["password"] != form_data.password:
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
    indicator = db.query(Indicator).filter(Indicator.id == ioc_id).first()
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
def read_current_user_profile(current_user: User = Depends(get_current_user)):
    """Returns the authenticated user identity and claims decoded from the JWT."""
    return current_user
