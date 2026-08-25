from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, Field, ConfigDict

# Indicator Types and Severities
IndicatorTypeEnum = Literal["ipv4", "domain", "sha256", "url", "email"]
SeverityEnum = Literal["low", "medium", "high", "critical"]

class IOCBase(BaseModel):
    """Base Pydantic schema with shared threat indicator attributes."""
    indicator_value: str = Field(..., json_schema_extra={"example": "198.51.100.24"}, description="The observable IP, domain, or hash")
    indicator_type: IndicatorTypeEnum = Field(..., json_schema_extra={"example": "ipv4"}, description="Classification of the IOC")
    threat_type: str = Field(..., json_schema_extra={"example": "ransomware_c2"}, description="Category of malicious activity")
    confidence_score: int = Field(default=50, ge=0, le=100, json_schema_extra={"example": 85}, description="Confidence score from 0 to 100")
    severity: SeverityEnum = Field(default="medium", json_schema_extra={"example": "high"}, description="Assessed severity level")
    description: Optional[str] = Field(None, json_schema_extra={"example": "Associated with BlackCat ransomware campaign"})
    is_active: bool = Field(default=True, description="Whether indicator is currently active")

class IOCCreate(IOCBase):
    """Schema for creating a new IOC (Request Body)."""
    pass

class IOCResponse(IOCBase):
    """
    Schema for serializing an IOC in API responses.
    model_config = ConfigDict(from_attributes=True) allows Pydantic to read directly
    from SQLAlchemy ORM models (previously orm_mode=True in Pydantic v1).
    """
    id: int
    first_seen: datetime
    last_seen: datetime

    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    """Schema for JWT access token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int

class TokenData(BaseModel):
    """Decoded JWT payload data."""
    username: Optional[str] = None
    role: Optional[str] = None

class User(BaseModel):
    """User schema representation."""
    username: str
    role: str
    disabled: bool = False
