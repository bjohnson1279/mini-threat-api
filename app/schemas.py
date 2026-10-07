from datetime import datetime
import ipaddress
import re
from typing import Optional, Literal
from pydantic import BaseModel, Field, ConfigDict, model_validator

# Indicator Types and Severities
IndicatorTypeEnum = Literal["ipv4", "domain", "sha256", "url", "email"]
SeverityEnum = Literal["low", "medium", "high", "critical"]

# ⚡ Bolt Optimization: Pre-compile regular expressions
# Compiling these at the module level prevents Python from having to re-compile
# (or re-fetch from the internal cache) these patterns on every single request.
# This significantly speeds up Pydantic request validation during high-throughput ingestion.
SHA256_REGEX = re.compile(r"^[A-Fa-f0-9]{64}\Z")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\Z")
DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\Z")

class IOCBase(BaseModel):
    """Base Pydantic schema with shared threat indicator attributes."""
    indicator_value: str = Field(..., max_length=255, json_schema_extra={"example": "198.51.100.24"}, description="The observable IP, domain, or hash")
    indicator_type: IndicatorTypeEnum = Field(..., json_schema_extra={"example": "ipv4"}, description="Classification of the IOC")
    threat_type: str = Field(..., max_length=100, json_schema_extra={"example": "ransomware_c2"}, description="Category of malicious activity")
    confidence_score: int = Field(default=50, ge=0, le=100, json_schema_extra={"example": 85}, description="Confidence score from 0 to 100")
    severity: SeverityEnum = Field(default="medium", json_schema_extra={"example": "high"}, description="Assessed severity level")
    description: Optional[str] = Field(None, max_length=500, json_schema_extra={"example": "Associated with BlackCat ransomware campaign"})
    is_active: bool = Field(default=True, description="Whether indicator is currently active")

class IOCCreate(IOCBase):
    """Schema for creating a new IOC (Request Body)."""

    # ⚡ Bolt Optimization: Moved validation from IOCBase to IOCCreate
    # Moving this expensive `@model_validator` out of `IOCBase` ensures that we don't
    # re-validate data coming OUT of the database during serialization (in `IOCResponse`),
    # which is already trusted. This significantly reduces response overhead for endpoints like `GET /iocs`.
    @model_validator(mode='after')
    def validate_indicator_value(self):
        # 🛡️ Sentinel Security Fix: Implement strict input validation on indicator_value
        # depending on indicator_type to prevent malformed data injection.
        if self.indicator_type == "ipv4":
            try:
                ipaddress.IPv4Address(self.indicator_value)
            except ValueError:
                raise ValueError("Invalid IPv4 address format")
        elif self.indicator_type == "sha256":
            if not SHA256_REGEX.match(self.indicator_value):
                raise ValueError("Invalid SHA256 hash format")
        elif self.indicator_type == "url":
            if not self.indicator_value.startswith(("http://", "https://")):
                raise ValueError("Invalid URL format (must start with http/https)")
        elif self.indicator_type == "email":
            if not EMAIL_REGEX.match(self.indicator_value):
                raise ValueError("Invalid email format")
        elif self.indicator_type == "domain":
            if not DOMAIN_REGEX.match(self.indicator_value):
                raise ValueError("Invalid domain format")
        return self

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
