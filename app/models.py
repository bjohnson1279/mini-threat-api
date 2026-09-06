from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Index
from app.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class Indicator(Base):
    """
    SQLAlchemy ORM Model representing an Indicator of Compromise (IOC).
    
    Analogy:
    - Laravel/Eloquent: class Indicator extends Model
    - Prisma: model Indicator { id Int @id @default(autoincrement()) ... }
    """
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    indicator_value = Column(String(255), nullable=False, index=True)  # e.g. IP, domain, hash
    indicator_type = Column(String(50), nullable=False, index=True)    # ipv4, domain, sha256, url
    threat_type = Column(String(100), nullable=False)                  # c2_server, phishing, ransomware
    confidence_score = Column(Integer, nullable=False, default=50)      # 0 to 100
    severity = Column(String(20), nullable=False, default="medium")    # low, medium, high, critical
    description = Column(String(500), nullable=True)
    first_seen = Column(DateTime(timezone=True), default=utc_now)
    last_seen = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    is_active = Column(Boolean, default=True, index=True)

    __table_args__ = (
        Index("ix_indicators_type_confidence", "indicator_type", "confidence_score"),
        # ⚡ Bolt Optimization:
        # Added dedicated index on confidence_score to speed up /iocs queries
        # when 'indicator_type' filter is not provided. The previous composite index
        # couldn't be used effectively without the leftmost prefix.
        # This reduces query time significantly for those queries.
        Index("ix_indicators_confidence_score", "confidence_score"),
    )
