from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default="analyst")  # admin, analyst
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String(64), nullable=False)
    model_name = Column(String(128), nullable=True)
    prompt = Column(Text, nullable=False)
    response = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=False)
    severity = Column(String(32), nullable=False)
    findings = Column(JSON, nullable=False)
    extra_metadata = Column("metadata", JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    audits = relationship("AuditLog", back_populates="scan", cascade="all, delete-orphan")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(64), nullable=False)
    actor_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    scan_id = Column(Integer, ForeignKey("scan_logs.id"), nullable=True)
    details = Column(JSON, nullable=False)
    prev_hash = Column(String(128), nullable=True)
    event_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    scan = relationship("ScanLog", back_populates="audits")
