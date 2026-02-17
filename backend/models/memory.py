"""
NeuroSploit v3 - Persistent Memory Models

Three memory types for cross-session learning:
1. AttackPatternMemory — what worked/failed against which tech stacks
2. TargetFingerprint — cumulative knowledge per domain
3. SuccessfulPayload — high-value payloads indexed by tech+vuln_type
"""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, Float, Integer, Boolean, DateTime, JSON
from backend.db.database import Base


class AttackPatternMemory(Base):
    """Records what attack patterns worked or failed against specific tech stacks."""
    __tablename__ = "attack_pattern_memory"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain = Column(String(255), nullable=False, index=True)
    vuln_type = Column(String(100), nullable=False, index=True)
    tech_stack = Column(JSON, default=list)  # ["nginx", "react", "express"]
    payload = Column(Text)
    parameter = Column(String(500))
    endpoint = Column(Text)
    success = Column(Boolean, nullable=False)
    confidence = Column(Float, default=0.0)
    severity = Column(String(20))
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class TargetFingerprint(Base):
    """Cumulative knowledge about a specific target domain."""
    __tablename__ = "target_fingerprints"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain = Column(String(255), nullable=False, unique=True, index=True)
    tech_stack = Column(JSON, default=list)
    waf_detected = Column(String(100))
    open_ports = Column(JSON, default=list)
    interesting_paths = Column(JSON, default=list)
    known_vulns = Column(JSON, default=list)  # [{type, endpoint, severity}]
    auth_type = Column(String(50))  # "jwt", "session", "basic", "none"
    scan_count = Column(Integer, default=0)
    last_scanned = Column(DateTime)
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SuccessfulPayload(Base):
    """High-value payloads that have been confirmed to work."""
    __tablename__ = "successful_payloads"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vuln_type = Column(String(100), nullable=False, index=True)
    tech_stack_tag = Column(String(255), index=True)  # e.g. "nginx+express" for lookup
    payload = Column(Text, nullable=False)
    parameter = Column(String(500))
    endpoint_pattern = Column(String(500))  # generalized pattern e.g. "/api/users/{id}"
    success_count = Column(Integer, default=1)
    last_success_domain = Column(String(255))
    confidence = Column(Float, default=0.0)
    severity = Column(String(20))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
