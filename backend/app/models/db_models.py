"""
SQLAlchemy ORM Models for ThreatMap Lite.
Module: Database + Pipeline + Report Management
Strictly adheres to architecture.md Section 4 Database Schema.
"""

import uuid
from datetime import datetime
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    JSON,
)
from sqlalchemy.orm import relationship

from backend.app.database import Base


def generate_uuid() -> str:
    """Helper to generate standard UUID strings."""
    return str(uuid.uuid4())


class Report(Base):
    """1. Reports metadata & pipeline status"""
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    file_name = Column(Text, nullable=False)
    page_count = Column(Integer, nullable=True)
    status = Column(String(32), nullable=False, default="pending")  # pending | processing | complete | failed
    error_msg = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationships with cascade delete
    pages = relationship("ReportPage", back_populates="report", cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="report", cascade="all, delete-orphan")
    behavior_sentences = relationship("BehaviorSentence", back_populates="report", cascade="all, delete-orphan")
    mappings = relationship("Mapping", back_populates="report", cascade="all, delete-orphan")
    ai_analyses = relationship("ReportAIAnalysis", back_populates="report", cascade="all, delete-orphan")


class ReportPage(Base):
    """2. Page-by-page extracted raw text"""
    __tablename__ = "report_pages"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_id = Column(String(36), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    page_number = Column(Integer, nullable=False)
    page_text = Column(Text, nullable=False)

    report = relationship("Report", back_populates="pages")

    __table_args__ = (
        UniqueConstraint("report_id", "page_number", name="uq_report_page_number"),
    )


class IOC(Base):
    """3. Extracted Indicators of Compromise (IOCs)"""
    __tablename__ = "iocs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_id = Column(String(36), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    ioc_type = Column(String(32), nullable=False)  # ipv4 | domain | url | md5 | sha1 | sha256 | cve
    ioc_value = Column(Text, nullable=False)
    source_page = Column(Integer, nullable=False)
    evidence = Column(Text, nullable=False)

    report = relationship("Report", back_populates="iocs")


class BehaviorSentence(Base):
    """4. Extracted behavior sentences"""
    __tablename__ = "behavior_sentences"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_id = Column(String(36), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    sentence = Column(Text, nullable=False)
    source_page = Column(Integer, nullable=False)

    report = relationship("Report", back_populates="behavior_sentences")
    mappings = relationship("Mapping", back_populates="sentence", cascade="all, delete-orphan")


class AttackTechnique(Base):
    """5. Curated MITRE ATT&CK techniques"""
    __tablename__ = "attack_techniques"

    technique_id = Column(String(64), primary_key=True)  # e.g. T1059.001
    technique_name = Column(Text, nullable=False)
    tactic = Column(Text, nullable=False)
    description = Column(Text, nullable=False)

    mappings = relationship("Mapping", back_populates="technique")
    mitigations = relationship("TechniqueMitigation", back_populates="technique", cascade="all, delete-orphan")


class AttackMitigation(Base):
    """6. Official MITRE ATT&CK mitigations"""
    __tablename__ = "attack_mitigations"

    mitigation_id = Column(String(64), primary_key=True)  # e.g. M1047
    name = Column(Text, nullable=False)
    description = Column(Text, nullable=False)

    techniques = relationship("TechniqueMitigation", back_populates="mitigation", cascade="all, delete-orphan")


class TechniqueMitigation(Base):
    """7. Technique-to-Mitigation mapping relationships"""
    __tablename__ = "technique_mitigations"

    technique_id = Column(String(64), ForeignKey("attack_techniques.technique_id", ondelete="CASCADE"), primary_key=True)
    mitigation_id = Column(String(64), ForeignKey("attack_mitigations.mitigation_id", ondelete="CASCADE"), primary_key=True)
    usage_description = Column(Text, nullable=True)

    technique = relationship("AttackTechnique", back_populates="mitigations")
    mitigation = relationship("AttackMitigation", back_populates="techniques")


class Mapping(Base):
    """8. ATT&CK Predictions & Abstentions"""
    __tablename__ = "mappings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_id = Column(String(36), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    sentence_id = Column(String(36), ForeignKey("behavior_sentences.id", ondelete="CASCADE"), nullable=False)
    technique_id = Column(String(64), ForeignKey("attack_techniques.technique_id", ondelete="RESTRICT"), nullable=True)
    similarity = Column(Float, nullable=False)
    confidence_ok = Column(Boolean, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    report = relationship("Report", back_populates="mappings")
    sentence = relationship("BehaviorSentence", back_populates="mappings")
    technique = relationship("AttackTechnique", back_populates="mappings")


class ReportAIAnalysis(Base):
    """9. Gemini AI-Generated Combined Summaries & Tips Cache"""
    __tablename__ = "report_ai_analysis"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_id = Column(String(36), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    generation_type = Column(String(64), nullable=False, default="summary_and_tips")
    summary = Column(Text, nullable=False)
    tips = Column(JSON, nullable=False)  # List of strings
    source_hash = Column(Text, nullable=False)
    prompt_version = Column(String(32), nullable=False, default="v1")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    report = relationship("Report", back_populates="ai_analyses")

    __table_args__ = (
        UniqueConstraint("report_id", "generation_type", "prompt_version", name="uq_report_ai_lookup"),
    )
