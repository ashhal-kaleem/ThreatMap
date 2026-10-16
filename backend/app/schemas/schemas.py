"""
Pydantic Schemas for ThreatMap Lite.
Strictly adheres to architecture.md Section 6 API Endpoints Specification.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ReportUploadResponse(BaseModel):
    report_id: str
    status: str = "processing"


class ReportStatusResponse(BaseModel):
    status: str  # pending | processing | complete | failed
    current_step: str
    error_msg: Optional[str] = None


class IOCResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    type: str  # ipv4 | domain | url | md5 | sha1 | sha256 | cve
    value: str
    source_page: int
    evidence: str


class ReportResultsResponse(BaseModel):
    report_id: str
    file_name: str
    page_count: Optional[int] = None
    status: str
    created_at: datetime
    iocs: List[IOCResponse]
    ioc_summary: Dict[str, int] = Field(default_factory=dict)
    mappings: List[Dict[str, Any]] = Field(default_factory=list)
    mitigations: List[Dict[str, Any]] = Field(default_factory=list)
    ai_analysis: Optional[Dict[str, Any]] = None


class ReportListItem(BaseModel):
    id: str
    file_name: str
    page_count: Optional[int] = None
    status: str
    created_at: datetime
    ioc_count: int = 0
