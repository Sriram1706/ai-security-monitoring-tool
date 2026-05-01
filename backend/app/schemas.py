from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=128)


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: str = "analyst"


class UserOut(BaseModel):
    id: int
    email: str
    role: str

    class Config:
        from_attributes = True


class ScanRequest(BaseModel):
    provider: str
    model_name: Optional[str] = None
    prompt: str = Field(min_length=1)
    response: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class RiskFinding(BaseModel):
    risk_type: str
    severity: str
    score: int
    explanation: str
    remediation: list[str] = []
    owasp_category: str | None = None
    framework: str | None = None
    category_id: str | None = None
    category_name: str | None = None
    atlas_tactic: str | None = None
    atlas_technique: str | None = None
    atlas_technique_id: str | None = None
    atlas_confidence: float | None = None
    prompt_intent: str | None = None
    attack_type: str | None = None
    risk_types: list[str] = []
    agentic_risk: str | None = None
    owasp_categories: list[str] = []
    confidence: float | None = None
    compliance_mappings: list[dict[str, str]] = []


class ClassificationOut(BaseModel):
    prompt_intent: str
    attack_type: str
    risk_types: list[str]
    agentic_risk: str
    owasp: list[str]
    severity: str
    confidence: float


class ScanResponse(BaseModel):
    scan_id: int
    total_score: int
    risk_score: float = 0.0
    severity: str
    findings: list[RiskFinding]
    created_at: datetime


class ScanLogOut(BaseModel):
    id: int
    provider: str
    source: Optional[str] = None
    model_name: Optional[str]
    prompt: str
    response: Optional[str]
    risk_score: int
    severity: str
    findings: list[dict[str, Any]]
    metadata: Optional[dict[str, Any]] = Field(default=None, alias="extra_metadata")
    created_at: datetime

    class Config:
        from_attributes = True
        populate_by_name = True


class AnalyticsOut(BaseModel):
    total_scans: int
    avg_risk_score: float
    severity_distribution: dict[str, int]
    top_risk_types: list[dict[str, Any]]


class CodeFindingOut(BaseModel):
    id: int
    log_id: int | None = None
    prompt: str
    finding_type: str
    severity: str
    title: str
    explanation: str
    remediation: str
    evidence: str
    confidence: float
    provider: str
    source: str
    endpoint: str
    timestamp: str
    metadata: dict[str, Any] = {}


class CodeFindingsSummaryOut(BaseModel):
    total_findings: int
    severity_distribution: dict[str, int]
    top_finding_types: list[dict[str, Any]]
    findings_last_24h: int


class PromptProcessRequest(BaseModel):
    prompt: str = Field(min_length=1)
    provider: str = "openai"
    model_name: Optional[str] = None


class PromptProcessResponse(BaseModel):
    prompt: str
    response: str
    risk_score: int
    risk_type: str
    severity: str
    status: str
    blocked: bool
    provider: str
    timestamp: datetime
    remediation: str
    findings: list[RiskFinding]
    policy_reason: str | None = None
    policy_version: str | None = None
    classifications: list[ClassificationOut] = []


class GatewayEvaluateRequest(BaseModel):
    prompt: str = Field(min_length=1)
    provider: str = "openai"
    source: str = "api_gateway"
    model_name: str | None = None
    metadata: dict[str, Any] | None = None


class GatewayEvaluateResponse(BaseModel):
    prompt: str
    provider: str
    source: str
    model_name: str | None = None
    risk_score: int
    risk_type: str
    severity: str
    status: str
    blocked: bool
    action: str
    policy_reason: str
    policy_version: str
    findings: list[RiskFinding]
    classifications: list[ClassificationOut] = []
    timestamp: datetime


class PolicyControlPlaneOut(BaseModel):
    app_name: str
    environment: str
    policy_version: str
    enforcement_actions: list[str]
    supported_sources: list[str]
    supported_providers: list[str]
    thresholds: dict[str, int]
    hard_block_risk_types: list[str]
    strict_prompt_attack_types: list[str]
    mirror_ingest_enabled: bool
    threat_intel_enabled: bool
    supply_chain_scan_enabled: bool
    url_fetch_allowlist: list[str]


class ConnectorSourceCreateRequest(BaseModel):
    source_name: str = Field(min_length=3, max_length=64)
    display_name: str = Field(min_length=3, max_length=128)
    source_type: str = Field(min_length=3, max_length=32)
    provider: str = Field(min_length=2, max_length=64)
    policy_profile: str = Field(default="default", min_length=3, max_length=64)
    metadata: dict[str, Any] | None = None


class ConnectorSourceOut(BaseModel):
    id: int
    source_name: str
    display_name: str
    source_type: str
    provider: str
    policy_profile: str
    status: str
    created_at: str
    updated_at: str
    last_seen_at: str | None = None
    metadata: dict[str, Any] = {}


class ConnectorSourceCreateResponse(BaseModel):
    source: ConnectorSourceOut
    api_key: str


class ConnectorSourceRotateResponse(BaseModel):
    source: ConnectorSourceOut
    api_key: str


class ThreatSummaryOut(BaseModel):
    total_requests: int
    blocked_requests: int
    injection_attempts: int
    data_leak_attempts: int


class MirrorIngestRequest(BaseModel):
    prompt: str = Field(min_length=1)
    source: str = "chatgpt_personal"
    provider: str = "chatgpt_personal"
    page_url: str | None = None


class MirrorIngestResponse(BaseModel):
    mirror_id: int
    prompt: str
    risk_score: int
    risk_type: str
    severity: str
    status: str
    blocked: bool
    provider: str
    source: str
    timestamp: datetime
    findings: list[RiskFinding]


class AlertOut(BaseModel):
    type: str
    severity: str
    message: str
    timestamp: str


class LogFilters(BaseModel):
    risk_type: Optional[str] = None
    severity: Optional[str] = None
    provider: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class AidrIncidentOut(BaseModel):
    incident_id: str
    timestamp: datetime
    who: str
    risk_type: str
    owasp_category: str
    severity: str
    score: int
    blocked: bool
    status: str
    priority: str | None = None
    confidence: float | None = None
    kill_chain_stage: str | None = None
    repeat_count: int | None = None
    how: str
    why: str
    prompt_preview: str
    explanation: str
    remediation: list[str]
    response_action: str


class AidrAttackPathEdgeOut(BaseModel):
    source_risk: str
    target_risk: str
    count: int
    avg_score: float | None = None
    blocked_rate: float | None = None
    confidence: float | None = None
    last_seen: str | None = None


class UrlScanRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    provider: str = "openai"


class UrlScanResponse(BaseModel):
    url: str
    blocked: bool
    status: str
    risk_score: int
    severity: str
    findings: list[RiskFinding]
    message: str
    timestamp: datetime
    policy_reason: str | None = None
    policy_version: str | None = None
    classifications: list[ClassificationOut] = []


class ThreatIntelStatusOut(BaseModel):
    enabled: bool
    rules_count: int
    last_updated: Optional[str] = None
    last_run: Optional[str] = None
    last_success: Optional[str] = None
    last_error: Optional[str] = None
    feeds: list[str] = []


class LogActionRequest(BaseModel):
    action: str = Field(min_length=4, max_length=8, description="BLOCK or FLAG")
    note: str | None = Field(default=None, max_length=500)


class LogActionResponse(BaseModel):
    id: int
    blocked: bool
    status: str
    analyst_action: str
    reviewed_by: str
    reviewed_at: str
    note: str | None = None


class SupplyChainEvidenceOut(BaseModel):
    prompt: str
    risk_type: str
    severity: str
    timestamp: str
    provider: str


class SupplyChainFindingOut(BaseModel):
    finding_id: str
    title: str
    category: str
    severity: str
    status: str
    score: int
    affected_component: str
    evidence_count: int
    description: str
    remediation: str
    last_seen: str | None = None
    evidence_samples: list[SupplyChainEvidenceOut] = []


class SupplyChainSummaryOut(BaseModel):
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    open: int
    monitor: int
    pass_count: int
    overall_score: int
    cve_count: int = 0
    scanned_dependencies: int = 0
    unpinned_dependencies: int = 0
    feed_status: str = "unknown"


class SupplyChainOut(BaseModel):
    generated_at: datetime
    summary: SupplyChainSummaryOut
    findings: list[SupplyChainFindingOut]
    scan_errors: list[str] = []
