from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

class Severity(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    weight: float = Field(ge=0.0, le=100.0, description="Contribution weight to risk score")
    explanation: str
    evidence: str
    remediation: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.9, description="Confidence in finding")

class RiskScoreBreakdown(BaseModel):
    total_score: int = Field(ge=0, le=100)
    severity: Severity
    raw_weighted_sum: float
    normalized_score: float
    contributing_findings: List[Finding]
    rule_counts_by_severity: Dict[str, int]
    important_limitations: List[str]
    recommended_actions: List[str]

class UrlDetails(BaseModel):
    raw_url: str
    scheme: str
    hostname: str
    registered_domain: str
    subdomains: List[str]
    port: Optional[int] = None
    path: str
    query_param_count: int
    is_ip_address: bool
    is_shortener: bool
    is_punycode: bool
    shannon_entropy: float
    suspicious_keywords_found: List[str]
    has_credentials_in_url: bool
    lookalike_target: Optional[str] = None

class EmailDetails(BaseModel):
    sender: Optional[str] = None
    sender_domain: Optional[str] = None
    display_name: Optional[str] = None
    reply_to: Optional[str] = None
    subject: Optional[str] = None
    extracted_urls: List[str]
    suspicious_keywords: List[str]
    urgency_detected: bool
    credential_harvest_detected: bool
    financial_fraud_detected: bool
    attachments_referenced: List[str]
    spoofing_indicators: List[str]
    headers_parsed: Dict[str, Any] = {}

class MessageDetails(BaseModel):
    message_type: str  # SMS, WhatsApp, Security Notification, General
    char_count: int
    extracted_urls: List[str]
    urgency_indicators: List[str]
    delivery_scam_detected: bool
    banking_scam_detected: bool
    otp_theft_detected: bool
    suspicious_action_call: bool

class ThreatIntelResult(BaseModel):
    provider: str
    status: str  # CLEAN, MALICIOUS, SUSPICIOUS, NOT_CONFIGURED, RATE_LIMITED, ERROR
    indicator: str
    verdict: Optional[str] = None
    positives: Optional[int] = None
    total_engines: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    is_live: bool = False
    details: str

class MLPredictionResult(BaseModel):
    model_name: str = "RandomForestPhishClassifier"
    is_available: bool
    prediction: Optional[str] = None  # "PHISHING", "LEGITIMATE"
    phishing_probability: Optional[float] = None
    confidence_interval: Optional[str] = None
    features_extracted: Optional[Dict[str, float]] = None
    model_metrics: Optional[Dict[str, Any]] = None
    notes: str

class ScanResult(BaseModel):
    scan_id: str
    scan_type: str  # url, email, message
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    input_preview: str
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    analysis_mode: str  # Rule-Based, Machine Learning, Threat Intel, Combined
    summary: str
    findings: List[Finding]
    risk_breakdown: RiskScoreBreakdown
    url_details: Optional[UrlDetails] = None
    email_details: Optional[EmailDetails] = None
    message_details: Optional[MessageDetails] = None
    ml_result: Optional[MLPredictionResult] = None
    threat_intel: List[ThreatIntelResult] = []
    checks_completed: List[str]
    checks_not_performed: List[str]
    limitations: List[str]
    recommendations: List[str]

# Request Schemas
class UrlScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048, description="URL to analyze")
    enable_ml: bool = True
    enable_threat_intel: bool = True

class EmailScanRequest(BaseModel):
    content: str = Field(min_length=5, max_length=100000, description="Raw email text or body")
    sender: Optional[str] = None
    display_name: Optional[str] = None
    reply_to: Optional[str] = None
    subject: Optional[str] = None
    raw_headers: Optional[str] = None

class MessageScanRequest(BaseModel):
    message: str = Field(min_length=3, max_length=5000, description="SMS or chat message")
    source_hint: Optional[str] = "sms"  # sms, whatsapp, telegram, chat

class ScanHistorySummary(BaseModel):
    scan_id: str
    timestamp: datetime
    scan_type: str
    input_preview: str
    risk_score: int
    severity: Severity
    finding_count: int
    analysis_mode: str
    summary: str

class DashboardStats(BaseModel):
    total_scans: int
    low_risk_count: int
    moderate_risk_count: int
    high_risk_count: int
    critical_risk_count: int
    scans_by_type: Dict[str, int]
    severity_distribution: Dict[str, int]
    top_triggered_rules: List[Dict[str, Any]]
    recent_trend: List[Dict[str, Any]]
