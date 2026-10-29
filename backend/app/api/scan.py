import os
import sys
import uuid
import json
import joblib
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query, status

from app.schemas.scan import (
    UrlScanRequest, EmailScanRequest, MessageScanRequest,
    ScanResult, ScanHistorySummary, DashboardStats,
    Finding, Severity, MLPredictionResult
)
from app.services.url_analyzer import UrlAnalyzer
from app.services.email_analyzer import EmailAnalyzer
from app.services.message_analyzer import MessageAnalyzer
from app.services.risk_scoring import RiskScoringEngine
from app.services.threat_intelligence import ThreatIntelligenceService
from app.database.db import db_service
from app.core.config import settings

# Ensure ML package is importable
ML_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "ml"))
if ML_DIR not in sys.path:
    sys.path.insert(0, ML_DIR)

try:
    from feature_extraction import extract_url_features, features_to_vector
except ImportError:
    extract_url_features = None
    features_to_vector = None

router = APIRouter()
url_analyzer = UrlAnalyzer()
email_analyzer = EmailAnalyzer()
message_analyzer = MessageAnalyzer()
threat_intel_service = ThreatIntelligenceService()

# Cache loaded ML model
_CACHED_MODEL = None
_CACHED_METRICS = None

def get_ml_model():
    global _CACHED_MODEL, _CACHED_METRICS
    if _CACHED_MODEL is None and os.path.exists(settings.ml_model_path):
        try:
            _CACHED_MODEL = joblib.load(settings.ml_model_path)
            if os.path.exists(settings.ml_metrics_path):
                with open(settings.ml_metrics_path, "r", encoding="utf-8") as f:
                    _CACHED_METRICS = json.load(f)
        except Exception as e:
            print(f"Error loading ML model: {e}")
            _CACHED_MODEL = None
    return _CACHED_MODEL, _CACHED_METRICS

@router.post("/scan/url", response_model=ScanResult)
async def scan_url(request: UrlScanRequest):
    """Analyze a URL using rule-based heuristics, machine learning, and threat intelligence."""
    raw_url = request.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # 1. Rule-based static URL analysis
    findings, url_details = url_analyzer.analyze(raw_url)
    checks_completed = [
        "RFC 3986 URL parsing & syntax validation",
        "Domain & Public Suffix classification",
        "IP address host detection",
        "Subdomain depth & nesting analysis",
        "IDN Punycode homograph check",
        "URL shortener blacklist lookup",
        "Sensitive action keywords detection",
        "Typosquatting & lookalike heuristic evaluation",
        "Shannon entropy calculation"
    ]
    checks_not_performed = [
        "Headless browser DOM execution (preventing SSRF/malware infection)",
        "Automated redirect chain following",
        "File payload download"
    ]

    # 2. Optional Machine Learning classification
    ml_result = None
    analysis_mode = "Rule-Based"
    if request.enable_ml and extract_url_features is not None:
        model, metrics = get_ml_model()
        if model is not None:
            analysis_mode = "Rule-Based + ML"
            feats = extract_url_features(raw_url)
            vec = features_to_vector(feats)
            try:
                pred_label = int(model.predict([vec])[0])
                probs = model.predict_proba([vec])[0]
                phish_prob = float(probs[1]) if len(probs) > 1 else (1.0 if pred_label == 1 else 0.0)
                pred_str = "PHISHING" if pred_label == 1 else "LEGITIMATE"

                ml_result = MLPredictionResult(
                    model_name="RandomForestPhishClassifier",
                    is_available=True,
                    prediction=pred_str,
                    phishing_probability=round(phish_prob, 4),
                    features_extracted=feats,
                    model_metrics=metrics,
                    notes="URL features evaluated by trained Random Forest model. Prediction is synthesized with heuristic indicators."
                )

                if pred_label == 1 and phish_prob >= 0.70:
                    findings.append(Finding(
                        rule_id="RULE_ML_PHISHING_PROBABILITY",
                        title=f"Machine Learning Phishing Alert ({round(phish_prob * 100, 1)}% Probability)",
                        severity=Severity.CRITICAL if phish_prob >= 0.90 else Severity.HIGH,
                        weight=80.0 if phish_prob >= 0.90 else 60.0,
                        explanation=f"The trained Random Forest classification model predicted this URL is phishing with {round(phish_prob * 100, 1)}% probability based on lexical structure and entropy metrics.",
                        evidence=f"Extracted features: entropy={feats.get('hostname_entropy')}, length={feats.get('url_length')}, subdomains={feats.get('num_subdomains')}",
                        remediation="Do not open or trust this URL.",
                        confidence=round(phish_prob, 2)
                    ))
            except Exception as e:
                ml_result = MLPredictionResult(
                    is_available=False,
                    notes=f"ML feature inference failed: {str(e)[:100]}"
                )
        else:
            ml_result = MLPredictionResult(
                is_available=False,
                notes="Trained ML model not found on server disk. Falling back cleanly to deterministic heuristic rules."
            )
            checks_not_performed.append("Machine learning model classification (model file unavailable)")

    # 3. Optional Threat Intelligence lookup
    threat_intel_results = []
    if request.enable_threat_intel:
        threat_intel_results = await threat_intel_service.query_url(raw_url)
        for ti in threat_intel_results:
            if ti.status == "MALICIOUS" and ti.is_live:
                findings.append(Finding(
                    rule_id=f"RULE_TI_{ti.provider.replace(' ', '_').upper()}",
                    title=f"Threat Intelligence Flag: {ti.provider}",
                    severity=Severity.CRITICAL,
                    weight=90.0,
                    explanation=f"The URL is confirmed malicious by {ti.provider}.",
                    evidence=ti.details,
                    remediation="Immediately block this domain at perimeter DNS/gateway.",
                    confidence=1.0
                ))
        if any(ti.is_live and ti.status != "NOT_CONFIGURED" for ti in threat_intel_results):
            analysis_mode = "Combined Analysis (Rules + ML + Threat Intel)"

    # 4. Transparent Risk Scoring
    risk_breakdown = RiskScoringEngine.calculate_score(findings)

    # 5. Executive summary synthesis
    if risk_breakdown.severity == Severity.CRITICAL:
        summary = f"CRITICAL THREAT: Found {len(findings)} high-risk indicators pointing to active credential harvesting or brand impersonation."
    elif risk_breakdown.severity == Severity.HIGH:
        summary = f"HIGH RISK: The analyzed URL displays strong phishing characteristics ({len(findings)} indicators triggered)."
    elif risk_breakdown.severity == Severity.MODERATE:
        summary = f"MODERATE RISK: Several anomalous URL attributes were detected. Proceed with caution."
    else:
        summary = "LOW RISK: No blatant heuristic threats or phishing patterns detected in this URL."

    scan_res = ScanResult(
        scan_id=str(uuid.uuid4()),
        scan_type="url",
        timestamp=datetime.utcnow(),
        input_preview=raw_url,
        risk_score=risk_breakdown.total_score,
        severity=risk_breakdown.severity,
        analysis_mode=analysis_mode,
        summary=summary,
        findings=risk_breakdown.contributing_findings,
        risk_breakdown=risk_breakdown,
        url_details=url_details,
        ml_result=ml_result,
        threat_intel=threat_intel_results,
        checks_completed=checks_completed,
        checks_not_performed=checks_not_performed,
        limitations=risk_breakdown.important_limitations,
        recommendations=risk_breakdown.recommended_actions
    )

    db_service.save_scan(scan_res)
    return scan_res

@router.post("/scan/email", response_model=ScanResult)
async def scan_email(request: EmailScanRequest):
    """Analyze an email message for spoofing, social engineering, malicious links, and header anomalies."""
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Email content cannot be empty.")

    findings, email_details = email_analyzer.analyze(
        content=request.content,
        sender=request.sender,
        display_name=request.display_name,
        reply_to=request.reply_to,
        subject=request.subject,
        raw_headers=request.raw_headers
    )

    checks_completed = [
        "Sender & Reply-To domain correlation",
        "Executive / Brand display name spoofing check",
        "Psychological urgency & threat pattern detection",
        "Credential harvesting lure detection",
        "Financial pressure & wire transfer request detection",
        "Dangerous attachment keyword pattern matching",
        "Embedded hyperlink extraction & deep URL inspection"
    ]
    if request.raw_headers or "spf=" in request.content.lower():
        checks_completed.append("Supplied SPF/DKIM/DMARC header analysis")

    checks_not_performed = [
        "Live DNS SPF/DMARC record query (distinguished from user-supplied headers)",
        "Direct email gateway sandbox detonation",
        "Active server-to-server mail bounce probe"
    ]

    risk_breakdown = RiskScoringEngine.calculate_score(findings)

    if risk_breakdown.severity == Severity.CRITICAL:
        summary = f"CRITICAL PHISHING: Highly sophisticated social engineering or spoofing attempt detected ({len(findings)} findings)."
    elif risk_breakdown.severity == Severity.HIGH:
        summary = f"HIGH SUSPICION: The email presents deceptive patterns aiming to acquire credentials or initiate unverified actions."
    elif risk_breakdown.severity == Severity.MODERATE:
        summary = "MODERATE RISK: Email contains urgency triggers or unusual routing indicators."
    else:
        summary = "LOW RISK: Content exhibits no obvious phishing patterns or spoofing markers."

    preview_text = request.subject or request.content[:100].replace("\n", " ")
    scan_res = ScanResult(
        scan_id=str(uuid.uuid4()),
        scan_type="email",
        timestamp=datetime.utcnow(),
        input_preview=preview_text,
        risk_score=risk_breakdown.total_score,
        severity=risk_breakdown.severity,
        analysis_mode="Heuristic Content & Header Engine",
        summary=summary,
        findings=risk_breakdown.contributing_findings,
        risk_breakdown=risk_breakdown,
        email_details=email_details,
        checks_completed=checks_completed,
        checks_not_performed=checks_not_performed,
        limitations=risk_breakdown.important_limitations,
        recommendations=risk_breakdown.recommended_actions
    )

    db_service.save_scan(scan_res)
    return scan_res

@router.post("/scan/message", response_model=ScanResult)
async def scan_message(request: MessageScanRequest):
    """Analyze SMS / chat messages for smishing, OTP theft, fake postal delivery, and urgent lures."""
    if not request.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    findings, message_details = message_analyzer.analyze(
        message=request.message,
        source_hint=request.source_hint
    )

    checks_completed = [
        "Package delivery smishing detection (USPS/DHL/FedEx)",
        "Banking & fraud alert smishing detection",
        "OTP & 2FA interception detection",
        "Family & emergency impersonation detection",
        "Shortened URL identification & embedded link security audit",
        "Psychological coercion & urgency analysis"
    ]
    checks_not_performed = [
        "Cellular carrier SS7 / HLR lookup",
        "Real-time SMS gateway sender ID lookup"
    ]

    risk_breakdown = RiskScoringEngine.calculate_score(findings)

    if risk_breakdown.severity == Severity.CRITICAL:
        summary = f"CRITICAL SMISHING: Dangerous mobile fraud attempt detected targeting credentials, banking, or OTPs."
    elif risk_breakdown.severity == Severity.HIGH:
        summary = f"HIGH RISK: Message contains deceptive postal or financial lures designed to redirect to rogue sites."
    elif risk_breakdown.severity == Severity.MODERATE:
        summary = "MODERATE RISK: Message contains shortened links or unsolicited urgency."
    else:
        summary = "LOW RISK: No recognized smishing or scam patterns were identified."

    scan_res = ScanResult(
        scan_id=str(uuid.uuid4()),
        scan_type="message",
        timestamp=datetime.utcnow(),
        input_preview=request.message[:100].replace("\n", " "),
        risk_score=risk_breakdown.total_score,
        severity=risk_breakdown.severity,
        analysis_mode="Mobile Smishing & Social Engineering Engine",
        summary=summary,
        findings=risk_breakdown.contributing_findings,
        risk_breakdown=risk_breakdown,
        message_details=message_details,
        checks_completed=checks_completed,
        checks_not_performed=checks_not_performed,
        limitations=risk_breakdown.important_limitations,
        recommendations=risk_breakdown.recommended_actions
    )

    db_service.save_scan(scan_res)
    return scan_res

@router.get("/scan/history", response_model=List[ScanHistorySummary])
async def get_scan_history(
    scan_type: Optional[str] = Query(None, description="Filter by type: url, email, message, or ALL"),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MODERATE, HIGH, CRITICAL, or ALL"),
    query: Optional[str] = Query(None, description="Search query string"),
    limit: int = Query(50, ge=1, le=100)
):
    """Retrieve historical scan records with optional filters."""
    return db_service.list_history(scan_type=scan_type, severity=severity, query=query, limit=limit)

@router.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan_details(scan_id: str):
    """Retrieve detailed scan result by ID."""
    scan = db_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan record '{scan_id}' not found.")
    return scan

@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan record from history."""
    deleted = db_service.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Scan record '{scan_id}' not found.")
    return {"message": "Scan record deleted successfully", "scan_id": scan_id}

@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """Get aggregated security telemetry and threat statistics."""
    return db_service.get_dashboard_stats()

@router.get("/demo/samples")
async def get_demo_samples():
    """Returns curated demo scenarios so users can test immediately without credentials."""
    return [
        {
            "id": "benign-url",
            "title": "Benign Official Domain",
            "type": "url",
            "description": "Legitimate, encrypted reference website with clean structure.",
            "data": {
                "url": "https://www.wikipedia.org/wiki/Computer_security"
            }
        },
        {
            "id": "lookalike-url",
            "title": "Credential Harvester Lookalike URL",
            "type": "url",
            "description": "Typosquatted domain mimicking PayPal with sensitive action keywords.",
            "data": {
                "url": "http://paypa1-security-verify.com.account-update.cc/login?cmd=_auth"
            }
        },
        {
            "id": "urgent-email",
            "title": "Urgent Banking Suspension Phishing Email",
            "type": "email",
            "description": "Urgent security lure with sender/reply-to mismatch and credential solicitation.",
            "data": {
                "sender": "Security Department <support@notification-chase-update.xyz>",
                "display_name": "Chase Security Team",
                "reply_to": "inbox9821@attacker-collect.cc",
                "subject": "URGENT: Unauthorized login detected. Account suspended within 24 hours.",
                "content": "Dear Customer,\n\nWe detected unauthorized activity from an unrecognized IP address. To prevent permanent termination, you must confirm your password and enter your OTP immediately.\n\nPlease visit the secure portal below to verify:\nhttp://chase-bank-alert.com/account/login?id=938210382\n\nFailure to respond within 24 hours will result in permanent debit card cancellation.\n\nChase Fraud Prevention Unit"
            }
        },
        {
            "id": "delivery-sms",
            "title": "Fake USPS Package Delivery Smishing SMS",
            "type": "message",
            "description": "Smishing SMS claiming an incomplete address with shortened link.",
            "data": {
                "message": "USPS Alert: Your parcel could not be delivered due to an incomplete address. Update address and pay $1.99 redelivery fee within 12 hours: http://bit.ly/3xSecAlertUrgent",
                "source_hint": "sms"
            }
        }
    ]

@router.post("/demo/seed")
async def seed_demo_data():
    """Seeds the database with representative initial scans for demonstration."""
    samples = await get_demo_samples()
    created = []
    for s in samples:
        if s["type"] == "url":
            res = await scan_url(UrlScanRequest(url=s["data"]["url"]))
            created.append(res.scan_id)
        elif s["type"] == "email":
            res = await scan_email(EmailScanRequest(**s["data"]))
            created.append(res.scan_id)
        elif s["type"] == "message":
            res = await scan_message(MessageScanRequest(**s["data"]))
            created.append(res.scan_id)
    return {"message": "Demo data successfully seeded", "scans_created": len(created), "ids": created}

@router.post("/demo/reset")
async def reset_demo_data():
    """Clears all scan history."""
    try:
        with db_service._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans")
            conn.commit()
        return {"message": "Scan history cleared successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
