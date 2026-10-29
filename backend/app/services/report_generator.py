import json
from typing import Dict, Any
from app.schemas.scan import ScanResult

class ReportGenerator:
    """Generates structured executive and technical security reports."""

    @staticmethod
    def generate_json_report(result: ScanResult) -> Dict[str, Any]:
        return {
            "report_metadata": {
                "platform": "PhishGuard AI — Phishing Detection Platform",
                "report_version": "1.0",
                "scan_id": result.scan_id,
                "generated_at": result.timestamp.isoformat(),
                "scan_type": result.scan_type.upper(),
                "analysis_mode": result.analysis_mode
            },
            "threat_assessment": {
                "risk_score": result.risk_score,
                "severity": result.severity.value,
                "summary": result.summary
            },
            "findings_count": len(result.findings),
            "findings": [f.model_dump() for f in result.findings],
            "technical_details": {
                "url_details": result.url_details.model_dump() if result.url_details else None,
                "email_details": result.email_details.model_dump() if result.email_details else None,
                "message_details": result.message_details.model_dump() if result.message_details else None,
                "ml_prediction": result.ml_result.model_dump() if result.ml_result else None,
                "threat_intel_results": [ti.model_dump() for ti in result.threat_intel]
            },
            "methodology_and_transparency": {
                "checks_completed": result.checks_completed,
                "checks_not_performed": result.checks_not_performed,
                "system_limitations": result.limitations
            },
            "recommended_actions": result.recommendations,
            "security_disclaimer": "PhishGuard AI provides heuristic and machine-learning assessments. Results do not constitute an absolute legal or forensic safety guarantee."
        }

    @staticmethod
    def generate_printable_html(result: ScanResult) -> str:
        findings_html = ""
        for f in result.findings:
            badge_color = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MODERATE": "#eab308",
                "LOW": "#10b981"
            }.get(f.severity.value, "#64748b")

            findings_html += f"""
            <div style="border: 1px solid #334155; border-radius: 8px; padding: 14px; margin-bottom: 12px; background-color: #0f172a;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span style="font-weight: 600; color: #f8fafc; font-size: 15px;">{f.title}</span>
                    <span style="background-color: {badge_color}; color: #ffffff; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">{f.severity.value}</span>
                </div>
                <div style="color: #94a3b8; font-size: 13px; margin-bottom: 6px;"><strong>Explanation:</strong> {f.explanation}</div>
                <div style="color: #cbd5e1; font-size: 12px; background-color: #1e293b; padding: 8px; border-radius: 4px; font-family: monospace; margin-bottom: 6px;"><strong>Evidence:</strong> {f.evidence}</div>
                <div style="color: #38bdf8; font-size: 13px;"><strong>Remediation:</strong> {f.remediation}</div>
            </div>
            """

        severity_color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MODERATE": "#eab308",
            "LOW": "#10b981"
        }.get(result.severity.value, "#64748b")

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>PhishGuard AI Report - {result.scan_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #020617; color: #f8fafc; padding: 30px; line-height: 1.5; }}
        .header {{ display: flex; justify-content: space-between; border-bottom: 2px solid #1e293b; padding-bottom: 16px; margin-bottom: 24px; }}
        .logo {{ font-size: 22px; font-weight: bold; color: #38bdf8; letter-spacing: -0.5px; }}
        .card {{ background-color: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .score-box {{ text-align: center; padding: 16px; border-radius: 8px; background: #1e293b; }}
        .score-num {{ font-size: 42px; font-weight: bold; color: {severity_color}; }}
        .actions-list li {{ margin-bottom: 6px; color: #94a3b8; }}
        @media print {{ body {{ background-color: #ffffff; color: #000000; }} .card {{ background-color: #f8fafc; border: 1px solid #cbd5e1; color: #000000; }} }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="logo">🛡️ PhishGuard AI</div>
            <div style="color: #64748b; font-size: 13px;">Cybersecurity Threat Assessment Report</div>
        </div>
        <div style="text-align: right; color: #64748b; font-size: 13px;">
            <div>Scan ID: {result.scan_id}</div>
            <div>Generated: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
        </div>
    </div>

    <div class="card" style="display: grid; grid-template-columns: 2fr 1fr; gap: 20px;">
        <div>
            <h2 style="margin-top: 0; color: #f8fafc; font-size: 18px;">Executive Summary</h2>
            <p style="color: #cbd5e1; font-size: 14px;">{result.summary}</p>
            <div style="margin-top: 14px; font-size: 13px; color: #94a3b8;">
                <div><strong>Input Type:</strong> {result.scan_type.upper()}</div>
                <div><strong>Analysis Mode:</strong> {result.analysis_mode}</div>
                <div><strong>Analyzed Preview:</strong> <code>{result.input_preview}</code></div>
            </div>
        </div>
        <div class="score-box">
            <div style="font-size: 13px; color: #94a3b8; text-transform: uppercase;">Threat Risk Score</div>
            <div class="score-num">{result.risk_score}<span style="font-size: 20px; color: #64748b;">/100</span></div>
            <div style="font-weight: bold; color: {severity_color};">{result.severity.value} RISK</div>
        </div>
    </div>

    <div class="card">
        <h3 style="margin-top: 0; color: #38bdf8; font-size: 16px;">Detection Findings ({len(result.findings)})</h3>
        {findings_html if findings_html else '<p style="color: #10b981;">No suspicious heuristic or machine learning indicators were triggered.</p>'}
    </div>

    <div class="card">
        <h3 style="margin-top: 0; color: #38bdf8; font-size: 16px;">Recommended Remediations</h3>
        <ul class="actions-list">
            {"".join(f"<li>{act}</li>" for act in result.recommendations)}
        </ul>
    </div>

    <div class="card" style="font-size: 12px; color: #64748b;">
        <h4 style="margin-top: 0; color: #94a3b8;">Analysis Transparency & Limitations</h4>
        <p><strong>Completed Checks:</strong> {", ".join(result.checks_completed)}</p>
        <p><strong>Known Limitations:</strong> {"; ".join(result.limitations)}</p>
        <p><em>Disclaimer: PhishGuard AI provides heuristic assessments and cannot guarantee absolute safety. Always practice defense-in-depth.</em></p>
    </div>
</body>
</html>
"""
        return html
