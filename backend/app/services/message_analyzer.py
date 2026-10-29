import re
from typing import List, Tuple, Optional
from app.schemas.scan import Finding, Severity, MessageDetails
from app.services.url_analyzer import UrlAnalyzer

DELIVERY_KEYWORDS = [
    r"usps", r"fedex", r"dhl", r"ups", r"package", r"parcel",
    r"delivery", r"redelivery", r"customs fee", r"shipment pending",
    r"cannot be delivered", r"address incomplete", r"update address"
]

BANKING_KEYWORDS = [
    r"bank of america", r"wells fargo", r"chase", r"citi", r"card suspended",
    r"account locked", r"unauthorized charge", r"fraud alert", r"wire transfer",
    r"debit card blocked", r"suspicious transaction"
]

OTP_KEYWORDS = [
    r"otp", r"verification code", r"one-time password", r"security code",
    r"do not share", r"passcode", r"enter code", r"confirm code"
]

IMPERSONATION_KEYWORDS = [
    r"hey mom", r"hey dad", r"new number", r"lost my phone",
    r"broken phone", r"emergency money", r"urgent favor", r"gift card"
]

class MessageAnalyzer:
    """Security analyzer for SMS (Smishing), chat, and social engineering messages."""

    def __init__(self):
        self.url_analyzer = UrlAnalyzer()

    def analyze(self, message: str, source_hint: Optional[str] = "sms") -> Tuple[List[Finding], MessageDetails]:
        findings: List[Finding] = []
        lower_msg = message.lower()

        # 1. Fake Delivery Scam Detection (Very common Smishing)
        delivery_matches = [k for k in DELIVERY_KEYWORDS if re.search(r"\b" + re.escape(k) + r"\b", lower_msg)]
        is_delivery_scam = len(delivery_matches) >= 2
        if is_delivery_scam:
            findings.append(Finding(
                rule_id="RULE_MSG_DELIVERY_SMISHING",
                title="Fake Package Delivery / Postal Notification Scam",
                severity=Severity.HIGH,
                weight=65.0,
                explanation="The message simulates a courier (USPS, FedEx, DHL) delivery delay or unpaid fee lure, a prevalent smishing tactic to steal payment credentials.",
                evidence=f"Matched indicators: {', '.join(delivery_matches)}",
                remediation="Do not click the tracking link. Visit the official courier website directly and enter your genuine tracking ID.",
                confidence=0.95
            ))

        # 2. Fake Banking Alert Detection
        banking_matches = [k for k in BANKING_KEYWORDS if re.search(r"\b" + re.escape(k) + r"\b", lower_msg)]
        is_banking_scam = len(banking_matches) >= 2
        if is_banking_scam:
            findings.append(Finding(
                rule_id="RULE_MSG_BANKING_SMISHING",
                title="Fraudulent Banking / Financial Alert Smishing",
                severity=Severity.CRITICAL,
                weight=80.0,
                explanation="The message masquerades as a bank fraud alert or account freeze notification designed to provoke panic credential entry.",
                evidence=f"Banking lure keywords: {', '.join(banking_matches)}",
                remediation="Never call the number in the SMS. Call the official phone number printed on the back of your bank card.",
                confidence=0.95
            ))

        # 3. OTP Theft / Credential Hijack
        otp_matches = [k for k in OTP_KEYWORDS if re.search(r"\b" + re.escape(k) + r"\b", lower_msg)]
        is_otp_theft = len(otp_matches) >= 1 and ("click" in lower_msg or "http" in lower_msg or "link" in lower_msg)
        if is_otp_theft:
            findings.append(Finding(
                rule_id="RULE_MSG_OTP_INTERCEPTION",
                title="One-Time Password (OTP) Interception / Phishing",
                severity=Severity.CRITICAL,
                weight=85.0,
                explanation="The message mentions verification codes or OTPs alongside a link or call-to-action. Fraudsters use this to bypass two-factor authentication.",
                evidence=f"OTP phrases matched: {', '.join(otp_matches)}",
                remediation="NEVER share OTPs or enter authentication codes into web pages linked via text messages.",
                confidence=0.95
            ))

        # 4. Family / Friend Impersonation ("Hi Mom" scam)
        impersonation_matches = [k for k in IMPERSONATION_KEYWORDS if re.search(r"\b" + re.escape(k) + r"\b", lower_msg)]
        if len(impersonation_matches) >= 2:
            findings.append(Finding(
                rule_id="RULE_MSG_FAMILY_IMPERSONATION",
                title="Emergency Contact / Relative Impersonation Scam",
                severity=Severity.HIGH,
                weight=70.0,
                explanation="The message simulates an urgent emergency from a family member claiming a broken/lost phone to solicit emergency fund transfers.",
                evidence=f"Impersonation patterns: {', '.join(impersonation_matches)}",
                remediation="Call the relative directly on their known, original phone number before sending money.",
                confidence=0.9
            ))

        # 5. Extract URLs and evaluate
        url_matches = list(set(re.findall(r"(https?://[^\s<>\"\'\(\)]+)", message, re.IGNORECASE)))
        for u in url_matches:
            u_findings, u_details = self.url_analyzer.analyze(u)
            if u_details.is_shortener:
                findings.append(Finding(
                    rule_id="RULE_MSG_SHORTENED_LINK",
                    title="Shortened Link in SMS Message",
                    severity=Severity.HIGH,
                    weight=50.0,
                    explanation="The message contains a shortened URL (e.g. bit.ly, tinyurl) which conceals the destination domain. Legitimate transactional notifications generally use recognizable brand domains.",
                    evidence=f"Shortened URL: {u}",
                    remediation="Do not open shortened links received via SMS from unknown numbers.",
                    confidence=0.95
                ))
            for uf in u_findings:
                if uf.severity in (Severity.HIGH, Severity.CRITICAL):
                    findings.append(Finding(
                        rule_id=f"MSG_LINK_{uf.rule_id}",
                        title=f"Suspicious Embedded Link: {uf.title}",
                        severity=uf.severity,
                        weight=uf.weight * 0.9,
                        explanation=f"Link found in message triggered a security alert: {uf.explanation}",
                        evidence=f"URL: {u} ({uf.evidence})",
                        remediation=uf.remediation,
                        confidence=uf.confidence
                    ))

        # 6. Check Call-to-action pressure
        urgency_terms = ["immediately", "urgent", "24 hours", "asap", "final notice", "suspended today"]
        found_urgency = [t for t in urgency_terms if t in lower_msg]
        if found_urgency:
            findings.append(Finding(
                rule_id="RULE_MSG_PSYCHOLOGICAL_URGENCY",
                title="High-Pressure Urgency Tactics",
                severity=Severity.MODERATE,
                weight=30.0,
                explanation="The message creates psychological pressure with tight deadlines to coerce an immediate reaction.",
                evidence=f"Urgency indicators: {', '.join(found_urgency)}",
                remediation="Take time to verify the sender through trusted independent channels.",
                confidence=0.85
            ))

        details = MessageDetails(
            message_type=source_hint or "sms",
            char_count=len(message),
            extracted_urls=url_matches,
            urgency_indicators=found_urgency,
            delivery_scam_detected=is_delivery_scam,
            banking_scam_detected=is_banking_scam,
            otp_theft_detected=is_otp_theft,
            suspicious_action_call=len(findings) > 0
        )

        return findings, details
