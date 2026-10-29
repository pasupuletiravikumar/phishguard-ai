import re
import email
from typing import List, Tuple, Optional, Dict, Any
from app.schemas.scan import Finding, Severity, EmailDetails
from app.services.url_analyzer import UrlAnalyzer

# High urgency social engineering phrases
URGENT_PHRASES = [
    r"urgent[ly]?",
    r"immediate[ly]? action required",
    r"account suspended",
    r"account suspension",
    r"within (?:24|48|12) hours?",
    r"terminate your account",
    r"unauthorized (?:activity|login|access)",
    r"unusual activity detected",
    r"final warning",
    r"action required immediately",
    r"security alert",
    r"failure to respond will result"
]

# Credential harvesting indicators
CREDENTIAL_PHRASES = [
    r"confirm your password",
    r"reset your password",
    r"verify your identity",
    r"enter your (?:pin|otp|passcode)",
    r"verification code",
    r"update your billing (?:info|information)",
    r"login to verify",
    r"credential verification",
    r"re-enter your credentials"
]

# Financial fraud indicators
FINANCIAL_PHRASES = [
    r"wire transfer",
    r"gift card",
    r"bitcoin",
    r"cryptocurrency",
    r"overdue invoice",
    r"remittance advice",
    r"payment pending",
    r"payment received",
    r"bank transfer receipt",
    r"direct deposit",
    r"payroll update"
]

# High-risk attachment references
ATTACHMENT_KEYWORDS = [
    r"\.exe\b", r"\.iso\b", r"\.zip\b", r"\.rar\b", r"\.vbs\b",
    r"\.scr\b", r"\.bat\b", r"\.html\b", r"\.xlsm\b", r"\.docm\b",
    r"attached invoice", r"attached receipt", r"see attachment",
    r"open the attached file"
]

URL_REGEX = re.compile(
    r"(https?://[^\s<>\"\'\(\)]+)",
    re.IGNORECASE
)

EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
)

class EmailAnalyzer:
    """Security analyzer for suspicious emails, header spoofing, and social engineering."""

    def __init__(self):
        self.url_analyzer = UrlAnalyzer()

    def analyze(
        self,
        content: str,
        sender: Optional[str] = None,
        display_name: Optional[str] = None,
        reply_to: Optional[str] = None,
        subject: Optional[str] = None,
        raw_headers: Optional[str] = None
    ) -> Tuple[List[Finding], EmailDetails]:
        findings: List[Finding] = []
        lower_content = content.lower()

        # 1. Parse raw email if it looks like an RFC 822 email message
        headers_parsed: Dict[str, Any] = {}
        if ("from:" in lower_content or "subject:" in lower_content) and not raw_headers:
            try:
                msg = email.message_from_string(content)
                if not sender and msg.get("From"):
                    sender = msg.get("From")
                if not reply_to and msg.get("Reply-To"):
                    reply_to = msg.get("Reply-To")
                if not subject and msg.get("Subject"):
                    subject = msg.get("Subject")
            except Exception:
                pass

        # Parse Authentication-Results or headers if provided
        header_text = (raw_headers or "") + "\n" + content[:1000]
        auth_findings = self._parse_authentication_headers(header_text)
        findings.extend(auth_findings)
        if auth_findings:
            headers_parsed["authentication_results"] = [f.title for f in auth_findings]

        # Extract sender email address from combined sender string if formatted as "Name <email@dom.com>"
        sender_address = None
        sender_domain = None
        if sender:
            addr_match = EMAIL_REGEX.search(sender)
            if addr_match:
                sender_address = addr_match.group(0).lower()
                sender_domain = sender_address.split("@")[-1]
            if not display_name and "<" in sender:
                display_name = sender.split("<")[0].strip().strip('"').strip("'")

        # 2. Sender vs Reply-To Mismatch Check
        if sender_address and reply_to:
            reply_match = EMAIL_REGEX.search(reply_to)
            if reply_match:
                reply_address = reply_match.group(0).lower()
                reply_domain = reply_address.split("@")[-1]
                if sender_domain and reply_domain != sender_domain:
                    findings.append(Finding(
                        rule_id="RULE_EMAIL_REPLY_TO_MISMATCH",
                        title="Sender and Reply-To Domain Mismatch",
                        severity=Severity.HIGH,
                        weight=65.0,
                        explanation=f"The email claims to originate from '@{sender_domain}' but directs responses to '@{reply_domain}'. Threat actors frequently redirect victim replies to rogue inboxes.",
                        evidence=f"From: {sender_address} | Reply-To: {reply_address}",
                        remediation="Do not reply directly. Verify the sender's authentic corporate contact details.",
                        confidence=0.95
                    ))

        # 3. Display Name Spoofing Check
        if display_name and sender_domain:
            target_brands = ["google", "microsoft", "apple", "paypal", "it support", "helpdesk", "admin", "security team"]
            lower_dn = display_name.lower()
            for brand in target_brands:
                if brand in lower_dn and brand.replace(" ", "") not in sender_domain:
                    findings.append(Finding(
                        rule_id="RULE_EMAIL_DISPLAY_NAME_SPOOFING",
                        title=f"Display Name Impersonation ({display_name})",
                        severity=Severity.CRITICAL,
                        weight=80.0,
                        explanation=f"The sender display name masquerades as '{display_name}', but the underlying sender domain is '@{sender_domain}'. This is an executive/service impersonation tactic.",
                        evidence=f"Display Name: '{display_name}' vs Sender: '{sender_address}'",
                        remediation="Flag and report this email immediately. Legitimate providers send from their official domain.",
                        confidence=0.95
                    ))
                    break

        # 4. Urgency and Threat Language Detection
        urgency_matches = []
        combined_text = (subject or "") + "\n" + content
        for pattern in URGENT_PHRASES:
            m = re.findall(pattern, combined_text, re.IGNORECASE)
            if m:
                urgency_matches.extend(m)

        if urgency_matches:
            findings.append(Finding(
                rule_id="RULE_EMAIL_ARTIFICIAL_URGENCY",
                title="Artificial Urgency & Threatening Language",
                severity=Severity.MODERATE if len(urgency_matches) <= 2 else Severity.HIGH,
                weight=30.0 + min(len(urgency_matches) * 10.0, 30.0),
                explanation="The message creates artificial panic or urgency (e.g. threatening imminent account suspension or legal action) to pressure the recipient into bypassing security caution.",
                evidence=f"Urgency phrases matched: {', '.join(set(urgency_matches[:4]))}",
                remediation="Pause and evaluate calmly. Legitimate services do not demand panic actions under tight deadlines.",
                confidence=0.85
            ))

        # 5. Credential Harvesting / Login Verification Lures
        cred_matches = []
        for pattern in CREDENTIAL_PHRASES:
            m = re.findall(pattern, combined_text, re.IGNORECASE)
            if m:
                cred_matches.extend(m)

        if cred_matches:
            findings.append(Finding(
                rule_id="RULE_EMAIL_CREDENTIAL_SOLICITATION",
                title="Credential & Sensitive Verification Solicitation",
                severity=Severity.HIGH,
                weight=60.0,
                explanation="The email solicits passwords, PINs, two-factor authentication codes, or account re-verification.",
                evidence=f"Solicitation phrases: {', '.join(set(cred_matches[:3]))}",
                remediation="Never enter credentials after following an email link. Navigate to the service via a trusted browser bookmark.",
                confidence=0.9
            ))

        # 6. Financial Fraud / Wire Transfer / Crypto Lures
        financial_matches = []
        for pattern in FINANCIAL_PHRASES:
            m = re.findall(pattern, combined_text, re.IGNORECASE)
            if m:
                financial_matches.extend(m)

        if financial_matches:
            findings.append(Finding(
                rule_id="RULE_EMAIL_FINANCIAL_PRESSURE",
                title="Financial Transaction / Wire Transfer / Crypto Request",
                severity=Severity.HIGH,
                weight=55.0,
                explanation="The email requests payment, wire transfers, invoices, or gift card / crypto payments.",
                evidence=f"Financial keywords: {', '.join(set(financial_matches[:3]))}",
                remediation="Verify all payment or bank detail changes via two-person out-of-band authorization.",
                confidence=0.85
            ))

        # 7. High-Risk Attachment References
        attachment_matches = []
        for pattern in ATTACHMENT_KEYWORDS:
            m = re.findall(pattern, combined_text, re.IGNORECASE)
            if m:
                attachment_matches.extend(m)

        if attachment_matches:
            findings.append(Finding(
                rule_id="RULE_EMAIL_SUSPICIOUS_ATTACHMENT_REF",
                title="Suspicious Attachment / Executable Reference",
                severity=Severity.MODERATE,
                weight=35.0,
                explanation="The email mentions attachments or file types (.zip, .iso, .exe, .html) frequently weaponized to deliver malware or HTML smuggling phishing payloads.",
                evidence=f"Attachment terms referenced: {', '.join(set(attachment_matches[:4]))}",
                remediation="Do not download or extract email attachments from unverified senders. Scan in an isolated sandbox.",
                confidence=0.85
            ))

        # 8. Extract and Analyze Embedded URLs
        extracted_urls = list(set(URL_REGEX.findall(content)))
        for u in extracted_urls[:5]:  # Analyze up to top 5 URLs
            u_findings, _ = self.url_analyzer.analyze(u)
            for uf in u_findings:
                # Include high or critical URL findings into email findings
                if uf.severity in (Severity.HIGH, Severity.CRITICAL):
                    findings.append(Finding(
                        rule_id=f"EMAIL_LINK_{uf.rule_id}",
                        title=f"Dangerous Embedded Link: {uf.title}",
                        severity=uf.severity,
                        weight=uf.weight * 0.9,
                        explanation=f"An embedded link in the email triggered a security alert: {uf.explanation}",
                        evidence=f"Link '{u}': {uf.evidence}",
                        remediation=uf.remediation,
                        confidence=uf.confidence
                    ))

        # Compile email details
        details = EmailDetails(
            sender=sender_address or sender,
            sender_domain=sender_domain,
            display_name=display_name,
            reply_to=reply_to,
            subject=subject,
            extracted_urls=extracted_urls,
            suspicious_keywords=list(set(urgency_matches + cred_matches + financial_matches)),
            urgency_detected=len(urgency_matches) > 0,
            credential_harvest_detected=len(cred_matches) > 0,
            financial_fraud_detected=len(financial_matches) > 0,
            attachments_referenced=list(set(attachment_matches)),
            spoofing_indicators=[f.title for f in findings if "Spoofing" in f.title or "Mismatch" in f.title],
            headers_parsed=headers_parsed
        )

        return findings, details

    def _parse_authentication_headers(self, text: str) -> List[Finding]:
        """Parses SPF, DKIM, and DMARC results from supplied email headers."""
        findings = []
        lower = text.lower()
        if "spf=fail" in lower or "spf=softfail" in lower:
            findings.append(Finding(
                rule_id="RULE_EMAIL_SPF_FAIL",
                title="SPF Authentication Failure (Supplied Header)",
                severity=Severity.HIGH,
                weight=60.0,
                explanation="The supplied email headers indicate that the sending mail server is not authorized to send email on behalf of the domain (SPF failed).",
                evidence="Authentication-Results: spf=fail/softfail detected in provided text",
                remediation="Treat the email as potentially forged or spoofed.",
                confidence=0.9
            ))
        elif "spf=pass" in lower:
            # Documented clean header indicator
            pass

        if "dmarc=fail" in lower:
            findings.append(Finding(
                rule_id="RULE_EMAIL_DMARC_FAIL",
                title="DMARC Policy Failure (Supplied Header)",
                severity=Severity.CRITICAL,
                weight=75.0,
                explanation="The supplied email headers show that DMARC alignment failed, indicating that neither SPF nor DKIM could authenticate the message from the claimed domain.",
                evidence="Authentication-Results: dmarc=fail detected in provided text",
                remediation="Reject or quarantine the message.",
                confidence=0.95
            ))

        if "dkim=fail" in lower:
            findings.append(Finding(
                rule_id="RULE_EMAIL_DKIM_FAIL",
                title="DKIM Cryptographic Signature Failure",
                severity=Severity.MODERATE,
                weight=40.0,
                explanation="The cryptographic DKIM signature failed verification, suggesting message tampering or header manipulation in transit.",
                evidence="Authentication-Results: dkim=fail detected in provided text",
                remediation="Verify origin through secondary trusted channel.",
                confidence=0.9
            ))

        return findings
