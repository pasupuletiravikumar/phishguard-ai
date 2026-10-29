import pytest
from app.services.email_analyzer import EmailAnalyzer
from app.schemas.scan import Severity

@pytest.fixture
def analyzer():
    return EmailAnalyzer()

def test_legitimate_email(analyzer):
    content = "Hi team, please find the agenda for tomorrow's standup meeting attached on the wiki."
    findings, details = analyzer.analyze(content, sender="colleague@company.com", subject="Meeting agenda")
    assert not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
    assert details.urgency_detected is False
    assert details.credential_harvest_detected is False

def test_credential_harvesting_urgent_email(analyzer):
    content = """
    URGENT NOTICE: Your account has been suspended due to unauthorized login attempts.
    You must confirm your password and enter your OTP verification code within 24 hours.
    Click here to verify: http://chase-bank-verify.com/login
    """
    findings, details = analyzer.analyze(
        content,
        sender="Security Department <security@chase-bank-verify.com>",
        subject="URGENT: Account Suspended"
    )
    assert details.urgency_detected is True
    assert details.credential_harvest_detected is True
    assert any(f.rule_id == "RULE_EMAIL_ARTIFICIAL_URGENCY" for f in findings)
    assert any(f.rule_id == "RULE_EMAIL_CREDENTIAL_SOLICITATION" for f in findings)

def test_sender_replyto_mismatch(analyzer):
    content = "Please reply to confirm payment."
    findings, details = analyzer.analyze(
        content,
        sender="billing@trusted-corp.com",
        reply_to="attacker@rogue-mail.cc",
        subject="Invoice inquiry"
    )
    assert any(f.rule_id == "RULE_EMAIL_REPLY_TO_MISMATCH" for f in findings)

def test_display_name_spoofing(analyzer):
    content = "Please review your IT account."
    findings, details = analyzer.analyze(
        content,
        sender="random_user8291@unknown-server.xyz",
        display_name="Microsoft Support Team",
        subject="Security Update"
    )
    assert any(f.rule_id == "RULE_EMAIL_DISPLAY_NAME_SPOOFING" for f in findings)

def test_authentication_header_spf_dmarc_failure(analyzer):
    content = "Dear customer, your statement is ready."
    raw_headers = "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=evil.com; dmarc=fail action=none"
    findings, details = analyzer.analyze(content, raw_headers=raw_headers)
    assert any(f.rule_id == "RULE_EMAIL_SPF_FAIL" for f in findings)
    assert any(f.rule_id == "RULE_EMAIL_DMARC_FAIL" for f in findings)
