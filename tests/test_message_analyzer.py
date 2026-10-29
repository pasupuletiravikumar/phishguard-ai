import pytest
from app.services.message_analyzer import MessageAnalyzer
from app.schemas.scan import Severity

@pytest.fixture
def analyzer():
    return MessageAnalyzer()

def test_legitimate_sms(analyzer):
    msg = "Hi Dad, I will be home by 6 PM for dinner."
    findings, details = analyzer.analyze(msg)
    assert not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
    assert details.delivery_scam_detected is False
    assert details.banking_scam_detected is False

def test_postal_delivery_smishing(analyzer):
    msg = "USPS: Your package could not be delivered due to incomplete address. Please update address and pay redelivery fee: http://usps-redelivery.info/pay"
    findings, details = analyzer.analyze(msg)
    assert details.delivery_scam_detected is True
    assert any(f.rule_id == "RULE_MSG_DELIVERY_SMISHING" for f in findings)

def test_banking_fraud_smishing(analyzer):
    msg = "Chase Bank Alert: Suspicious transaction detected. Your debit card is locked. Call immediately or verify: http://chase-security-check.net"
    findings, details = analyzer.analyze(msg)
    assert details.banking_scam_detected is True
    assert any(f.rule_id == "RULE_MSG_BANKING_SMISHING" for f in findings)

def test_otp_theft_attempt(analyzer):
    msg = "Do not share this OTP with anyone. Your verification code is 849201. Click here to confirm authorization: http://secure-login-token.cc/otp"
    findings, details = analyzer.analyze(msg)
    assert details.otp_theft_detected is True
    assert any(f.rule_id == "RULE_MSG_OTP_INTERCEPTION" for f in findings)

def test_family_emergency_scam(analyzer):
    msg = "Hey Mom, I lost my phone and this is my new number. I have an emergency and need urgent money for rent."
    findings, details = analyzer.analyze(msg)
    assert any(f.rule_id == "RULE_MSG_FAMILY_IMPERSONATION" for f in findings)
