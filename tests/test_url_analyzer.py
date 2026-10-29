import pytest
from app.services.url_analyzer import UrlAnalyzer
from app.schemas.scan import Severity

@pytest.fixture
def analyzer():
    return UrlAnalyzer()

def test_benign_url(analyzer):
    findings, details = analyzer.analyze("https://www.google.com/")
    assert details.hostname == "www.google.com"
    assert details.is_ip_address is False
    assert details.has_credentials_in_url is False
    assert details.is_punycode is False
    assert details.scheme == "https"
    # Should have no critical or high findings
    assert not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)

def test_ip_address_host(analyzer):
    findings, details = analyzer.analyze("http://192.168.1.100/login")
    assert details.is_ip_address is True
    assert any(f.rule_id == "RULE_URL_IP_HOST" for f in findings)

def test_excessive_subdomains(analyzer):
    findings, details = analyzer.analyze("http://secure.account.billing.update.bank.com.attacker.com/auth")
    assert len(details.subdomains) >= 3
    assert any(f.rule_id == "RULE_URL_EXCESSIVE_SUBDOMAINS" for f in findings)

def test_at_symbol_credentials(analyzer):
    findings, details = analyzer.analyze("http://user:password123@legit-site.com.attacker.net/login")
    assert details.has_credentials_in_url is True
    assert any(f.rule_id == "RULE_URL_EMBEDDED_CREDENTIALS" for f in findings)

def test_punycode_homograph(analyzer):
    findings, details = analyzer.analyze("https://xn--gogle-qqa.com/login")
    assert details.is_punycode is True
    assert any(f.rule_id == "RULE_URL_PUNYCODE_HOMOGRAPH" for f in findings)

def test_url_shortener(analyzer):
    findings, details = analyzer.analyze("https://bit.ly/3xSecAlertUrgent")
    assert details.is_shortener is True
    assert any(f.rule_id == "RULE_URL_SHORTENER_DETECTED" for f in findings)

def test_missing_scheme_handled_gracefully(analyzer):
    findings, details = analyzer.analyze("example.com/test-path")
    assert any(f.rule_id == "RULE_URL_MISSING_SCHEME" for f in findings)
    assert details.hostname == "example.com"

def test_typosquatting_brand_lookalike(analyzer):
    findings, details = analyzer.analyze("http://paypa1-security-verification.com/login")
    assert details.lookalike_target == "paypal"
    assert any(f.rule_id == "RULE_URL_TYPOSQUATTING_LOOKALIKE" for f in findings)

def test_extremely_long_url(analyzer):
    long_url = "https://example.com/login?token=" + "A" * 150
    findings, details = analyzer.analyze(long_url)
    assert any(f.rule_id == "RULE_URL_EXCESSIVE_LENGTH" for f in findings)
