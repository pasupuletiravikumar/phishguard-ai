import pytest
from app.services.risk_scoring import RiskScoringEngine
from app.schemas.scan import Finding, Severity

def test_zero_findings_score():
    breakdown = RiskScoringEngine.calculate_score([])
    assert breakdown.total_score == 0
    assert breakdown.severity == Severity.LOW
    assert "not definitive proof of safety" in breakdown.important_limitations[1].lower()

def test_single_low_finding():
    finding = Finding(
        rule_id="RULE_TEST_LOW",
        title="Minor Notice",
        severity=Severity.LOW,
        weight=10.0,
        explanation="Test explanation",
        evidence="Test evidence",
        remediation="Test remediation",
        confidence=0.8
    )
    breakdown = RiskScoringEngine.calculate_score([finding])
    assert 1 <= breakdown.total_score <= 24
    assert breakdown.severity == Severity.LOW

def test_critical_anchor_enforcement():
    finding = Finding(
        rule_id="RULE_TEST_CRITICAL",
        title="Critical Brand Impersonation",
        severity=Severity.CRITICAL,
        weight=85.0,
        explanation="Test explanation",
        evidence="Test evidence",
        remediation="Test remediation",
        confidence=0.95
    )
    breakdown = RiskScoringEngine.calculate_score([finding])
    assert breakdown.total_score >= 75
    assert breakdown.severity == Severity.CRITICAL

def test_duplicate_findings_deduplicated():
    finding1 = Finding(
        rule_id="RULE_SAME_ID",
        title="Test Alert",
        severity=Severity.MODERATE,
        weight=30.0,
        explanation="Exp 1",
        evidence="Ev 1",
        remediation="Rem 1"
    )
    finding2 = Finding(
        rule_id="RULE_SAME_ID",
        title="Test Alert",
        severity=Severity.MODERATE,
        weight=30.0,
        explanation="Exp 2",
        evidence="Ev 2",
        remediation="Rem 2"
    )
    b_single = RiskScoringEngine.calculate_score([finding1])
    b_double = RiskScoringEngine.calculate_score([finding1, finding2])
    assert b_single.total_score == b_double.total_score
    assert len(b_double.contributing_findings) == 1

def test_maximum_score_normalization_caps_at_100():
    many_findings = [
        Finding(
            rule_id=f"RULE_{i}",
            title=f"Finding {i}",
            severity=Severity.CRITICAL,
            weight=90.0,
            explanation="Desc",
            evidence="Ev",
            remediation="Rem"
        )
        for i in range(10)
    ]
    breakdown = RiskScoringEngine.calculate_score(many_findings)
    assert breakdown.total_score <= 100
    assert breakdown.severity == Severity.CRITICAL
