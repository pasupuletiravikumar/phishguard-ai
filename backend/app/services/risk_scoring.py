import math
from typing import List, Tuple
from app.schemas.scan import Finding, Severity, RiskScoreBreakdown

class RiskScoringEngine:
    """
    Transparent, explainable risk scoring system.
    Scores range from 0 to 100:
      0-24:   LOW RISK
      25-49:  MODERATE RISK
      50-74:  HIGH RISK
      75-100: CRITICAL RISK
    """

    @staticmethod
    def calculate_score(findings: List[Finding]) -> RiskScoreBreakdown:
        if not findings:
            return RiskScoreBreakdown(
                total_score=0,
                severity=Severity.LOW,
                raw_weighted_sum=0.0,
                normalized_score=0.0,
                contributing_findings=[],
                rule_counts_by_severity={"LOW": 0, "MODERATE": 0, "HIGH": 0, "CRITICAL": 0},
                important_limitations=[
                    "No rule matches were triggered by the submitted input.",
                    "A score of zero indicates absence of known heuristic flags, NOT definitive proof of safety.",
                    "Zero-day phishing tactics, newly registered domains, or novel obfuscation may bypass static rules."
                ],
                recommended_actions=[
                    "Continue standard security hygiene.",
                    "Do not share sensitive passwords or two-factor authentication codes unless identity is verified."
                ]
            )

        # Deduplicate findings by rule_id, keeping the highest weight instance
        unique_findings = {}
        for f in findings:
            if f.rule_id not in unique_findings or f.weight > unique_findings[f.rule_id].weight:
                unique_findings[f.rule_id] = f

        deduped_list = list(unique_findings.values())

        # Count by severity
        rule_counts = {"LOW": 0, "MODERATE": 0, "HIGH": 0, "CRITICAL": 0}
        for f in deduped_list:
            rule_counts[f.severity.value] = rule_counts.get(f.severity.value, 0) + 1

        # Calculate using a probabilistic independent risk union formula:
        # P(threat) = 1 - product(1 - p_i) where p_i is the adjusted normalized risk contribution of rule i
        # This prevents linear blowup, naturally caps at 100, and ensures multiple moderate signals accumulate.
        prob_safe = 1.0
        raw_weighted_sum = sum(f.weight * f.confidence for f in deduped_list)

        max_single_weight = 0.0
        for f in deduped_list:
            # Normalized contribution factor between 0.05 and 0.95
            p_i = (f.weight / 100.0) * (0.8 + 0.2 * f.confidence)
            p_i = min(max(p_i, 0.05), 0.95)
            prob_safe *= (1.0 - p_i)
            if f.weight > max_single_weight:
                max_single_weight = f.weight

        combined_risk_ratio = 1.0 - prob_safe
        calculated_score = combined_risk_ratio * 100.0

        # Anchor checks:
        # If any finding is CRITICAL (weight >= 75), the final score cannot be lower than 75
        if rule_counts["CRITICAL"] > 0:
            calculated_score = max(calculated_score, 75.0, max_single_weight)
        # If any finding is HIGH (weight >= 50), the final score cannot be lower than 50
        elif rule_counts["HIGH"] > 0:
            calculated_score = max(calculated_score, 50.0, max_single_weight)
        # If any finding is MODERATE (weight >= 25), the final score cannot be lower than 25
        elif rule_counts["MODERATE"] > 0:
            calculated_score = max(calculated_score, 25.0, max_single_weight)

        final_score = int(round(min(max(calculated_score, 0.0), 100.0)))

        # Determine severity category
        if final_score >= 75:
            severity = Severity.CRITICAL
        elif final_score >= 50:
            severity = Severity.HIGH
        elif final_score >= 25:
            severity = Severity.MODERATE
        else:
            severity = Severity.LOW

        # Generate contextual recommendations
        actions = []
        if severity == Severity.CRITICAL:
            actions.append("IMMEDIATE ACTION: Do not click any links or interact with the sender.")
            actions.append("Never submit passwords, OTPs, or financial information on the target site.")
            actions.append("Block the sender address or domain on your email gateway / firewall.")
            actions.append("Report the incident to your internal SOC or cybersecurity team.")
        elif severity == Severity.HIGH:
            actions.append("Treat this communication with extreme suspicion.")
            actions.append("Verify the claimed organization independently through an official telephone or trusted bookmark.")
            actions.append("Inspect sender domain and SSL certificate validity before proceeding.")
        elif severity == Severity.MODERATE:
            actions.append("Exercise caution: multiple anomaly indicators were observed.")
            actions.append("Check the exact spelling of domain names for subtle typosquatting.")
            actions.append("Avoid providing personal credentials unless authenticity is confirmed.")
        else:
            actions.append("Maintain routine vigilance; verify unexpected requests out-of-band.")

        limitations = [
            "Score is derived from static heuristic indicators and optional machine learning classification.",
            "Dynamic page rendering, cloaking techniques, and multi-stage redirects were not executed to prevent server exploitation.",
            "External reputation services may have propagation latency for newly minted phishing domains."
        ]

        return RiskScoreBreakdown(
            total_score=final_score,
            severity=severity,
            raw_weighted_sum=round(raw_weighted_sum, 2),
            normalized_score=round(calculated_score, 2),
            contributing_findings=sorted(deduped_list, key=lambda x: x.weight, reverse=True),
            rule_counts_by_severity=rule_counts,
            important_limitations=limitations,
            recommended_actions=actions
        )
