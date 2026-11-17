"""
CyberGuard Desktop - Weighted Explainable Risk Scoring Engine
Implements the formula:
Risk = 0.30U + 0.25P + 0.20I + 0.15L + 0.10C
Where U=Urgency, P=Payment, I=Impersonation, L=URL Risk, C=Credential Theft.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from config import APP_CONFIG, CyberGuardConfig
from detection.scam_rules import RuleDetectionResult
from detection.url_analyzer import URLAnalysisResult


@dataclass
class RiskEvaluationResult:
    score: int                           # 0 to 100 integer
    severity: str                        # Low, Suspicious, High, Critical
    detected_categories: List[str]
    reasons: List[str]
    component_scores: Dict[str, float]   # Raw U, P, I, L, C values (0-100)
    uncertainty_description: str
    highest_risk_url: Optional[str] = None
    extracted_domain: Optional[str] = None


class RiskEngine:
    """
    Combines rule matching scores and URL heuristic scores into an explainable,
    normalized risk score between 0 and 100.
    """

    def __init__(self, config: CyberGuardConfig = APP_CONFIG):
        self.config = config

    def calculate_risk(
        self,
        rule_result: RuleDetectionResult,
        url_results: List[URLAnalysisResult]
    ) -> RiskEvaluationResult:
        """
        Calculates composite risk based on modular components.
        """
        # 1. Extract component scores (0 to 100)
        u_score = min(100.0, max(0.0, rule_result.category_scores.get("Urgency", 0.0)))
        p_score = min(100.0, max(0.0, rule_result.category_scores.get("Payment Request", 0.0)))
        i_score = min(100.0, max(0.0, rule_result.category_scores.get("Impersonation", 0.0)))
        c_score = min(100.0, max(0.0, rule_result.category_scores.get("Credential Theft", 0.0)))

        # L = URL Risk: Take the maximum risk among all found URLs
        l_score = 0.0
        highest_url = None
        extracted_domain = None
        url_reasons = []

        if url_results:
            for ur in url_results:
                if ur.risk_score > l_score:
                    l_score = ur.risk_score
                    highest_url = ur.url
                    extracted_domain = ur.domain
                url_reasons.extend(ur.explanations)

        # Weighted calculation
        # Risk = 0.30U + 0.25P + 0.20I + 0.15L + 0.10C
        w_u = self.config.weight_urgency
        w_p = self.config.weight_payment
        w_i = self.config.weight_impersonation
        w_l = self.config.weight_url_risk
        w_c = self.config.weight_credential_theft

        raw_score = (
            (w_u * u_score) +
            (w_p * p_score) +
            (w_i * i_score) +
            (w_l * l_score) +
            (w_c * c_score)
        )

        # Compound bonus: When multiple severe attack vectors co-occur
        # e.g. Urgent Impersonation with Suspicious URL & Credential Harvesting
        severe_vectors = sum(1 for val in [u_score, p_score, i_score, l_score, c_score] if val >= 50.0)
        if severe_vectors >= 3:
            raw_score = min(100.0, raw_score * 1.20)
        elif severe_vectors >= 2:
            raw_score = min(100.0, raw_score * 1.10)

        # Clamp score between 0 and 100
        score = int(round(min(100.0, max(0.0, raw_score))))

        # Categorize Severity:
        # 0–29: Low
        # 30–59: Suspicious
        # 60–79: High
        # 80–100: Critical
        if score >= 80:
            severity = "Critical"
        elif score >= 60:
            severity = "High"
        elif score >= 30:
            severity = "Suspicious"
        else:
            severity = "Low"

        # Combine all reasons without duplicates
        all_reasons = []
        for r in rule_result.explanations:
            if r not in all_reasons:
                all_reasons.append(r)
        for r in url_reasons:
            if r not in all_reasons:
                all_reasons.append(r)

        # Determine active detected categories
        detected_cats = list(rule_result.categories)
        if l_score >= 35.0 and "Suspicious URL" not in detected_cats:
            detected_cats.append("Suspicious URL")

        # Uncertainty description
        if not detected_cats:
            uncertainty = "High confidence: No anomalous phishing or scam indicators observed."
        elif len(detected_cats) == 1:
            uncertainty = "Moderate uncertainty: Single indicator triggered; benign context cannot be excluded."
        else:
            uncertainty = f"Elevated confidence: {len(detected_cats)} convergent indicators identified."

        return RiskEvaluationResult(
            score=score,
            severity=severity,
            detected_categories=detected_cats,
            reasons=all_reasons,
            component_scores={
                "Urgency": u_score,
                "Payment": p_score,
                "Impersonation": i_score,
                "URL_Risk": l_score,
                "Credential_Theft": c_score
            },
            uncertainty_description=uncertainty,
            highest_risk_url=highest_url,
            extracted_domain=extracted_domain
        )

