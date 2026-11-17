"""
CyberGuard Desktop - Automated Test Suite for Risk Scoring and Event Correlation
Tests score boundaries, weighted formulas, compound bonuses, and temporal correlation.
"""

import pytest
from config import CyberGuardConfig
from detection.scam_rules import RuleDetectionResult, RuleMatch
from detection.url_analyzer import URLAnalysisResult, URLIndicator
from detection.risk_engine import RiskEngine
from detection.event_correlation import EventCorrelationEngine


@pytest.fixture
def risk_engine():
    config = CyberGuardConfig(
        weight_urgency=0.30,
        weight_payment=0.25,
        weight_impersonation=0.20,
        weight_url_risk=0.15,
        weight_credential_theft=0.10
    )
    return RiskEngine(config=config)


def test_clean_input_low_risk(risk_engine):
    rule_res = RuleDetectionResult(
        categories=[],
        matches=[],
        category_scores={"Urgency": 0.0, "Payment Request": 0.0, "Impersonation": 0.0, "Credential Theft": 0.0},
        explanations=[]
    )
    risk_res = risk_engine.calculate_risk(rule_res, [])
    assert risk_res.score == 0
    assert risk_res.severity == "Low"


def test_suspicious_boundary(risk_engine):
    # Only moderate urgency: 0.30 * 100 = 30 -> Suspicious
    rule_res = RuleDetectionResult(
        categories=["Urgency"],
        matches=[RuleMatch("Urgency", "urgent", "test", 100.0)],
        category_scores={"Urgency": 100.0, "Payment Request": 0.0, "Impersonation": 0.0, "Credential Theft": 0.0},
        explanations=["Urgency detected"]
    )
    risk_res = risk_engine.calculate_risk(rule_res, [])
    assert 30 <= risk_res.score <= 35
    assert risk_res.severity == "Suspicious"


def test_critical_boundary(risk_engine):
    # All components active: Urgency (100), Payment (100), Impersonation (100), Credential (100)
    rule_res = RuleDetectionResult(
        categories=["Urgency", "Payment Request", "Impersonation", "Credential Theft"],
        matches=[],
        category_scores={
            "Urgency": 100.0,
            "Payment Request": 100.0,
            "Impersonation": 100.0,
            "Credential Theft": 100.0
        },
        explanations=["Critical scam indicators"]
    )
    url_res = [
        URLAnalysisResult(
            url="http://192.168.1.1/pay",
            domain="192.168.1.1",
            risk_score=90.0,
            is_suspicious=True,
            indicators=[],
            explanations=[]
        )
    ]
    risk_res = risk_engine.calculate_risk(rule_res, url_res)
    assert risk_res.score >= 80
    assert risk_res.severity == "Critical"


def test_event_correlation_sequence():
    engine = EventCorrelationEngine(window_sec=60, bonus_multiplier=1.25)
    
    # Event 1: Bank KYC notification
    s1, ins1 = engine.add_event(
        categories=["Urgency", "Impersonation"],
        score=45,
        severity="Suspicious",
        reasons=["KYC notice"]
    )
    assert len(ins1) == 0

    # Event 2: Suspicious URL
    s2, ins2 = engine.add_event(
        categories=["Suspicious URL"],
        score=50,
        severity="Suspicious",
        reasons=["Shortened URL"]
    )
    assert any("Temporal Correlation" in i for i in ins2)

    # Event 3: OTP request page
    s3, ins3 = engine.add_event(
        categories=["Credential Theft"],
        score=65,
        severity="High",
        reasons=["OTP requested"]
    )
    # Compound sequence trigger
    assert any("multi-stage sequence" in i for i in ins3)
    assert s3 > 65

