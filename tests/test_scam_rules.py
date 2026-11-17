"""
CyberGuard Desktop - Automated Test Suite for Scam Rules
Tests urgency, impersonation, payment requests, credential theft, fake jobs,
and legitimate messages for false positive prevention.
"""

import pytest
from detection.scam_rules import ScamRuleEngine


@pytest.fixture
def rule_engine():
    return ScamRuleEngine()


def test_urgency_detection(rule_engine):
    text = "Immediate action required: Your account is suspended within 24 hours. Act now!"
    result = rule_engine.analyze(text)
    assert "Urgency" in result.categories
    assert result.category_scores["Urgency"] >= 60.0
    assert any("suspended" in m.indicator.lower() or "act now" in m.indicator.lower() for m in result.matches)


def test_bank_impersonation(rule_engine):
    text = "Dear customer, State Bank account security verification team requires your confirmation."
    result = rule_engine.analyze(text)
    assert "Impersonation" in result.categories
    assert result.category_scores["Impersonation"] >= 50.0


def test_fake_job_payment(rule_engine):
    text = "Congratulations! Guaranteed employment as remote assistant. Pay registration fee of $150 to get the job."
    result = rule_engine.analyze(text)
    assert "Fake Job" in result.categories
    assert "Payment Request" in result.categories
    assert result.category_scores["Payment Request"] >= 50.0


def test_credential_theft_pattern(rule_engine):
    text = "Your KYC verification is pending. Please share your OTP and enter your PIN immediately."
    result = rule_engine.analyze(text)
    assert "Credential Theft" in result.categories
    assert result.category_scores["Credential Theft"] >= 70.0


def test_legitimate_bank_notification(rule_engine):
    # Legitimate message contains warning to NEVER share OTP
    text = "Your one-time password is 492018. Never share your OTP or password with anyone. Bank never calls to ask for OTP."
    result = rule_engine.analyze(text)
    assert result.has_legitimate_context is True
    # Score should be significantly dampened by safety mitigators
    assert result.category_scores["Credential Theft"] <= 35.0


def test_legitimate_job_posting(rule_engine):
    text = "We are hiring a Senior Python Software Engineer. Full-time position, health insurance, 401k match. Apply via our portal."
    result = rule_engine.analyze(text)
    assert "Fake Job" not in result.categories
    assert "Payment Request" not in result.categories
    assert result.category_scores["Payment Request"] == 0.0


def test_empty_input(rule_engine):
    result = rule_engine.analyze("")
    assert len(result.categories) == 0
    assert len(result.matches) == 0
    assert len(result.explanations) == 0

