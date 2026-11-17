"""
CyberGuard Desktop - Labeled Scenario Test Suite
Evaluates the 6 required college project scenarios:
1. WhatsApp-style scam message
2. Fake bank KYC message
3. Suspicious investment advertisement
4. Fake job requiring an upfront fee
5. Legitimate banking notification
6. Normal website with no suspicious content
"""

import pytest
from detection.scam_rules import ScamRuleEngine
from detection.url_analyzer import URLAnalyzer
from detection.risk_engine import RiskEngine
from config import APP_CONFIG


@pytest.fixture
def pipeline():
    return {
        "rules": ScamRuleEngine(),
        "url": URLAnalyzer(),
        "risk": RiskEngine(config=APP_CONFIG)
    }


def evaluate(pipeline, text: str):
    rule_res = pipeline["rules"].analyze(text)
    url_res = pipeline["url"].analyze_all(text)
    risk_res = pipeline["risk"].calculate_risk(rule_res, url_res)
    return risk_res


# 1. WhatsApp-style scam message
def test_scenario_whatsapp_scam(pipeline):
    text = (
        "URGENT: Hi Mom, my phone broke and I am using this temporary number. "
        "I need to pay a bill right now or my account will be blocked. "
        "Please transfer $450 immediately to http://bit.ly/quick-send-fund"
    )
    res = evaluate(pipeline, text)
    assert res.score >= 60
    assert res.severity in ["High", "Critical"]
    assert "Urgency" in res.detected_categories or "Payment Request" in res.detected_categories


# 2. Fake bank KYC message
def test_scenario_fake_bank_kyc(pipeline):
    text = (
        "Dear State Bank customer, your KYC verification has expired today. "
        "To avoid account suspension, click here to update: "
        "http://192.168.1.45/sbi/verify-login and enter your OTP."
    )
    res = evaluate(pipeline, text)
    assert res.score >= 70
    assert res.severity in ["High", "Critical"]
    assert "Credential Theft" in res.detected_categories
    assert "Suspicious URL" in res.detected_categories


# 3. Suspicious investment advertisement
def test_scenario_suspicious_investment(pipeline):
    text = (
        "Exclusive opportunity: Guaranteed returns of 25% daily! "
        "100% risk-free crypto investment scheme. Double your money within 48 hours. "
        "Send crypto to http://guaranteed-profit.crypto-growth.xyz/invest"
    )
    res = evaluate(pipeline, text)
    assert res.score >= 50
    assert res.severity in ["Suspicious", "High", "Critical"]
    assert "Payment Request" in res.detected_categories


# 4. Fake job requiring upfront fee
def test_scenario_fake_job_fee(pipeline):
    text = (
        "Hiring immediate remote assistants! Guaranteed employment with $500 daily profit. "
        "Pay registration fee of $99 for the starter kit before you can start working."
    )
    res = evaluate(pipeline, text)
    assert res.score >= 55
    assert res.severity in ["Suspicious", "High", "Critical"]
    assert "Payment Request" in res.detected_categories
    assert "Fake Job" in res.detected_categories


# 5. Legitimate banking notification
def test_scenario_legitimate_bank(pipeline):
    text = (
        "HDFC Bank Alert: Rs. 1,500 debited from A/C **4921 at 14:20. "
        "If this was not you, call 1800-202-6161. Never share your OTP or password with anyone. "
        "Bank never asks for confidential details."
    )
    res = evaluate(pipeline, text)
    # Must NOT be flagged as high/critical fraud!
    assert res.score < 30
    assert res.severity == "Low"


# 6. Normal website with no suspicious content
def test_scenario_normal_website(pipeline):
    text = (
        "Python is a high-level, general-purpose programming language. "
        "Its design philosophy emphasizes code readability with the use of significant indentation. "
        "Documentation available at https://docs.python.org/3/"
    )
    res = evaluate(pipeline, text)
    assert res.score < 20
    assert res.severity == "Low"
    assert len(res.detected_categories) == 0

