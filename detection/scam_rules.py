"""
CyberGuard Desktop - Rule-Based Scam & Social Engineering Detection Engine
Evaluates contextual patterns of urgency, impersonation, financial fraud,
credential theft, and fake jobs with false-positive mitigation.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple


@dataclass
class RuleMatch:
    category: str
    indicator: str
    explanation: str
    weight: float  # 0.0 to 100.0


@dataclass
class RuleDetectionResult:
    categories: List[str]
    matches: List[RuleMatch]
    category_scores: Dict[str, float]  # 0 to 100 per category
    explanations: List[str]
    has_legitimate_context: bool = False


class ScamRuleEngine:
    """
    Modular rule engine that inspects normalized text for scam indicators,
    co-occurring malicious vectors, and legitimate safety warnings.
    """

    def __init__(self):
        self._compile_rules()

    def _compile_rules(self):
        # 1. URGENCY PATTERNS
        self.urgency_patterns = [
            (re.compile(r"\b(urgent|urgently|immediate|immediately|act now|right now|without delay)\b", re.IGNORECASE),
             "High urgency trigger", 45.0),
            (re.compile(r"\b(account (?:has been |is |will be |to be )?(?:suspended|blocked|frozen|locked|terminated|restricted|compromised)|account suspension|avoid suspension)\b", re.IGNORECASE),
             "Account suspension threat", 70.0),
            (re.compile(r"\b(last warning|final notice|final warning|within 24 hours|within \d+ hours)\b", re.IGNORECASE),
             "Artificial time constraint/deadline", 60.0),
            (re.compile(r"\b(expired today|expires today|has expired|expiring soon|valid only for today)\b", re.IGNORECASE),
             "Expiring urgency inducement", 50.0),
            (re.compile(r"\b(urgent verification|immediate action required|action required urgently)\b", re.IGNORECASE),
             "Urgent action demand", 65.0),
        ]

        # 2. IMPERSONATION PATTERNS
        self.impersonation_patterns = [
            # Bank impersonation
            (re.compile(r"\b(?:bank|banking|credit union)\s+(?:[a-z]+\s+){0,2}(?:account|security|alert|verification|update|support|team)\b", re.IGNORECASE),
             "Bank impersonation / verification notice", 65.0),
            (re.compile(r"\b(state bank|hdfc|icici|chase|wells fargo|bank of america|barclays|citi)\b", re.IGNORECASE),
             "Major banking institution mention", 35.0),
            # Family emergency / WhatsApp scam impersonation
            (re.compile(r"\b(hi mom|hi dad|hello mom|hello dad|lost my phone|temporary number|new phone number|phone broke)\b", re.IGNORECASE),
             "Family emergency / trusted contact impersonation lure", 70.0),
            # Government impersonation
            (re.compile(r"\b(income tax|irs|tax department|law enforcement|federal police|customs office|judiciary)\b", re.IGNORECASE),
             "Government agency impersonation", 75.0),
            # Courier / Parcel delivery
            (re.compile(r"\b(fedex|dhl|ups|postal service|usps|blue dart|courier delivery|parcel pending|customs fee for package)\b", re.IGNORECASE),
             "Courier / parcel delivery impersonation", 60.0),
            # Tech support
            (re.compile(r"\b(microsoft support|apple support|windows security center|tech support|geek squad)\b", re.IGNORECASE),
             "Tech support impersonation", 70.0),
            # Executive / HR authority
            (re.compile(r"\b(ceo|hr department|payroll director)\s+(?:needs|requires|requested)\b", re.IGNORECASE),
             "Executive / HR authority impersonation", 50.0),
        ]

        # 3. FINANCIAL FRAUD & SUSPICIOUS PAYMENTS
        self.financial_patterns = [
            (re.compile(r"\b(advance payment|processing fee|clearance fee|handling fee|registration fee|refundable deposit)\b", re.IGNORECASE),
             "Advance fee / registration charge request", 70.0),
            (re.compile(r"\b(guaranteed returns?|100% risk[- ]free|double your money|daily profit|crypto investment scheme)\b", re.IGNORECASE),
             "Unrealistic investment promise / high-yield scam", 80.0),
            (re.compile(r"\b(transfer\s+(?:(?:\$|€|£|₹)?\d+|money|funds|crypto|cash)|send\s+(?:(?:\$|€|£|₹)?\d+|money|crypto|cash|funds)|pay (?:a\s+)?(?:bill|fee))\b", re.IGNORECASE),
             "Direct fund transfer / payment solicitation", 70.0),
            (re.compile(r"\b(buy (?:apple|google play|amazon|steam) gift cards?)\b", re.IGNORECASE),
             "Gift card payment mechanism (common scam vector)", 90.0),
            (re.compile(r"\b(lottery winner|you have won|prize award|jackpot winner|selected for award)\b", re.IGNORECASE),
             "Prize or lottery scam lure", 85.0),
        ]

        # 4. CREDENTIAL THEFT & SENSITIVE VERIFICATION
        self.credential_patterns = [
            (re.compile(r"\b(enter|share|provide|verify|send|submit)\s+(?:your\s+)?(otp|one[- ]time[- ]password|sms code|verification code)\b", re.IGNORECASE),
             "Solicitation of OTP / One-Time Passcode", 85.0),
            (re.compile(r"\b(enter|provide|send)\s+(?:your\s+)?(pin|atm pin|cvv|security code|mpin)\b", re.IGNORECASE),
             "Request for payment PIN or CVV", 90.0),
            (re.compile(r"\b(enter|verify|confirm)\s+(?:your\s+)?(password|login credentials)\b", re.IGNORECASE),
             "Password harvesting request", 75.0),
            (re.compile(r"\b(kyc (?:verification|update|expired|mandatory|pending)|update your kyc)\b", re.IGNORECASE),
             "Urgent KYC verification lure", 75.0),
            (re.compile(r"\b(click (?:the )?(?:link|here) to (?:verify|unblock|activate|restore|update))\b", re.IGNORECASE),
             "Deceptive link action to verify account", 70.0),
        ]

        # 5. FAKE JOB OPPORTUNITIES
        self.job_patterns = [
            (re.compile(r"\b(?:pay|send|transfer)\s+(?:a\s+)?(?:registration fee|kit fee|training fee|processing fee)\s+(?:for|to get)\s+(?:the\s+)?job\b", re.IGNORECASE),
             "Job contingent on upfront payment", 90.0),
            (re.compile(r"\b(guaranteed employment|job guaranteed|guaranteed selection|no interview needed)\b", re.IGNORECASE),
             "Guaranteed employment claim", 65.0),
            (re.compile(r"\b(earn \$?\d{3,5}\s*(?:daily|per day|hourly|per hour)|(?:daily|hourly)\s+profit)\b", re.IGNORECASE),
             "Unrealistic work-from-home compensation", 75.0),
            (re.compile(r"\b(starter kit|kit fee|training kit fee)\b", re.IGNORECASE),
             "Starter kit purchase requirement for employment", 70.0),
        ]

        # 6. LEGITIMATE SAFETY CONTEXT (False Positive Mitigators)
        self.legitimate_mitigators = [
            re.compile(r"\b(never share your (?:otp|pin|password)|do not share (?:this )?(?:otp|code|pin)|bank never calls to ask for otp|bank never asks for confidential details)\b", re.IGNORECASE),
            re.compile(r"\b(if this was not you|if not you,? call|contact fraud department|report fraud)\b", re.IGNORECASE),
            re.compile(r"\b(two[- ]factor authentication is enabled|security alert: new login)\b", re.IGNORECASE),
        ]

    def analyze(self, text: str) -> RuleDetectionResult:
        if not text or len(text.strip()) < 5:
            return RuleDetectionResult(
                categories=[], matches=[], category_scores={}, explanations=[]
            )

        matches: List[RuleMatch] = []
        category_scores: Dict[str, float] = {
            "Urgency": 0.0,
            "Impersonation": 0.0,
            "Payment Request": 0.0,
            "Credential Theft": 0.0,
            "Fake Job": 0.0
        }

        # Check for legitimate bank advisory language that warns user NOT to share
        has_legitimate_context = False
        for mitigator in self.legitimate_mitigators:
            if mitigator.search(text):
                has_legitimate_context = True
                break

        # A. Evaluate Urgency
        for pat, desc, score in self.urgency_patterns:
            m = pat.search(text)
            if m:
                matches.append(RuleMatch("Urgency", m.group(0), desc, score))
                category_scores["Urgency"] = min(100.0, category_scores["Urgency"] + score)

        # B. Evaluate Impersonation
        for pat, desc, score in self.impersonation_patterns:
            m = pat.search(text)
            if m:
                matches.append(RuleMatch("Impersonation", m.group(0), desc, score))
                category_scores["Impersonation"] = min(100.0, category_scores["Impersonation"] + score)

        # C. Evaluate Financial Fraud
        for pat, desc, score in self.financial_patterns:
            m = pat.search(text)
            if m:
                matches.append(RuleMatch("Payment Request", m.group(0), desc, score))
                category_scores["Payment Request"] = min(100.0, category_scores["Payment Request"] + score)

        # D. Evaluate Credential Theft
        for pat, desc, score in self.credential_patterns:
            m = pat.search(text)
            if m:
                matches.append(RuleMatch("Credential Theft", m.group(0), desc, score))
                category_scores["Credential Theft"] = min(100.0, category_scores["Credential Theft"] + score)

        # E. Evaluate Fake Jobs
        for pat, desc, score in self.job_patterns:
            m = pat.search(text)
            if m:
                matches.append(RuleMatch("Fake Job", m.group(0), desc, score))
                category_scores["Fake Job"] = min(100.0, category_scores["Fake Job"] + score)

        # Map Fake Job into Impersonation (Fake employer/recruiter lure)
        if category_scores["Fake Job"] > 0:
            category_scores["Impersonation"] = min(100.0, max(category_scores["Impersonation"], category_scores["Fake Job"]))

        # Apply False Positive Mitigations
        if has_legitimate_context:
            category_scores["Credential Theft"] = max(0.0, category_scores["Credential Theft"] - 65.0)
            category_scores["Impersonation"] = max(0.0, category_scores["Impersonation"] - 45.0)
            category_scores["Urgency"] = max(0.0, category_scores["Urgency"] - 30.0)

        # Contextual Combinations:
        if category_scores["Fake Job"] >= 30.0 and category_scores["Payment Request"] >= 30.0:
            category_scores["Payment Request"] = min(100.0, category_scores["Payment Request"] + 30.0)

        # Determine active categories (where score >= 25)
        active_cats = [cat for cat, sc in category_scores.items() if sc >= 25.0]

        # Build explanations
        explanations = []
        for match in matches:
            expl = f"{match.category}: '{match.indicator}' ({match.explanation})"
            if expl not in explanations:
                explanations.append(expl)

        if has_legitimate_context:
            explanations.append("Context Note: Contains safety advisory language (e.g., 'Never share OTP').")

        return RuleDetectionResult(
            categories=active_cats,
            matches=matches,
            category_scores=category_scores,
            explanations=explanations,
            has_legitimate_context=has_legitimate_context
        )
