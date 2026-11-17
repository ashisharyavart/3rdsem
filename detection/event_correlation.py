"""
CyberGuard Desktop - Multi-Event Correlation Engine
Maintains a rolling time-window of recent screen signals to correlate multi-stage scam flows
(e.g., Fake KYC Notice -> Phishing URL Click -> OTP Solicitation).
"""

import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from config import APP_CONFIG


@dataclass
class TemporalEvent:
    timestamp: float
    categories: List[str]
    score: int
    severity: str
    reasons: List[str]
    domain: Optional[str] = None


class EventCorrelationEngine:
    """
    Correlates recent screen events occurring within a short-lived sliding window
    (default 60s) to identify progressive social engineering and credential harvest workflows.
    """

    def __init__(self, window_sec: int = 60, bonus_multiplier: float = 1.25):
        self.window_sec = window_sec
        self.bonus_multiplier = bonus_multiplier
        self.history: List[TemporalEvent] = []

    def add_event(
        self,
        categories: List[str],
        score: int,
        severity: str,
        reasons: List[str],
        domain: Optional[str] = None
    ) -> Tuple[int, List[str]]:
        """
        Record a detection event and calculate correlated score adjustment.
        Returns:
            (correlated_score: int, correlation_insights: List[str])
        """
        now = time.time()
        self._expire_old(now)

        new_event = TemporalEvent(
            timestamp=now,
            categories=categories,
            score=score,
            severity=severity,
            reasons=reasons,
            domain=domain
        )
        self.history.append(new_event)

        # Correlate across history window
        correlated_score = score
        insights = []

        all_categories = set()
        for ev in self.history:
            all_categories.update(ev.categories)

        # Check for classic Multi-Stage Phishing Sequence:
        # 1. Impersonation or Urgency (e.g. KYC/Bank Alert)
        # 2. Suspicious URL
        # 3. Credential Theft (OTP / PIN / Password)
        has_lure = any(c in all_categories for c in ["Urgency", "Impersonation"])
        has_url = "Suspicious URL" in all_categories
        has_harvest = "Credential Theft" in all_categories

        if len(self.history) >= 2:
            if has_lure and has_url and has_harvest:
                insights.append(
                    "Temporal Correlation: Detected high-risk multi-stage sequence "
                    "(Account Lure -> Verification URL -> Credential/OTP Harvest)."
                )
                correlated_score = min(100, int(score * self.bonus_multiplier + 15))
            elif has_lure and (has_url or has_harvest):
                insights.append(
                    "Temporal Correlation: Detected consecutive threat indicators within recent window."
                )
                correlated_score = min(100, int(score * 1.15 + 5))

        return correlated_score, insights

    def _expire_old(self, current_time: float):
        cutoff = current_time - self.window_sec
        self.history = [ev for ev in self.history if ev.timestamp >= cutoff]

    def clear(self):
        self.history.clear()

