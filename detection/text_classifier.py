"""
CyberGuard Desktop - Optional Machine Learning Text Classifier
Provides an optional, local TF-IDF + LogisticRegression baseline classifier.
Per Section 15, defaults to disabled without external dependencies or fabricated data.
The rule-based detection engine remains the primary, fully functional system.
"""

from typing import Optional, Tuple
import os
from pathlib import Path


class OptionalTextClassifier:
    """
    Optional secondary ML classifier using scikit-learn TF-IDF + Logistic Regression.
    Explicitly disabled by default due to strict 48-hour local privacy requirements
    and lack of certified client-specific labeled training data.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.is_enabled = False
        self.model_path = model_path
        self.pipeline = None
        self._load_if_available()

    def _load_if_available(self):
        if self.model_path and os.path.isfile(self.model_path):
            try:
                import joblib
                self.pipeline = joblib.load(self.model_path)
                self.is_enabled = True
            except Exception:
                self.is_enabled = False

    def predict(self, text: str) -> Tuple[bool, float]:
        """
        Returns (is_scam: bool, confidence: float).
        Returns (False, 0.0) when classifier is not active.
        """
        if not self.is_enabled or self.pipeline is None or not text:
            return False, 0.0

        try:
            proba = self.pipeline.predict_proba([text])[0][1]
            return proba >= 0.5, float(proba)
        except Exception:
            return False, 0.0

