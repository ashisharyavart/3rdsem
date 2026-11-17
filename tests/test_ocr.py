"""
CyberGuard Desktop - Automated Test Suite for OCR Engine & Text Processing
Tests text cleaning, whitespace normalization, empty buffer handling,
missing Tesseract handling, and privacy redaction.
"""

import pytest
import numpy as np
from monitoring.ocr_engine import OCREngine, OCRResult
from utils.text_cleaner import clean_ocr_text
from utils.privacy import redact_sensitive_info


def test_text_cleaner_whitespace():
    raw = "  URGENT:   Verify   your   account   now.  \n\n\n\nVisit:   https://example.com  "
    cleaned = clean_ocr_text(raw)
    assert "URGENT: Verify your account now." in cleaned
    assert "https://example.com" in cleaned
    assert "\n\n\n" not in cleaned


def test_text_cleaner_noise():
    raw = "Valid line 1\n~\n^\nValid line 2"
    cleaned = clean_ocr_text(raw)
    assert "Valid line 1" in cleaned
    assert "Valid line 2" in cleaned
    assert "~" not in cleaned


def test_ocr_empty_image():
    engine = OCREngine(tesseract_cmd="dummy_nonexistent_path.exe")
    # Missing tesseract should return clean error without throwing exception
    res = engine.extract_text(np.zeros((100, 100, 3), dtype=np.uint8))
    assert res.is_available is False
    assert "Tesseract OCR is not installed or configured" in res.error_message


def test_privacy_redaction():
    text = "User otp: 849201 entered. Card 4532-1234-5678-9012 verified. password: secretPassword!"
    redacted = redact_sensitive_info(text)
    assert "849201" not in redacted
    assert "[REDACTED]" in redacted
    assert "4532-1234-5678-9012" not in redacted
    assert "[REDACTED-CARD]" in redacted
    assert "secretPassword!" not in redacted
    assert "[REDACTED-PWD]" in redacted

