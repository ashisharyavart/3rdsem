"""
CyberGuard Desktop - Privacy Safeguards and Window Exclusions
Ensures strict local-only execution, credential redaction, and sensitive application exclusion.
"""

import re
import sys
from typing import List, Optional

# Regular expressions for masking sensitive data before displaying or storing
CREDENTIAL_PATTERNS = [
    # Common OTP formats (e.g., OTP: 123456 or code: 9876)
    (re.compile(r"\b(otp|code|pin|token|one[- ]time[- ]password)\s*[:=\-]?\s*([0-9]{4,8})\b", re.IGNORECASE), r"\1: [REDACTED]"),
    # Credit Card numbers (simple 16-digit or 4x4 digit groups)
    (re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"), "[REDACTED-CARD]"),
    # Passwords in plain text contexts
    (re.compile(r"\b(password|passwd|pwd)\s*[:=]\s*(\S+)", re.IGNORECASE), r"\1: [REDACTED-PWD]"),
    # Bank Account numbers (typically 9-18 digits isolated)
    (re.compile(r"\b(account|acct|a/c)\s*#?\s*[:=]?\s*([0-9]{9,18})\b", re.IGNORECASE), r"\1: [REDACTED-ACCT]"),
]


def redact_sensitive_info(text: str) -> str:
    """
    Scrub identifiable credential fragments (OTPs, PINs, Passwords, Card numbers)
    from extracted text to protect user privacy.
    """
    if not text:
        return ""
    sanitized = text
    for pattern, replacement in CREDENTIAL_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def get_active_window_title() -> Optional[str]:
    """
    Retrieve the title of the currently focused/foreground window on Windows.
    Returns None if unavailable or on non-Windows platforms.
    """
    if sys.platform != "win32":
        return None

    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return None

        length = user32.GetWindowTextLengthW(hwnd)
        if length > 0:
            buff = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buff, length + 1)
            return buff.value
    except Exception:
        pass
    return None


def is_active_window_excluded(excluded_titles: List[str]) -> bool:
    """
    Check if the currently active foreground window should be excluded from OCR/analysis
    (e.g., password managers, security settings).
    """
    title = get_active_window_title()
    if not title:
        return False

    title_lower = title.lower()
    for excl in excluded_titles:
        if excl.strip().lower() in title_lower:
            return True
    return False

