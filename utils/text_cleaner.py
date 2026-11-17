"""
CyberGuard Desktop - Text Cleaner & Normalizer
Sanitizes raw OCR text, removes scanning noise, and preserves URLs, amounts, and critical tokens.
"""

import re


def clean_ocr_text(raw_text: str) -> str:
    """
    Cleans and normalizes raw OCR text:
    - Normalizes line breaks and whitespace.
    - Strips non-printable ASCII noise while preserving UTF-8 and unicode quotes/currency.
    - Keeps URLs and domain patterns intact.
    - Preserves numerical figures, currency symbols ($/€/£/₹), and phone numbers.
    """
    if not raw_text:
        return ""

    # Replace carriage returns and vertical whitespace
    text = raw_text.replace("\r\n", "\n").replace("\r", "\n")

    # Replace null bytes or non-printable control characters (except newline and tab)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    # Normalize weird unicode spaces (non-breaking space, thin space, etc.)
    text = re.sub(r"[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]", " ", text)

    # Replace 3 or more consecutive newlines with 2 newlines (preserve paragraphs)
    text = re.sub(r"\n{3,}", "\n\n", text)

    # Clean lines individually
    cleaned_lines = []
    for line in text.split("\n"):
        line = line.strip()
        # Collapse multiple horizontal spaces
        line = re.sub(r"[ \t]+", " ", line)

        # Skip isolated random noise lines (e.g., single stray punctuation mark like `~` or `|` or `_`)
        if len(line) == 1 and line in "~`^|_§±":
            continue

        if line:
            cleaned_lines.append(line)

    cleaned_text = "\n".join(cleaned_lines)
    return cleaned_text

