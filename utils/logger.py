"""
CyberGuard Desktop - Logging Utility
Provides structured, privacy-preserving logging without leaking raw OCR or sensitive credentials.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime


def setup_logger(name: str = "CyberGuard") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.hasHandlers():
        return logger

    logger.setLevel(logging.INFO)

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


logger = setup_logger()

