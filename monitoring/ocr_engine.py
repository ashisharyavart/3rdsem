"""
CyberGuard Desktop - Optical Character Recognition (OCR) Engine
Extracts on-screen text in-memory via pytesseract with graceful fallback,
privacy-preserving execution, and completely silent background subprocess calls.
"""

import os
import sys
import time
import subprocess
from dataclasses import dataclass
from typing import Optional
import numpy as np
import cv2
from PIL import Image
import pytesseract

from config import APP_CONFIG
from utils.logger import logger


# ---------------------------------------------------------------------------
# Windows Subprocess Silencing Patch
# On Windows 10/11, console executables (like tesseract.exe) spawn a visible
# console or Windows Terminal window unless creationflags=CREATE_NO_WINDOW is set.
# We patch pytesseract's subprocess invocation to ensure silent background execution.
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

    # 1. Patch pytesseract.pytesseract.subprocess_args to always pass CREATE_NO_WINDOW & SW_HIDE
    _orig_subprocess_args = pytesseract.pytesseract.subprocess_args

    def _silent_subprocess_args(*args, **kwargs):
        res = _orig_subprocess_args(*args, **kwargs)
        res["creationflags"] = CREATE_NO_WINDOW
        if "startupinfo" in res and res["startupinfo"]:
            res["startupinfo"].dwFlags |= subprocess.STARTF_USESHOWWINDOW
            res["startupinfo"].wShowWindow = subprocess.SW_HIDE
        else:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            res["startupinfo"] = si
        return res

    pytesseract.pytesseract.subprocess_args = _silent_subprocess_args

    # 2. Patch pytesseract's version check to prevent console popups
    def _silent_get_tesseract_version():
        tess_cmd = pytesseract.pytesseract.tesseract_cmd
        if not tess_cmd or not os.path.isfile(tess_cmd):
            raise pytesseract.TesseractNotFoundError()
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = subprocess.SW_HIDE
        try:
            output = subprocess.check_output(
                [tess_cmd, "--version"],
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW,
                startupinfo=si,
            )
            raw = output.decode("utf-8", errors="ignore")
            # Parse version string (e.g. 'tesseract 5.4.0...')
            parts = raw.split()
            ver_str = parts[1] if len(parts) > 1 else "5.0.0"
            return pytesseract.pytesseract.Version(ver_str)
        except Exception:
            raise pytesseract.TesseractNotFoundError()

    pytesseract.pytesseract.get_tesseract_version = _silent_get_tesseract_version
    pytesseract.get_tesseract_version = _silent_get_tesseract_version


@dataclass
class OCRResult:
    text: str
    is_available: bool
    error_message: Optional[str] = None
    duration_sec: float = 0.0


class OCREngine:
    """
    Manages OCR processing on captured screen buffers.
    Handles Tesseract setup verification and completely silent in-memory text extraction.
    """

    def __init__(self, tesseract_cmd: Optional[str] = None, language: str = "eng"):
        self.tesseract_cmd = tesseract_cmd or APP_CONFIG.tesseract_cmd
        self.language = language
        self._cached_available: Optional[bool] = None
        self._apply_tesseract_path()

    def update_tesseract_path(self, path: str):
        self.tesseract_cmd = path
        self._cached_available = None
        self._apply_tesseract_path()

    def _apply_tesseract_path(self):
        if self.tesseract_cmd and os.path.isfile(self.tesseract_cmd):
            pytesseract.pytesseract.tesseract_cmd = self.tesseract_cmd

    def is_tesseract_available(self) -> bool:
        """
        Verify if the configured Tesseract binary exists and can run.
        Caches result to avoid continuous version-checking subprocesses.
        """
        if self._cached_available is not None:
            return self._cached_available

        if not self.tesseract_cmd or not os.path.isfile(self.tesseract_cmd):
            self._cached_available = False
            return False

        try:
            self._apply_tesseract_path()
            version = pytesseract.get_tesseract_version()
            self._cached_available = version is not None
            return self._cached_available
        except Exception:
            self._cached_available = False
            return False

    def extract_text(self, image_bgr: np.ndarray, timeout_sec: float = 4.0) -> OCRResult:
        """
        Performs in-memory OCR on a BGR screen image without saving to disk.
        Executes silently without opening any console or terminal window.
        Returns an OCRResult containing the extracted string or an error.
        """
        if not self.is_tesseract_available():
            msg = (
                "Tesseract OCR is not installed or configured. "
                "Please configure the path in Settings or install Tesseract-OCR."
            )
            return OCRResult(text="", is_available=False, error_message=msg)

        if image_bgr is None or image_bgr.size == 0:
            return OCRResult(text="", is_available=True, error_message="Empty image provided.")

        start_time = time.time()
        try:
            # Convert OpenCV BGR to RGB PIL image for pytesseract
            img_rgb = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2RGB)
            pil_img = Image.fromarray(img_rgb)

            # Extract text with timeout (using patched silent subprocess_args)
            extracted = pytesseract.image_to_string(
                pil_img,
                lang=self.language,
                timeout=timeout_sec,
                config="--oem 3 --psm 3"
            )
            elapsed = time.time() - start_time

            cleaned = extracted.strip() if extracted else ""
            return OCRResult(text=cleaned, is_available=True, duration_sec=elapsed)

        except pytesseract.TesseractNotFoundError:
            self._cached_available = False
            return OCRResult(
                text="",
                is_available=False,
                error_message="Tesseract binary not found at configured path."
            )
        except pytesseract.TesseractError as te:
            logger.error(f"Tesseract OCR execution error: {te}")
            return OCRResult(text="", is_available=True, error_message=str(te))
        except Exception as e:
            logger.error(f"Unexpected error during OCR processing: {e}")
            return OCRResult(text="", is_available=True, error_message=str(e))
