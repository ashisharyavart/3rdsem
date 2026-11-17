"""
CyberGuard Desktop - Central Configuration Module
Provides default and user-customizable settings for monitoring, OCR,
threat detection, risk scoring, event correlation, and database storage.
"""

import os
import json
import shutil
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Dict, Any, List

# Base directories
PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(PROJECT_ROOT))) / "CyberGuard"
DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_FILE_PATH = DEFAULT_DATA_DIR / "config.json"


def find_tesseract_path() -> str:
    """
    Attempt to automatically detect the Tesseract OCR executable path on Windows.
    Checks PATH and standard installation paths.
    """
    which_path = shutil.which("tesseract")
    if which_path and os.path.isfile(which_path):
        return which_path

    candidates = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
        os.path.expandvars(r"%LOCALAPPDATA%\Tesseract-OCR\tesseract.exe"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate

    return ""


@dataclass
class CyberGuardConfig:
    # Monitoring Configuration
    capture_interval_sec: float = 3.0
    screen_diff_threshold: float = 0.015  # 1.5% difference required to trigger OCR
    screen_downscale_width: int = 640     # Resolution for fast screen comparison
    auto_start_monitoring: bool = False
    
    # OCR Engine Configuration
    tesseract_cmd: str = field(default_factory=find_tesseract_path)
    ocr_language: str = "eng"
    ocr_timeout_sec: float = 4.0
    min_ocr_text_length: int = 15

    # Alert & Risk Engine Configuration
    alert_threshold: int = 60          # 0-100 score threshold to show desktop alert
    enable_alert_overlay: bool = True
    duplicate_alert_suppression_sec: int = 45  # Avoid re-alerting identical risk signature within window

    # Risk Weights (Must sum to 1.0)
    weight_urgency: float = 0.30
    weight_payment: float = 0.25
    weight_impersonation: float = 0.20
    weight_url_risk: float = 0.15
    weight_credential_theft: float = 0.10

    # Event Correlation
    correlation_window_sec: int = 60
    correlation_bonus_multiplier: float = 1.25

    # Storage & History
    database_path: str = str(DEFAULT_DATA_DIR / "threat_history.db")
    max_history_entries: int = 500

    # Privacy & Exclusions
    excluded_window_titles: List[str] = field(default_factory=lambda: [
        "KeePass", "Bitwarden", "1Password", "Windows Security", "CyberGuard"
    ])
    mask_sensitive_preview: bool = True
    minimize_to_tray_on_close: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CyberGuardConfig":
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    def save(self, path: Path = CONFIG_FILE_PATH) -> None:
        """Persist current configuration to JSON file."""
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=4)
        except Exception as e:
            print(f"[Config] Error saving config: {e}")

    @classmethod
    def load(cls, path: Path = CONFIG_FILE_PATH) -> "CyberGuardConfig":
        """Load configuration from JSON file or return defaults."""
        if path.is_file():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                config = cls.from_dict(data)
                # If tesseract path wasn't set or was invalid, attempt auto-detect
                if not config.tesseract_cmd or not os.path.isfile(config.tesseract_cmd):
                    detected = find_tesseract_path()
                    if detected:
                        config.tesseract_cmd = detected
                return config
            except Exception as e:
                print(f"[Config] Error loading config: {e}. Falling back to defaults.")
        return cls()


# Singleton global config instance
APP_CONFIG = CyberGuardConfig.load()

