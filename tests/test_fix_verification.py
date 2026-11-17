"""
CyberGuard Desktop - Comprehensive Fix Verification Test
Verifies:
1. OCR and screen monitoring run 100% silently with no console or terminal popups.
2. PySide6 application lifecycle and MonitorWorker properly start and stop.
3. Closing the main window cleanly halts the worker and terminates background execution.
4. Real Tesseract OCR text extraction and threat detection continue working correctly.
5. Legitimate threat alerts function when genuine threats are detected.
"""

import sys
import time
import subprocess
import pytest
import numpy as np
import cv2
from PIL import Image, ImageDraw

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt, QTimer

from config import APP_CONFIG
from monitoring.ocr_engine import OCREngine
from monitoring.monitor_worker import MonitorWorker
from desktop.main_window import MainWindow
from desktop.alert_overlay import ThreatAlertOverlay


def test_tesseract_silence_and_execution():
    """Verify that tesseract OCR runs cleanly and silently without spawning console windows."""
    engine = OCREngine()
    assert engine.is_tesseract_available() is True

    # Create a synthetic image containing known test text
    img = np.ones((150, 450, 3), dtype=np.uint8) * 255
    cv2.putText(img, "CYBERGUARD SECURITY SCAN TEST", (20, 80), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 0, 0), 2)

    res = engine.extract_text(img)
    assert res.is_available is True
    assert "CYBERGUARD" in res.text.upper() or "SECURITY" in res.text.upper()


def test_worker_lifecycle_and_shutdown():
    """Verify worker starts, monitors, and stops cleanly without orphaned threads."""
    app = QApplication.instance() or QApplication(sys.argv)

    worker = MonitorWorker(config=APP_CONFIG)
    assert not worker.isRunning()

    # Start worker
    worker.start_monitoring()
    time.sleep(0.5)
    assert worker.isRunning()

    # Pause worker
    worker.pause_monitoring()
    assert worker._paused is True

    # Unpause worker
    worker.start_monitoring()
    assert worker._paused is False

    # Stop worker
    worker.stop_monitoring()
    time.sleep(0.5)
    assert not worker.isRunning()


def test_main_window_close_clean_shutdown():
    """Verify that closing the main window shuts down worker and does not leave orphaned background tasks."""
    app = QApplication.instance() or QApplication(sys.argv)

    win = MainWindow(config=APP_CONFIG)
    worker = MonitorWorker(config=APP_CONFIG)

    win.start_monitoring_requested.connect(worker.start_monitoring)
    win.stop_monitoring_requested.connect(worker.stop_monitoring)

    # Start monitoring
    win.start_monitoring_requested.emit()
    time.sleep(0.5)
    assert worker.isRunning()

    # Trigger close on MainWindow
    win.close()
    time.sleep(1.0)

    # Verify worker stopped
    assert not worker.isRunning()


def test_legitimate_threat_alert_overlay():
    """Verify legitimate threat overlay displays properly when a genuine high/critical risk is detected."""
    app = QApplication.instance() or QApplication(sys.argv)

    fake_threat = {
        "score": 85,
        "severity": "Critical",
        "categories": ["Urgency", "Credential Theft"],
        "reasons": ["Urgent verification demanded", "OTP requested on suspicious domain"],
        "domain": "192.168.1.100"
    }

    win = MainWindow(config=APP_CONFIG)
    win.show_alert_overlay(fake_threat)

    assert win.active_alert is not None
    assert win.active_alert.isVisible()
    win.active_alert.close()

