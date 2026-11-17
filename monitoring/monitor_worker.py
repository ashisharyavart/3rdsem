"""
CyberGuard Desktop - Screen Monitoring Background Worker
Runs multi-display capture, change detection, OCR extraction, and threat analysis
in an asynchronous QThread to ensure the PySide6 UI never stutters or freezes.
"""

import time
import hashlib
from typing import Dict, Any, Optional
from PySide6.QtCore import QThread, Signal, Slot, QMutex, QMutexLocker

from config import APP_CONFIG, CyberGuardConfig
from monitoring.screen_capture import ScreenCaptureManager
from monitoring.screen_change import ScreenChangeDetector
from monitoring.ocr_engine import OCREngine
from utils.text_cleaner import clean_ocr_text
from utils.privacy import is_active_window_excluded
from detection.scam_rules import ScamRuleEngine
from detection.url_analyzer import URLAnalyzer
from detection.risk_engine import RiskEngine
from detection.event_correlation import EventCorrelationEngine
from utils.logger import logger


class MonitorWorker(QThread):
    """
    Background worker thread orchestrating continuous multi-monitor security checks.
    """
    # Signals emitted to UI
    status_changed = Signal(bool, bool)      # is_monitoring, is_paused
    scan_completed = Signal(int, int)        # total_scans, active_monitors
    threat_detected = Signal(dict)           # threat_data dictionary
    risk_updated = Signal(int, str)          # current_score, severity
    error_occurred = Signal(str)             # human-readable error description
    ocr_status = Signal(bool, str)           # is_available, message

    def __init__(self, config: CyberGuardConfig = APP_CONFIG, parent=None):
        super().__init__(parent)
        self.config = config
        self._mutex = QMutex()
        self._running = False
        self._paused = False
        self._immediate_scan_flag = False

        self.capture_mgr = ScreenCaptureManager()
        self.change_detector = ScreenChangeDetector(
            diff_threshold=self.config.screen_diff_threshold,
            downscale_width=self.config.screen_downscale_width
        )
        self.ocr_engine = OCREngine(
            tesseract_cmd=self.config.tesseract_cmd,
            language=self.config.ocr_language
        )
        self.scam_rules = ScamRuleEngine()
        self.url_analyzer = URLAnalyzer()
        self.risk_engine = RiskEngine(config=self.config)
        self.correlation_engine = EventCorrelationEngine(
            window_sec=self.config.correlation_window_sec,
            bonus_multiplier=self.config.correlation_bonus_multiplier
        )

        self.total_scans = 0
        self._recent_signatures: Dict[str, float] = {}  # hash -> timestamp for duplicate suppression

    def run(self):
        """Main worker execution loop."""
        with QMutexLocker(self._mutex):
            self._running = True
            self._paused = False

        self.status_changed.emit(True, False)
        logger.info("MonitorWorker started background execution loop.")

        # Check OCR availability upfront
        ocr_available = self.ocr_engine.is_tesseract_available()
        if not ocr_available:
            self.ocr_status.emit(False, "Tesseract OCR binary not found.")
            logger.warning("MonitorWorker: Tesseract OCR is not installed or configured.")

        while True:
            # Check thread termination
            with QMutexLocker(self._mutex):
                if not self._running:
                    break
                paused = self._paused
                immediate = self._immediate_scan_flag
                self._immediate_scan_flag = False

            if paused and not immediate:
                self.msleep(200)
                continue

            # Execute scan cycle
            try:
                self._perform_scan_cycle(force_ocr=immediate)
            except Exception as e:
                logger.error(f"Error during scan cycle: {e}")
                self.error_occurred.emit(f"Monitoring error: {str(e)}")

            # Sleep for configured interval in responsive chunks
            sleep_ms = int(self.config.capture_interval_sec * 1000)
            step_ms = 100
            for _ in range(0, sleep_ms, step_ms):
                with QMutexLocker(self._mutex):
                    if not self._running or self._immediate_scan_flag:
                        break
                self.msleep(step_ms)

        self.capture_mgr.close()
        self.status_changed.emit(False, False)
        logger.info("MonitorWorker finished.")

    def _perform_scan_cycle(self, force_ocr: bool = False):
        """Captures all monitors and processes visual changes."""
        displays = self.capture_mgr.capture_all_monitors()
        if not displays:
            return

        self.total_scans += 1
        monitor_count = len(displays)
        self.scan_completed.emit(self.total_scans, monitor_count)

        # Check if the active foreground window is excluded (privacy guard)
        if is_active_window_excluded(self.config.excluded_window_titles):
            logger.info("Foreground window is in exclusion list. Skipping OCR for this cycle.")
            return

        max_cycle_score = 0
        max_cycle_severity = "Low"

        for display in displays:
            mon_id = display["monitor_id"]
            img = display["image_bgr"]

            # Change detection: skip OCR if screen didn't change meaningfully
            changed, diff_ratio = self.change_detector.has_changed(mon_id, img)
            if not changed and not force_ocr:
                continue

            # Run OCR on changed display
            ocr_res = self.ocr_engine.extract_text(img, timeout_sec=self.config.ocr_timeout_sec)
            if not ocr_res.is_available:
                self.ocr_status.emit(False, ocr_res.error_message or "OCR unavailable")
                continue

            raw_text = ocr_res.text
            if not raw_text or len(raw_text) < self.config.min_ocr_text_length:
                continue

            cleaned_text = clean_ocr_text(raw_text)
            if not cleaned_text:
                continue

            # Run Detection Pipeline
            rule_res = self.scam_rules.analyze(cleaned_text)
            url_res = self.url_analyzer.analyze_all(cleaned_text)
            risk_res = self.risk_engine.calculate_risk(rule_res, url_res)

            # Correlate with recent events
            if risk_res.score >= 20:
                corr_score, corr_insights = self.correlation_engine.add_event(
                    categories=risk_res.detected_categories,
                    score=risk_res.score,
                    severity=risk_res.severity,
                    reasons=risk_res.reasons,
                    domain=risk_res.extracted_domain
                )
                if corr_insights:
                    risk_res.reasons.extend(corr_insights)
                    risk_res.score = corr_score
                    if risk_res.score >= 80:
                        risk_res.severity = "Critical"
                    elif risk_res.score >= 60:
                        risk_res.severity = "High"

            if risk_res.score > max_cycle_score:
                max_cycle_score = risk_res.score
                max_cycle_severity = risk_res.severity

            # Trigger Threat Event if risk is suspicious or above
            if risk_res.score >= 30:
                self._dispatch_threat(risk_res, mon_id)

        # Emit highest risk observed in this cycle
        self.risk_updated.emit(max_cycle_score, max_cycle_severity)

    def _dispatch_threat(self, risk_res, monitor_id: int):
        """Constructs and emits a threat event, suppressing duplicates within suppression window."""
        # Signature based on categories + domain + severity
        cats_str = "-".join(sorted(risk_res.detected_categories))
        domain_str = risk_res.extracted_domain or "none"
        sig_str = f"{cats_str}_{domain_str}_{risk_res.severity}"
        sig_hash = hashlib.md5(sig_str.encode("utf-8")).hexdigest()

        now = time.time()
        last_seen = self._recent_signatures.get(sig_hash, 0.0)
        if (now - last_seen) < self.config.duplicate_alert_suppression_sec:
            # Duplicate within suppression window
            return

        self._recent_signatures[sig_hash] = now

        # Prune older signatures
        cutoff = now - (self.config.duplicate_alert_suppression_sec * 2)
        self._recent_signatures = {k: v for k, v in self._recent_signatures.items() if v >= cutoff}

        threat_payload = {
            "score": risk_res.score,
            "severity": risk_res.severity,
            "categories": risk_res.detected_categories,
            "explanation": "\n".join(risk_res.reasons),
            "reasons": risk_res.reasons,
            "domain": risk_res.extracted_domain,
            "monitor_id": monitor_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        self.threat_detected.emit(threat_payload)

    # Control methods invoked from UI thread
    def start_monitoring(self):
        with QMutexLocker(self._mutex):
            if self._running:
                if self._paused:
                    self._paused = False
                    self.status_changed.emit(True, False)
                return
            self._running = True
            self._paused = False

        if not self.isRunning():
            self.start()
        else:
            self.status_changed.emit(True, False)

    def pause_monitoring(self):
        with QMutexLocker(self._mutex):
            if not self._running:
                return
            self._paused = True
        self.status_changed.emit(True, True)

    def stop_monitoring(self):
        with QMutexLocker(self._mutex):
            if not self._running and not self.isRunning():
                return
            self._running = False
            self._paused = False
            self._immediate_scan_flag = False

        if self.isRunning():
            self.wait(3000)
            if self.isRunning():
                logger.warning("MonitorWorker did not terminate within timeout; terminating thread.")
                self.terminate()
                self.wait(1000)

        self.status_changed.emit(False, False)

    def request_scan_now(self):
        with QMutexLocker(self._mutex):
            self._immediate_scan_flag = True

