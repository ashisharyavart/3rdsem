"""
CyberGuard Desktop - Application Entry Point
Initializes PySide6 application, configuration, database repository, background monitoring worker,
and connects all UI signals.
"""

import sys
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

from config import APP_CONFIG
from desktop.main_window import MainWindow
from monitoring.monitor_worker import MonitorWorker
from database.history import ThreatHistoryRepository
from utils.logger import logger


def main():
    # Set high-DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("CyberGuard Desktop")
    app.setApplicationDisplayName("CyberGuard Desktop")
    app.setOrganizationName("CyberGuard")

    # Initialize repository and load prior history
    history_repo = ThreatHistoryRepository()
    window = MainWindow(config=APP_CONFIG)

    # Populate existing database history on startup
    prior_threats = history_repo.get_recent_threats(limit=APP_CONFIG.max_history_entries)
    window.history_widget.set_threats(prior_threats)
    counts = history_repo.get_threat_counts()
    high_critical_count = counts.get("Critical", 0) + counts.get("High", 0)
    window.update_stats(
        scans=0,
        threats=counts.get("total", 0),
        high_critical=high_critical_count,
        monitors=1
    )

    # Initialize Background Worker
    worker = MonitorWorker(config=APP_CONFIG)

    # Connect UI controls to Worker
    window.start_monitoring_requested.connect(worker.start_monitoring)
    window.pause_monitoring_requested.connect(worker.pause_monitoring)
    window.stop_monitoring_requested.connect(worker.stop_monitoring)
    window.scan_now_requested.connect(worker.request_scan_now)

    # Connect Worker outputs to UI
    def on_status_changed(is_monitoring: bool, is_paused: bool):
        window.update_monitoring_state(is_monitoring, is_paused)

    def on_scan_completed(total_scans: int, active_monitors: int):
        window.update_stats(
            scans=total_scans,
            threats=window.threat_count,
            high_critical=window.high_threat_count,
            monitors=active_monitors
        )

    def on_risk_updated(score: int, severity: str):
        window.update_risk_display(score, severity)

    def on_ocr_status(is_available: bool, message: str):
        if not is_available:
            window.set_ocr_missing_state(message)

    def on_threat_detected(threat_data: dict):
        logger.warning(
            f"Threat Detected: {threat_data.get('severity')} "
            f"(Score: {threat_data.get('score')}) - Categories: {threat_data.get('categories')}"
        )
        # 1. Save to SQLite database
        history_repo.insert_threat(
            score=threat_data.get("score", 0),
            severity=threat_data.get("severity", "Low"),
            categories=threat_data.get("categories", []),
            explanation=threat_data.get("explanation", ""),
            domain=threat_data.get("domain"),
            monitor_id=threat_data.get("monitor_id", 1)
        )

        # 2. Update UI Threat Table and Counters
        window.history_widget.add_threat(threat_data)
        window.threat_count += 1
        if threat_data.get("score", 0) >= 60:
            window.high_threat_count += 1

        window.update_stats(
            scans=window.scan_count,
            threats=window.threat_count,
            high_critical=window.high_threat_count,
            monitors=window.monitor_count
        )

        # 3. Trigger Alert Overlay if above threshold
        if threat_data.get("score", 0) >= APP_CONFIG.alert_threshold:
            window.show_alert_overlay(threat_data)

    def on_clear_history():
        history_repo.clear_history()
        logger.info("Threat history purged from SQLite database.")

    worker.status_changed.connect(on_status_changed)
    worker.scan_completed.connect(on_scan_completed)
    worker.risk_updated.connect(on_risk_updated)
    worker.ocr_status.connect(on_ocr_status)
    worker.threat_detected.connect(on_threat_detected)
    window.history_widget.clear_history_requested.connect(on_clear_history)

    # Ensure clean shutdown of worker on app exit
    def clean_exit():
        logger.info("Application shutting down: stopping background monitoring worker.")
        worker.stop_monitoring()
        worker.wait(2500)

    app.aboutToQuit.connect(clean_exit)

    window.show()
    logger.info("CyberGuard Desktop ready.")
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
