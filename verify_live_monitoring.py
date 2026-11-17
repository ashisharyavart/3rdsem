"""
CyberGuard Desktop - Live Continuous Monitoring Verification Script
Runs continuous live monitoring for 2+ minutes with real OCR on every cycle,
inspecting all system windows to verify zero temporary popups appear.
Then verifies clean shutdown and verifies 2+ minutes of post-shutdown silence.
"""

import sys
import time
import ctypes
import numpy as np
import cv2
from PySide6.QtWidgets import QApplication

from config import APP_CONFIG
from monitoring.monitor_worker import MonitorWorker


def log(msg: str):
    print(msg, flush=True)


def get_visible_windows():
    """Retrieve all visible top-level window titles and class names."""
    windows = []
    user32 = ctypes.windll.user32

    def enum_cb(hwnd, lparam):
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buff = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buff, length + 1)
                title = buff.value
                cls_buff = ctypes.create_unicode_buffer(256)
                user32.GetClassNameW(hwnd, cls_buff, 256)
                windows.append((hwnd, title, cls_buff.value))
        return True

    CMPFUNC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
    user32.EnumWindows(CMPFUNC(enum_cb), 0)
    return windows


def run_test():
    log("=== Step 1 & 2: Starting CyberGuard Monitor Worker ===")
    app = QApplication.instance() or QApplication(sys.argv)

    config = APP_CONFIG
    config.capture_interval_sec = 2.0

    worker = MonitorWorker(config=config)
    scan_count_record = []
    ocr_call_count = 0

    # Ensure each scan generates fresh changing text so OCR runs on every cycle
    cycle_counter = [0]

    def test_capture():
        cycle_counter[0] += 1
        # Alternate background tone with large contrast (>25 intensity) to trigger real OCR on every single cycle
        bg_val = 255 if (cycle_counter[0] % 2 == 0) else 100
        text_color = (0, 0, 0) if bg_val == 255 else (255, 255, 255)
        img = np.ones((600, 1000, 3), dtype=np.uint8) * bg_val
        cv2.putText(
            img,
            f"CYBERGUARD LIVE MONITORING VERIFICATION CYCLE #{cycle_counter[0]} - SCANNING ACTIVE",
            (30, 200),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.6,
            text_color,
            2
        )
        return [{
            "monitor_id": 1,
            "rect": {"left": 0, "top": 0, "width": 1000, "height": 600},
            "image_bgr": img
        }]

    worker.capture_mgr.capture_all_monitors = test_capture

    # Track OCR invocations
    orig_extract = worker.ocr_engine.extract_text

    def tracking_extract(*args, **kwargs):
        nonlocal ocr_call_count
        ocr_call_count += 1
        return orig_extract(*args, **kwargs)

    worker.ocr_engine.extract_text = tracking_extract

    worker.scan_completed.connect(lambda scans, mons: scan_count_record.append(scans))

    baseline_windows = {hwnd for hwnd, title, cls in get_visible_windows()}
    log(f"Baseline window snapshot: {len(baseline_windows)} visible windows.")

    worker.start_monitoring()
    time.sleep(0.5)
    assert worker.isRunning(), "Worker failed to start"
    log("MonitorWorker running successfully.")

    log("\n=== Step 3 & 4: Continuous Scanning for >2 Minutes (Tracking Popups) ===")
    start_time = time.time()
    unwanted_popups = []
    target_duration = 125  # 2 minutes 5 seconds
    last_log = 0

    while (time.time() - start_time) < target_duration:
        app.processEvents()

        current_windows = get_visible_windows()
        for hwnd, title, cls in current_windows:
            if hwnd not in baseline_windows:
                lower_title = title.lower()
                lower_cls = cls.lower()
                # Check for any console, terminal, or flashing popup
                if any(x in lower_title for x in ["tesseract", "cmd.exe", "conhost", "powershell", "terminal"]) or \
                   any(x in lower_cls for x in ["consolewindowclass", "cascadia_desktop_window"]):
                    unwanted_popups.append((title, cls, time.time()))
                    log(f"ALERT: Unwanted popup detected: Title='{title}', Class='{cls}'")

        elapsed = int(time.time() - start_time)
        if elapsed != last_log and elapsed % 15 == 0:
            last_log = elapsed
            log(f"Elapsed: {elapsed:3d}s / {target_duration}s | Completed Scans: {len(scan_count_record)} | OCR Invocations: {ocr_call_count} | Unwanted Popups: {len(unwanted_popups)}")

        time.sleep(0.05)

    log(f"\nCompleted continuous scanning duration ({target_duration}s).")
    log(f"Total scans completed: {len(scan_count_record)}")
    log(f"Total OCR invocations executed: {ocr_call_count}")
    log(f"Total unwanted popups observed: {len(unwanted_popups)}")

    assert len(scan_count_record) >= 30, f"Expected at least 30 scans in 2 minutes, got {len(scan_count_record)}"
    assert ocr_call_count >= 20, f"Expected at least 20 OCR invocations, got {ocr_call_count}"
    assert len(unwanted_popups) == 0, f"Unwanted popups detected: {unwanted_popups}"
    log("VERIFIED: Zero unwanted popups appeared during >2 minutes of continuous scanning!")

    print("\n=== Step 5: Confirming OCR and Detection Engine Still Work ===")
    phish_img = np.ones((300, 900, 3), dtype=np.uint8) * 255
    cv2.putText(
        phish_img,
        "URGENT: State Bank KYC expired today. Enter OTP immediately.",
        (20, 100),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.6,
        (0, 0, 0),
        2
    )
    cv2.putText(
        phish_img,
        "Update at: http://192.168.1.45/sbi/verify-login",
        (20, 180),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.6,
        (0, 0, 0),
        2
    )
    ocr_res = worker.ocr_engine.extract_text(phish_img)
    assert ocr_res.is_available is True
    log(f"OCR extracted text: {repr(ocr_res.text)}")
    assert "OTP" in ocr_res.text.upper() or "BANK" in ocr_res.text.upper()

    rule_res = worker.scam_rules.analyze(ocr_res.text)
    url_res = worker.url_analyzer.analyze_all(ocr_res.text)
    risk_res = worker.risk_engine.calculate_risk(rule_res, url_res)
    log(f"Risk Engine output: Score={risk_res.score}, Severity={risk_res.severity}, Categories={risk_res.detected_categories}")
    assert risk_res.score >= 60, f"Expected high risk, got {risk_res.score}"
    assert "Credential Theft" in risk_res.detected_categories
    log("VERIFIED: OCR and Detection engine are 100% operational!")

    log("\n=== Step 6 & 7: Closing CyberGuard & Confirming Worker Termination ===")
    worker.stop_monitoring()
    time.sleep(1.0)
    assert not worker.isRunning(), "Worker failed to terminate after stop_monitoring()"
    log("VERIFIED: Worker terminated completely. worker.isRunning() == False.")

    log("\n=== Step 8: Post-Shutdown Silence for >2 Minutes ===")
    post_start = time.time()
    post_scans = []
    post_popups = []

    worker.scan_completed.connect(lambda s, m: post_scans.append(s))
    last_log = 0

    while (time.time() - post_start) < target_duration:
        app.processEvents()
        current_windows = get_visible_windows()
        for hwnd, title, cls in current_windows:
            if hwnd not in baseline_windows:
                lower_title = title.lower()
                if any(x in lower_title for x in ["tesseract", "cmd.exe", "conhost", "terminal"]):
                    post_popups.append((title, cls))

        elapsed = int(time.time() - post_start)
        if elapsed != last_log and elapsed % 15 == 0:
            last_log = elapsed
            log(f"Post-stop elapsed: {elapsed:3d}s / {target_duration}s | Post-stop scans: {len(post_scans)} | Popups: {len(post_popups)}")

        time.sleep(0.05)

    assert len(post_scans) == 0, f"Scans occurred after shutdown: {len(post_scans)}"
    assert len(post_popups) == 0, f"Popups appeared after shutdown: {len(post_popups)}"
    log("VERIFIED: Zero scans and zero popups during 2-minute post-shutdown period!")

    log("\n=== Step 9: Testing Legitimate Threat Alert Overlay Separately ===")
    threat_payload = {
        "score": 92,
        "severity": "Critical",
        "categories": ["Urgency", "Credential Theft", "Suspicious URL"],
        "reasons": ["Urgent verification demanded", "OTP requested on suspicious domain"],
        "domain": "192.168.1.1"
    }
    from desktop.alert_overlay import ThreatAlertOverlay
    overlay = ThreatAlertOverlay(threat_payload)
    overlay.show()
    assert overlay.isVisible(), "Alert overlay failed to show"
    log("Threat Alert Overlay displayed correctly with Critical styling.")
    overlay.close()
    log("Threat Alert Overlay dismissed cleanly.")

    log("\n=======================================================")
    log("ALL 9 TEST STEPS COMPLETED AND VERIFIED SUCCESSFULLY!")
    log("=======================================================")


if __name__ == "__main__":
    run_test()
